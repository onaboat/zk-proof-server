use axum::{extract::State, routing::post, Json, Router, serve};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use bs58;
use tracing::{info, warn};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature, transaction::Transaction};
use solana_zk_sdk::encryption::{elgamal::ElGamalKeypair, auth_encryption::AeKey};

use spl_token_2022::{
    extension::{
        confidential_transfer::{account_info::combine_balances, ConfidentialTransferAccount, instruction::{configure_account, PubkeyValidityProofData}},
        BaseStateWithExtensions, StateWithExtensions, ExtensionType,
    },
    instruction::reallocate,
    id as token_2022_id,
    solana_zk_sdk::encryption::{auth_encryption::AeCiphertext, elgamal::ElGamalCiphertext},
    state::Account,
};

use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_confidential_transfer_proof_extraction::instruction::{ProofData, ProofLocation};
use base64::{prelude::BASE64_STANDARD, Engine};
use bincode;

#[derive(Deserialize)]
struct GenerateKeysRequest {
    signature: String,
}

#[derive(Serialize)]
struct GenerateKeysResponse {
    pubkey_bytes: String,
    elgamal_signature: String,
    aes_signature: String,
}

#[derive(Deserialize)]
struct BalanceRequest {
    authority: String,
    token_mint: String,
    elgamal_signature: String,
    aes_signature: String,
}

#[derive(Serialize)]
struct BalanceResponse {
    pending_balance: f64,
    available_balance: f64,
}

#[derive(Deserialize)]
struct InitializeRequest {
    authority: String,
    token_mint: String,
    elgamal_signature: String,
    aes_signature: String,
}

#[derive(Serialize)]
struct InitializeResponse {
    transaction: String,
}

#[derive(Clone)]
struct AppState {
    rpc: Arc<RpcClient>,
}

async fn generate_keys(Json(req): Json<GenerateKeysRequest>) -> Json<GenerateKeysResponse> {
    let signature = Signature::from_str(&req.signature).expect("Invalid signature");
    let elgamal = ElGamalKeypair::new_from_signature(&signature).expect("ElGamal failed");
    let aes = AeKey::new_from_signature(&signature).expect("AES failed");

    let pubkey_bytes = elgamal.pubkey().get_point().compress().to_bytes();
    let elgamal_signature: [u8; 64] = (&elgamal).into();
    let aes_signature: [u8; 16] = aes.into();

    Json(GenerateKeysResponse {
        pubkey_bytes: bs58::encode(pubkey_bytes).into_string(),
        elgamal_signature: bs58::encode(elgamal_signature).into_string(),
        aes_signature: bs58::encode(aes_signature).into_string(),
    })
}

async fn balance(State(state): State<Arc<AppState>>, Json(payload): Json<BalanceRequest>) -> Json<BalanceResponse> {
    info!("🔍 Starting balance check...");

    let authority = Pubkey::from_str(&payload.authority).unwrap_or_default();
    let token_mint = Pubkey::from_str(&payload.token_mint).unwrap_or_default();
    let elgamal_signature = Signature::from_str(&payload.elgamal_signature).unwrap_or_default();
    let aes_signature = Signature::from_str(&payload.aes_signature).unwrap_or_default();

    info!("🔑 Authority: {}", authority);
    info!("🪙 Token Mint: {}", token_mint);

    let user_ata = get_associated_token_address_with_program_id(&authority, &token_mint, &token_2022_id());
    info!("📦 ATA: {}", user_ata);

    let elgamal_key = match ElGamalKeypair::new_from_signature(&elgamal_signature) {
        Ok(val) => val,
        Err(e) => {
            warn!("❌ Failed to derive ElGamal keypair: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let ae_key = match AeKey::new_from_signature(&aes_signature) {
        Ok(val) => val,
        Err(e) => {
            warn!("❌ Failed to derive AES key: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let accounts = state.rpc.get_multiple_accounts(&[user_ata]).await.unwrap_or_default();
    let account_data = match accounts.get(0).and_then(|opt| opt.as_ref()) {
        Some(data) => data,
        None => {
            warn!("❌ Token account not found for {}", user_ata);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let token_account = match StateWithExtensions::<Account>::unpack(&account_data.data) {
        Ok(acc) => acc,
        Err(e) => {
            warn!("❌ Failed to unpack token account: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let confidential = match token_account.get_extension::<ConfidentialTransferAccount>() {
        Ok(conf) => conf,
        Err(e) => {
            warn!("❌ No ConfidentialTransferAccount extension found: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let pending_lo: ElGamalCiphertext = match confidential.pending_balance_lo.try_into() {
        Ok(val) => val,
        Err(e) => {
            warn!("❌ Failed to parse pending_balance_lo: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let pending_hi: ElGamalCiphertext = match confidential.pending_balance_hi.try_into() {
        Ok(val) => val,
        Err(e) => {
            warn!("❌ Failed to parse pending_balance_hi: {:?}", e);
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let lo = match elgamal_key.secret().decrypt_u32(&pending_lo) {
        Some(val) => val,
        None => {
            warn!("❌ Failed to decrypt pending_lo");
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let hi = match elgamal_key.secret().decrypt_u32(&pending_hi) {
        Some(val) => val,
        None => {
            warn!("❌ Failed to decrypt pending_hi");
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let pending = match combine_balances(lo, hi) {
        Some(val) => val,
        None => {
            warn!("❌ Failed to combine balances");
            return Json(BalanceResponse { pending_balance: 0.0, available_balance: 0.0 });
        }
    };

    let available_ct: AeCiphertext = match confidential.decryptable_available_balance.try_into() {
        Ok(val) => val,
        Err(e) => {
            warn!("❌ Failed to parse decryptable_available_balance: {:?}", e);
            return Json(BalanceResponse { pending_balance: pending as f64, available_balance: 0.0 });
        }
    };

    let available = ae_key.decrypt(&available_ct).unwrap_or_else(|| {
        warn!("❌ Failed to decrypt available balance");
        0
    });

    let decimals = 9.0;

    info!("✅ Decrypted Pending: {}", pending);
    info!("✅ Decrypted Available: {}", available);

    Json(BalanceResponse {
        pending_balance: pending as f64 / 10f64.powf(decimals),
        available_balance: available as f64 / 10f64.powf(decimals),
    })
}

async fn initialize(State(_state): State<Arc<AppState>>, Json(payload): Json<InitializeRequest>) -> Json<InitializeResponse> {
    let authority = Pubkey::from_str(&payload.authority).unwrap();
    let token_mint = Pubkey::from_str(&payload.token_mint).unwrap();
    let user_ata = get_associated_token_address_with_program_id(&authority, &token_mint, &token_2022_id());

    let elgamal = ElGamalKeypair::new_from_signature(&Signature::from_str(&payload.elgamal_signature).unwrap()).unwrap();
    let aes = AeKey::new_from_signature(&Signature::from_str(&payload.aes_signature).unwrap()).unwrap();

    let proof_data = PubkeyValidityProofData::new(&elgamal).unwrap();
    let mut configure_ixs = configure_account(
        &token_2022_id(),
        &user_ata,
        &token_mint,
        &aes.encrypt(0).into(),
        65536,
        &authority,
        &[],
        ProofLocation::InstructionOffset(1.try_into().unwrap(), ProofData::InstructionData(&proof_data)),
    ).unwrap();

    let mut instructions = vec![
        create_associated_token_account_idempotent(&authority, &authority, &token_mint, &token_2022_id()),
        reallocate(
            &token_2022_id(),
            &user_ata,
            &authority,
            &authority,
            &[],
            &[ExtensionType::ConfidentialTransferAccount],
        ).unwrap(),
    ];

    instructions.append(&mut configure_ixs);

    let tx = Transaction::new_with_payer(&instructions, Some(&authority));
    let serialized_tx = bincode::serialize(&tx).unwrap();

    Json(InitializeResponse {
        transaction: BASE64_STANDARD.encode(serialized_tx),
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let rpc = Arc::new(RpcClient::new("https://api.devnet.solana.com".to_string()));
    router_api(rpc).await;
}

async fn router_api(rpc: Arc<RpcClient>) {
    let app = Router::new()
        .route("/generate-keys", post(generate_keys))
        .route("/proof/balances", post(balance))
        .route("/initialize", post(initialize))
        .with_state(Arc::new(AppState { rpc }));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("📡 Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
}
