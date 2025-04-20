// src/main.rs
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio;
use spl_token_2022::extension::confidential_transfer::{
    elgamal::{ElGamalKeypair, ElGamalPubkey},
    auth_encryption::AeKey,
};
use spl_token_confidential_transfer_proof_generation::{
    withdraw::WithdrawProofData,
    transfer::TransferProofData,
    deposit::DepositAmountEncryption,
};

#[derive(Deserialize)]
struct GenerateKeysRequest {
    user_pubkey: String,
}

#[derive(Serialize)]
struct GenerateKeysResponse {
    elgamal_pubkey: String,
    aes_key: String,
}

#[derive(Deserialize)]
struct WithdrawProofRequest {
    amount: u64,
    elgamal_secret: String,
    aes_key: String,
}

#[derive(Serialize)]
struct WithdrawProofResponse {
    equality_proof: String,
    range_proof: String,
}

#[derive(Deserialize)]
struct TransferProofRequest {
    amount: u64,
    sender_elgamal_secret: String,
    sender_aes_key: String,
    recipient_elgamal_pubkey: String,
}

#[derive(Serialize)]
struct TransferProofResponse {
    equality_proof: String,
    range_proof: String,
    ciphertext_validity_proof: String,
    ciphertext_lo: String,
    ciphertext_hi: String,
}

#[derive(Deserialize)]
struct DepositProofRequest {
    amount: u64,
    elgamal_pubkey: String,
    aes_key: String,
}

#[derive(Serialize)]
struct DepositProofResponse {
    ciphertext_lo: String,
    ciphertext_hi: String,
}

async fn generate_keys(Json(req): Json<GenerateKeysRequest>) -> Json<GenerateKeysResponse> {
    let pubkey_bytes = bs58::decode(&req.user_pubkey).into_vec().unwrap_or(vec![0u8; 32]);

    let elgamal_keypair = ElGamalKeypair::new_from_seed(&pubkey_bytes);
    let aes_key = AeKey::new_from_seed(&pubkey_bytes);

    Json(GenerateKeysResponse {
        elgamal_pubkey: bs58::encode(elgamal_keypair.pubkey().as_bytes()).into_string(),
        aes_key: bs58::encode(aes_key.to_bytes()).into_string(),
    })
}

async fn generate_withdraw_proof(Json(req): Json<WithdrawProofRequest>) -> Json<WithdrawProofResponse> {
    let elgamal_bytes = bs58::decode(&req.elgamal_secret).unwrap_or_default();
    let aes_bytes = bs58::decode(&req.aes_key).unwrap_or_default();

    let elgamal_keypair = ElGamalKeypair::from_bytes(&elgamal_bytes).expect("Invalid ElGamal key");
    let aes_key = AeKey::from_bytes(&aes_bytes).expect("Invalid AES key");

    let proof_data = WithdrawProofData::generate_proof_data(
        req.amount,
        &elgamal_keypair,
        &aes_key,
    ).expect("Proof generation failed");

    Json(WithdrawProofResponse {
        equality_proof: bs58::encode(proof_data.equality_proof).into_string(),
        range_proof: bs58::encode(proof_data.range_proof).into_string(),
    })
}

async fn generate_transfer_proof(Json(req): Json<TransferProofRequest>) -> Json<TransferProofResponse> {
    let sender_elgamal_bytes = bs58::decode(&req.sender_elgamal_secret).unwrap_or_default();
    let sender_aes_bytes = bs58::decode(&req.sender_aes_key).unwrap_or_default();
    let recipient_pubkey_bytes = bs58::decode(&req.recipient_elgamal_pubkey).unwrap_or_default();

    let sender_elgamal = ElGamalKeypair::from_bytes(&sender_elgamal_bytes).expect("Invalid sender ElGamal key");
    let sender_aes = AeKey::from_bytes(&sender_aes_bytes).expect("Invalid sender AES key");
    let recipient_elgamal = ElGamalPubkey::from_bytes(&recipient_pubkey_bytes).expect("Invalid recipient ElGamal pubkey");

    let proof_data = TransferProofData::generate_split_proof_data(
        req.amount,
        &sender_elgamal,
        &sender_aes,
        recipient_elgamal,
        None, // No auditor key
    ).expect("Transfer proof generation failed");

    Json(TransferProofResponse {
        equality_proof: bs58::encode(proof_data.equality_proof).into_string(),
        range_proof: bs58::encode(proof_data.range_proof).into_string(),
        ciphertext_validity_proof: bs58::encode(proof_data.ciphertext_validity_proof).into_string(),
        ciphertext_lo: bs58::encode(proof_data.ciphertext_lo.to_bytes()).into_string(),
        ciphertext_hi: bs58::encode(proof_data.ciphertext_hi.to_bytes()).into_string(),
    })
}

async fn generate_deposit_proof(Json(req): Json<DepositProofRequest>) -> Json<DepositProofResponse> {
    let elgamal_bytes = bs58::decode(&req.elgamal_pubkey).unwrap_or_default();
    let aes_bytes = bs58::decode(&req.aes_key).unwrap_or_default();

    let elgamal_pubkey = ElGamalPubkey::from_bytes(&elgamal_bytes).expect("Invalid ElGamal pubkey");
    let aes_key = AeKey::from_bytes(&aes_bytes).expect("Invalid AES key");

    let encrypted = DepositAmountEncryption::encrypt(req.amount, elgamal_pubkey, &aes_key);

    Json(DepositProofResponse {
        ciphertext_lo: bs58::encode(encrypted.ciphertext_lo.to_bytes()).into_string(),
        ciphertext_hi: bs58::encode(encrypted.ciphertext_hi.to_bytes()).into_string(),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/generate-keys", post(generate_keys))
        .route("/proofs/withdraw", post(generate_withdraw_proof))
        .route("/proofs/transfer", post(generate_transfer_proof))
        .route("/proofs/deposit", post(generate_deposit_proof));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string()).parse().unwrap();
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
