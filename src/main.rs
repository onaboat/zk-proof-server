use axum::serve;
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use solana_zk_sdk::encryption::{
    elgamal::ElGamalKeypair,
    auth_encryption::AeKey,
};
// use solana_sdk::signature::{self, Keypair};
use solana_sdk::signature::Signature;
use std::str::FromStr;
use bs58;
use std::net::SocketAddr;

#[derive(Deserialize)]
struct GenerateKeysRequest {
    signature: String,
}

#[derive(Serialize)]
struct GenerateKeysResponse {
    pubkey_bytes : String,
    elgamal_bytes: String,
    aes_bytes: String,
}

async fn generate_keys(Json(req): Json<GenerateKeysRequest>) -> Json<GenerateKeysResponse> {

    //  let seed = b"ahoy_this_be_seed_123456789012"; // 32 bytes
    // let signer = Keypair::new();

    // let signer_bytes = bs58::decode(&req.user_pubkey).into_vec().expect("Invalid base58 pubkey");
    // let signer = Keypair::from_bytes(&signer_bytes).expect("Failed to create Keypair from bytes");

    // let elgamal = ElGamalKeypair::new_from_signer(&signer, seed).expect("ElGamal failed"); 
    // let aes = AeKey::new_from_signer(&signer, seed).expect("AES failed");

    
    let signature = Signature::from_str(&req.signature).expect("Invalid signature string");

    let elgamal = ElGamalKeypair::new_from_signature(&signature).expect("ElGamal failed"); 
    let aes = AeKey::new_from_signature(&signature).expect("AES failed");

    let pubkey_bytes = elgamal.pubkey().get_point().compress().to_bytes();
    let elgamal_bytes: [u8; 64] = (&elgamal).into();
    let aes_bytes: [u8; 16] = aes.into();

    Json(GenerateKeysResponse {
        pubkey_bytes: bs58::encode(pubkey_bytes).into_string(),
        elgamal_bytes: bs58::encode(elgamal_bytes).into_string(),
        aes_bytes: bs58::encode(aes_bytes).into_string(),
    })

}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/generate-keys", post(generate_keys));
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
}
