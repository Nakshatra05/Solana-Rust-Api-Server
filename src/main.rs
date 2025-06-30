use axum::{routing::post, Json, Router, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use bs58;
use spl_token::instruction::initialize_mint;
use solana_sdk::{pubkey::Pubkey, instruction::AccountMeta};
use base64::{engine::general_purpose, Engine as _};
use spl_token::instruction::mint_to;
use serde_json;
use std::str::FromStr;
use solana_sdk::system_instruction;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Placeholder structs for requests
#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct MessageSignResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct MessageVerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SendTokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountInfo>,
    instruction_data: String,
}

// Handlers
async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let data = KeypairData { pubkey, secret };
    let response = SuccessResponse { success: true, data };
    (StatusCode::OK, axum::Json(serde_json::to_value(response).unwrap()))
}

async fn create_token(Json(req): Json<TokenCreateRequest>) -> impl IntoResponse {
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid mint pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let mint_authority_pubkey = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid mintAuthority pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            let err = serde_json::json!({"success": false, "error": format!("Failed to create instruction: {}", e)});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|meta: &AccountMeta| AccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(ix.data);
    let response = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    let resp = SuccessResponse { success: true, data: response };
    (StatusCode::OK, axum::Json(serde_json::to_value(resp).unwrap()))
}

async fn mint_token(Json(req): Json<TokenMintRequest>) -> impl IntoResponse {
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid mint pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let dest_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid destination pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid authority pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let ix = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &dest_pubkey,
        &authority_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            let err = serde_json::json!({"success": false, "error": format!("Failed to create instruction: {}", e)});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|meta: &AccountMeta| AccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(ix.data);
    let response = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    let resp = SuccessResponse { success: true, data: response };
    (StatusCode::OK, axum::Json(serde_json::to_value(resp).unwrap()))
}

async fn sign_message(Json(req): Json<MessageSignRequest>) -> impl IntoResponse {
    use solana_sdk::signer::keypair::Keypair;
    if req.message.is_empty() || req.secret.is_empty() {
        let err = serde_json::json!({"success": false, "error": "Missing required fields"});
        return (StatusCode::BAD_REQUEST, axum::Json(err));
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid base58 secret key"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid secret key bytes"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key_b58 = keypair.pubkey().to_string();
    let response = MessageSignResponse {
        signature: signature_b64,
        public_key: public_key_b58,
        message: req.message,
    };
    let resp = serde_json::json!({"success": true, "data": response});
    (StatusCode::OK, axum::Json(resp))
}

async fn verify_message(Json(req): Json<MessageVerifyRequest>) -> impl IntoResponse {
    use ed25519_dalek::Verifier;
    use ed25519_dalek::PublicKey as DalekPublicKey;
    use ed25519_dalek::Signature as DalekSignature;
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        let err = serde_json::json!({"success": false, "error": "Missing required fields"});
        return (StatusCode::BAD_REQUEST, axum::Json(err));
    }
    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid base58 pubkey"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let dalek_pubkey = match DalekPublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid pubkey bytes"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let sig_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid base64 signature"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let dalek_sig = match DalekSignature::from_bytes(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid signature bytes"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let valid = dalek_pubkey.verify(req.message.as_bytes(), &dalek_sig).is_ok();
    let response = MessageVerifyResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };
    let resp = serde_json::json!({"success": true, "data": response});
    (StatusCode::OK, axum::Json(resp))
}

async fn send_sol(Json(req): Json<SendSolRequest>) -> impl IntoResponse {
    if req.from.is_empty() || req.to.is_empty() || req.lamports == 0 {
        let err = serde_json::json!({"success": false, "error": "Missing or invalid required fields"});
        return (StatusCode::BAD_REQUEST, axum::Json(err));
    }
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid from address"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid to address"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);
    let accounts: Vec<String> = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();
    let instruction_data = general_purpose::STANDARD.encode(ix.data);
    let response = serde_json::json!({
        "program_id": ix.program_id.to_string(),
        "accounts": accounts,
        "instruction_data": instruction_data
    });
    let resp = serde_json::json!({"success": true, "data": response});
    (StatusCode::OK, axum::Json(resp))
}

async fn send_token(Json(req): Json<SendTokenRequest>) -> impl IntoResponse {
    use spl_token::instruction::transfer;
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        let err = serde_json::json!({"success": false, "error": "Missing required fields"});
        return (StatusCode::BAD_REQUEST, axum::Json(err));
    }
    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid destination address"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            let err = serde_json::json!({"success": false, "error": "Invalid owner address"});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let ix = match transfer(
        &spl_token::id(),
        &owner_pubkey, // source
        &destination_pubkey, // destination
        &owner_pubkey, // authority
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            let err = serde_json::json!({"success": false, "error": format!("Failed to create instruction: {}", e)});
            return (StatusCode::BAD_REQUEST, axum::Json(err));
        }
    };
    let accounts: Vec<SendTokenAccountInfo> = ix.accounts.iter().map(|meta| SendTokenAccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(ix.data);
    let response = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    let resp = serde_json::to_value(serde_json::json!({"success": true, "data": response})).unwrap();
    (StatusCode::OK, axum::Json(resp))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
