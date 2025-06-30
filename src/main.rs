use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use bs58;
use std::net::SocketAddr;
use spl_token::instruction::initialize_mint;
use solana_sdk::{pubkey::Pubkey, instruction::AccountMeta};
use base64;
use spl_token::instruction::mint_to;
use serde_json;
use solana_sdk::system_instruction;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
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
    mintAuthority: String,
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
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenAccountInfo {
    pubkey: String,
    isSigner: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountInfo>,
    instruction_data: String,
}

// Handlers
async fn generate_keypair() -> Json<SuccessResponse<KeypairData>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let data = KeypairData { pubkey, secret };
    Json(SuccessResponse { success: true, data })
}

async fn create_token(Json(req): Json<TokenCreateRequest>) -> Json<SuccessResponse<TokenCreateResponse>> {
    // Parse pubkeys
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: "Invalid mint pubkey".to_string(),
                },
            });
        }
    };
    let mint_authority_pubkey = match Pubkey::from_str(&req.mintAuthority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: "Invalid mintAuthority pubkey".to_string(),
                },
            });
        }
    };
    // Use None for freeze authority for simplicity
    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: format!("Failed to create instruction: {}", e),
                },
            });
        }
    };
    let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|meta: &AccountMeta| AccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = base64::encode(ix.data);
    let response = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Json(SuccessResponse { success: true, data: response })
}

async fn mint_token(Json(req): Json<TokenMintRequest>) -> Json<SuccessResponse<TokenCreateResponse>> {
    use std::str::FromStr;
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: "Invalid mint pubkey".to_string(),
                },
            });
        }
    };
    let dest_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: "Invalid destination pubkey".to_string(),
                },
            });
        }
    };
    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: "Invalid authority pubkey".to_string(),
                },
            });
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
            return Json(SuccessResponse {
                success: false,
                data: TokenCreateResponse {
                    program_id: "".to_string(),
                    accounts: vec![],
                    instruction_data: format!("Failed to create instruction: {}", e),
                },
            });
        }
    };
    let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|meta: &AccountMeta| AccountInfo {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let instruction_data = base64::encode(ix.data);
    let response = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Json(SuccessResponse { success: true, data: response })
}

async fn sign_message(Json(req): Json<MessageSignRequest>) -> Json<serde_json::Value> {
    use solana_sdk::signature::Signature;
    use solana_sdk::signer::keypair::Keypair;
    use std::str::FromStr;

    // Validate fields
    if req.message.is_empty() || req.secret.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    // Decode secret key
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid base58 secret key"
            }));
        }
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key bytes"
            }));
        }
    };
    // Sign message
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_b64 = base64::encode(signature.as_ref());
    let public_key_b58 = keypair.pubkey().to_string();
    let response = MessageSignResponse {
        signature: signature_b64,
        public_key: public_key_b58,
        message: req.message,
    };
    Json(serde_json::json!({
        "success": true,
        "data": response
    }))
}

async fn verify_message(Json(req): Json<MessageVerifyRequest>) -> Json<serde_json::Value> {
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::Signature;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::PublicKey as DalekPublicKey;
    use ed25519_dalek::Signature as DalekSignature;
    use std::str::FromStr;

    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    // Decode pubkey
    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid base58 pubkey"
            }));
        }
    };
    let dalek_pubkey = match DalekPublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid pubkey bytes"
            }));
        }
    };
    // Decode signature
    let sig_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid base64 signature"
            }));
        }
    };
    let dalek_sig = match DalekSignature::from_bytes(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid signature bytes"
            }));
        }
    };
    // Verify
    let valid = dalek_pubkey.verify(req.message.as_bytes(), &dalek_sig).is_ok();
    let response = MessageVerifyResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };
    Json(serde_json::json!({
        "success": true,
        "data": response
    }))
}

async fn send_sol(Json(_req): Json<SendSolRequest>) -> Json<ErrorResponse> {
    Json(ErrorResponse { success: false, error: "Not implemented".to_string() })
}

async fn send_token(Json(req): Json<SendTokenRequest>) -> Json<serde_json::Value> {
    use std::str::FromStr;
    use spl_token::instruction::transfer;
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }
    let destination_pubkey = match solana_sdk::pubkey::Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid destination address"
            }));
        }
    };
    let mint_pubkey = match solana_sdk::pubkey::Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint address"
            }));
        }
    };
    let owner_pubkey = match solana_sdk::pubkey::Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid owner address"
            }));
        }
    };
    // For SPL token transfer, source is owner's associated token account for the mint
    // In a real app, you'd derive the associated token account, but here we just use owner as source for instruction
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
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create instruction: {}", e)
            }));
        }
    };
    let accounts: Vec<SendTokenAccountInfo> = ix.accounts.iter().map(|meta| SendTokenAccountInfo {
        pubkey: meta.pubkey.to_string(),
        isSigner: meta.is_signer,
    }).collect();
    let instruction_data = base64::encode(ix.data);
    let response = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data,
    };
    Json(serde_json::json!({
        "success": true,
        "data": response
    }))
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
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
