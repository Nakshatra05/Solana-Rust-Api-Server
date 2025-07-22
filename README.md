# Solana Rust HTTP Server

## Overview
This project is a Rust-based HTTP server that exposes Solana-related endpoints. It provides functionality to generate keypairs, handle SPL tokens, sign/verify messages, and construct valid on-chain instructions. All cryptographic operations use standard libraries, and no private keys are stored on the server.

## Features & Endpoints
All endpoints return JSON responses in the following format:
- **Success (HTTP 200):**
  ```json
  { "success": true, "data": { "example_field": "example_value" } }
  ```
- **Error (HTTP 400):**
  ```json
  { "success": false, "error": "Description of error" }
  ```

### 1. Generate Keypair
- **POST** `/keypair`
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "pubkey": "base58-encoded-public-key",
      "secret": "base58-encoded-secret-key"
    }
  }
  ```

### 2. Create Token
- **POST** `/token/create`
- **Request:**
  ```json
  {
    "mintAuthority": "base58-encoded-public-key",
    "mint": "base58-encoded-public-key",
    "decimals": 6
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "program_id": "string",
      "accounts": [
        { "pubkey": "pubkey", "is_signer": true, "is_writable": true }
      ],
      "instruction_data": "base64-encoded-data"
    }
  }
  ```

### 3. Mint Token
- **POST** `/token/mint`
- **Request:**
  ```json
  {
    "mint": "mint-address",
    "destination": "destination-user-address",
    "authority": "authority-address",
    "amount": 1000000
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "program_id": "string",
      "accounts": [
        { "pubkey": "pubkey", "is_signer": false, "is_writable": true }
      ],
      "instruction_data": "base64-encoded-data"
    }
  }
  ```

### 4. Sign Message
- **POST** `/message/sign`
- **Request:**
  ```json
  {
    "message": "Hello, Solana!",
    "secret": "base58-encoded-secret-key"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "signature": "base64-encoded-signature",
      "public_key": "base58-encoded-public-key",
      "message": "Hello, Solana!"
    }
  }
  ```
- **Error (missing fields):**
  ```json
  { "success": false, "error": "Missing required fields" }
  ```

### 5. Verify Message
- **POST** `/message/verify`
- **Request:**
  ```json
  {
    "message": "Hello, Solana!",
    "signature": "base64-encoded-signature",
    "pubkey": "base58-encoded-public-key"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "valid": true,
      "message": "Hello, Solana!",
      "pubkey": "base58-encoded-public-key"
    }
  }
  ```

### 6. Send SOL
- **POST** `/send/sol`
- **Request:**
  ```json
  {
    "from": "sender-address",
    "to": "recipient-address",
    "lamports": 100000
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "program_id": "respective program id",
      "accounts": [
        "address of first account",
        "address of second account"
      ],
      "instruction_data": "instruction_data"
    }
  }
  ```

### 7. Send Token
- **POST** `/send/token`
- **Request:**
  ```json
  {
    "destination": "destination-user-address",
    "mint": "mint-address",
    "owner": "owner-address",
    "amount": 100000
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "data": {
      "program_id": "respective program id",
      "accounts": [
        { "pubkey": "pubkey", "isSigner": true }
      ],
      "instruction_data": "instruction_data"
    }
  }
  ```

## Technical Details
- **Signature Implementation:** Ed25519 for signing/verification
- **Encoding:** Base58 for public/private keys, base64 for signatures and instruction data
- **Error Handling:**
  - All endpoints return detailed error messages in the specified format
  - Proper validation of all input fields
  - Consistent error message format
- **Security Considerations:**
  - No private keys are stored on the server
  - All cryptographic operations use standard libraries
  - Input validation for all endpoints
  - Proper error handling to avoid information leakage

## Getting Started
### Prerequisites
- Rust (https://rustup.rs/)
- Solana SDK dependencies (see `Cargo.toml`)

### Build & Run
```sh
cargo build
cargo run
```
The server will listen on `0.0.0.0:3000` by default.

### Example Usage
You can use `curl`, Postman, or any HTTP client to interact with the endpoints. Example:
```sh
curl -X POST http://localhost:3000/keypair
```

### Testing Endpoints
- Use the provided endpoint specifications and example requests above.
- For public access, you can use [ngrok](https://ngrok.com/) to expose your local server:
  ```sh
  ngrok http 3000
  ```

## Dependencies
- [axum](https://crates.io/crates/axum)
- [serde](https://crates.io/crates/serde)
- [solana-sdk](https://crates.io/crates/solana-sdk)
- [spl-token](https://crates.io/crates/spl-token)
- [bs58](https://crates.io/crates/bs58)
- [base64](https://crates.io/crates/base64)

## Notes
- All endpoints are stateless and do not persist any sensitive data.
- The server is suitable for local development, testing, and as a reference implementation for Solana-related HTTP APIs.

---
