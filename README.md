# zk-proof-server

A minimal API built in Rust with Axum to generate zero-knowledge proofs (ZK) for confidential transfers on Solana.

### Endpoints
- `POST /generate-keys`
- `POST /proofs/withdraw`
- `POST /proofs/transfer`
- `POST /proofs/deposit`

### Getting Started

```bash
cargo build
cargo run
```

Test the server locally at `http://localhost:3000`.

Deployable to [Render.com](https://render.com/) with a `cargo` buildpack.