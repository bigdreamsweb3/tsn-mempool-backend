# TSN Mempool Backend

Python-based mempool server for TrustLink TSN (Transfer Settlement Network).

## What it does

- Maintains the pending transaction mempool
- Tracks unconfirmed payment intents
- Provides API for the frontend explorer

## Setup

```bash
pip install -r requirements.txt
python server.py
```

## Environment

Copy `.env.example` to `.env` and configure:
- `PORT` - Server port (default: 3000)
- `RPC_URL` - Solana RPC endpoint
- `MINT_ADDRESS` - Token mint address

## API Endpoints

- `GET /api/mempool` - List pending transactions
- `GET /api/mempool/<tx_id>` - Get transaction details

## Part of TrustLink

This is a submodule of [trustlink-pay](https://github.com/bigdreamsweb3/trustlink-pay).

For the frontend explorer, see [tsn-mempool-frontend](https://github.com/bigdreamsweb3/tsn-mempool-frontend).