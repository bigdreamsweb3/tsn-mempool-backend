from __future__ import annotations

"""
TSN Shared Mempool — self-hosted version.

Requirements:
    pip install fastapi uvicorn[standard] httpx firebase-admin python-dotenv

Environment variables (create a .env file):
    GITHUB_TOKEN=<your GitHub PAT with Contents:Write on tsn-epoch-records>
    FIREBASE_PROJECT_ID=<firebase project id>
    FIREBASE_CLIENT_EMAIL=<firebase admin client email>
    FIREBASE_PRIVATE_KEY=<firebase admin private key>
    PORT=8000
    EPOCH_HOURS=7
"""

import asyncio
import base64
import glob
import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional
from uuid import uuid4

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Path as ApiPath, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent / ".env")

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("tsn-mempool")

# ── Config ───────────────────────────────────────────────────────────────────
GITHUB_REPO     = "bigdreamsweb3/tsn-epoch-records"
GITHUB_API      = "https://api.github.com"
MEMPOOL_STORE   = os.environ.get("MEMPOOL_STORE", "file").strip().lower()
MEMPOOL_FILE    = Path(os.environ.get("MEMPOOL_FILE", ".mempool-store.json")).resolve()
FIREBASE_COLLECTION = os.environ.get("FIREBASE_COLLECTION", "tsn_mempool").strip()
SOLANA_RPC_URL  = os.environ.get("SOLANA_RPC_URL") or os.environ.get("RPC_URL") or "https://api.devnet.solana.com"
TSN_PROGRAM_ID  = os.environ.get("TSN_PROGRAM_ID") or os.environ.get("PROGRAM_ID") or "TSN31jddtsmUg4D5aEdhY31nwB1e53VJJg9X8NoRP8V"
EPOCH_HOURS     = int(os.environ.get("EPOCH_HOURS", "7"))
EPOCH_SECS      = EPOCH_HOURS * 60 * 60
VAULT_LIQUIDITY_REFRESH_SECS = max(60, int(os.environ.get("VAULT_LIQUIDITY_REFRESH_SECS", str(EPOCH_SECS))))
PORT            = int(os.environ.get("PORT", "8000"))
MEMPOOL_NS      = "tsn"
CLAIM_PROCESSING_TIMEOUT_SECS = int(os.environ.get("CLAIM_PROCESSING_TIMEOUT_SECS", "300"))
CRANKER_HEARTBEAT_TTL_SECS = int(os.environ.get("CRANKER_HEARTBEAT_TTL_SECS", "30"))
DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
CRANKER_VAULT_ACCOUNT_SIZE = 162
CRANKER_VAULT_DISCRIMINATOR = hashlib.sha256(b"account:CrankerVault").digest()[:8]
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_vault_liquidity_cache: Optional[dict[str, Any]] = None
_vault_liquidity_lock = asyncio.Lock()

TERMINAL_INTENT_STATUSES = {
    "executed",
    "settled",
    "completed",
    "failed",
    "canceled",
    "cancelled",
    "expired",
    "reverted",
}
TERMINAL_CLAIM_STATUSES = {
    "completed",
    "failed",
    "canceled",
    "cancelled",
    "expired",
}

def get_supported_token_mints() -> set[str]:
    raw = os.environ.get("SOLANA_ALLOWED_SPL_TOKENS", "").strip()
    if not raw:
        return {DEVNET_USDC_MINT}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return {DEVNET_USDC_MINT}
        mints = {
            str(token.get("mintAddress", "")).strip()
            for token in parsed
            if isinstance(token, dict) and str(token.get("mintAddress", "")).strip()
        }
        return mints or {DEVNET_USDC_MINT}
    except json.JSONDecodeError:
        logger.warning("SOLANA_ALLOWED_SPL_TOKENS was invalid JSON; using devnet USDC only")
        return {DEVNET_USDC_MINT}

def get_supported_token_metadata() -> dict[str, dict[str, Any]]:
    raw = os.environ.get("SOLANA_ALLOWED_SPL_TOKENS", "").strip()
    default = {
        DEVNET_USDC_MINT: {
            "symbol": "USDC",
            "name": "USD Coin",
            "decimals": 6,
            "unit_price_usd": 1.0,
        }
    }
    if not raw:
        return default
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return default
    if not isinstance(parsed, list):
        return default
    metadata = {}
    for token in parsed:
        if not isinstance(token, dict):
            continue
        mint = str(token.get("mintAddress", "")).strip()
        if not mint:
            continue
        unit_price_usd = parse_optional_float(
            token.get("unitPriceUsd")
            or token.get("unit_price_usd")
            or token.get("priceUsd")
            or token.get("usdPrice")
        )
        symbol = str(token.get("symbol") or "").upper()
        metadata[mint] = {
            "symbol": token.get("symbol") or mint[:6].upper(),
            "name": token.get("name") or token.get("symbol") or "Token",
            "decimals": int(token.get("decimals") or 0),
            "unit_price_usd": unit_price_usd if unit_price_usd is not None else (1.0 if symbol in {"USDC", "USDT"} else None),
        }
    return metadata or default

def parse_optional_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None

def encode_base58(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    return (BASE58_ALPHABET[0] * leading_zeroes) + (encoded or BASE58_ALPHABET[0])

# ── Store helpers ─────────────────────────────────────────────────────────────
class FirebaseStore:
    """Firestore-backed store with the hash-like methods used by this API."""

    def __init__(self):
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore
        except ImportError as exc:
            raise RuntimeError(
                "firebase-admin is required for TSN mempool storage. "
                "Run: pip install -r requirements.txt"
            ) from exc

        if not firebase_admin._apps:
            project_id = os.environ.get("FIREBASE_PROJECT_ID")
            client_email = os.environ.get("FIREBASE_CLIENT_EMAIL")
            private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
            credentials_path = (
                os.environ.get("FIREBASE_CREDENTIALS")
                or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            )
            if not credentials_path:
                credential_files = glob.glob(os.path.join(".fb_creds", "*.json"))
                credentials_path = credential_files[0] if credential_files else None

            if credentials_path:
                firebase_admin.initialize_app(credentials.Certificate(credentials_path))
            elif project_id and client_email and private_key:
                firebase_admin.initialize_app(
                    credentials.Certificate({
                        "type": "service_account",
                        "project_id": project_id,
                        "client_email": client_email,
                        "private_key": private_key,
                        "token_uri": "https://oauth2.googleapis.com/token",
                    })
                )
            else:
                raise RuntimeError(
                    "Firebase mempool storage requires FIREBASE_PROJECT_ID, "
                    "FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY in .env, "
                    "or a Firebase service-account JSON file in .fb_creds"
                )

        self.db = firestore.client()
        self.root = self.db.collection(FIREBASE_COLLECTION)

    def _doc(self, key: str):
        return self.root.document(key.replace("/", "__"))

    def _item_doc(self, key: str, field: str):
        return self._doc(key).collection("items").document(field.replace("/", "__"))

    async def get(self, key: str) -> Optional[str]:
        doc = await asyncio.to_thread(lambda: self._doc(key).get())
        if not doc.exists:
            return None
        return (doc.to_dict() or {}).get("value")

    async def set(self, key: str, value: str) -> None:
        await asyncio.to_thread(lambda: self._doc(key).set({"value": value}))

    async def hget(self, key: str, field: str) -> Optional[str]:
        doc = await asyncio.to_thread(lambda: self._item_doc(key, field).get())
        if not doc.exists:
            return None
        return (doc.to_dict() or {}).get("value")

    async def hgetall(self, key: str) -> dict:
        def read_items() -> dict:
            return {
                doc.id: (doc.to_dict() or {}).get("value")
                for doc in self._doc(key).collection("items").stream()
            }
        return await asyncio.to_thread(read_items)

    async def hlen(self, key: str) -> int:
        return len(await self.hgetall(key))

    async def hset(self, key: str, field: Optional[str] = None, value: Optional[str] = None, mapping: Optional[dict] = None) -> None:
        if mapping:
            def write_mapping() -> None:
                batch = self.db.batch()
                for item_field, item_value in mapping.items():
                    batch.set(self._item_doc(key, item_field), {"value": item_value})
                batch.commit()
            await asyncio.to_thread(write_mapping)
            return

        if field is None or value is None:
            raise ValueError("hset requires either field/value or mapping")
        await asyncio.to_thread(lambda: self._item_doc(key, field).set({"value": value}))

    async def delete(self, *keys: str) -> None:
        def delete_keys() -> None:
            for key in keys:
                bucket = self._doc(key)
                for doc in bucket.collection("items").stream():
                    doc.reference.delete()
                bucket.delete()
        await asyncio.to_thread(delete_keys)

    async def aclose(self) -> None:
        return None

class FileStore:
    """Local JSON-backed mempool store for devnet testing without Firebase quota."""

    def __init__(self, path: Path = MEMPOOL_FILE):
        self.path = path
        self._lock = asyncio.Lock()

    async def _read(self) -> dict:
        if not self.path.exists():
            return {"values": {}, "hashes": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Local mempool file was invalid JSON; starting fresh: %s", self.path)
            return {"values": {}, "hashes": {}}

    async def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            data = await self._read()
            return data.get("values", {}).get(key)

    async def set(self, key: str, value: str) -> None:
        async with self._lock:
            data = await self._read()
            data.setdefault("values", {})[key] = value
            await self._write(data)

    async def hget(self, key: str, field: str) -> Optional[str]:
        async with self._lock:
            data = await self._read()
            return data.get("hashes", {}).get(key, {}).get(field)

    async def hgetall(self, key: str) -> dict:
        async with self._lock:
            data = await self._read()
            return dict(data.get("hashes", {}).get(key, {}))

    async def hlen(self, key: str) -> int:
        return len(await self.hgetall(key))

    async def hset(self, key: str, field: Optional[str] = None, value: Optional[str] = None, mapping: Optional[dict] = None) -> None:
        async with self._lock:
            data = await self._read()
            bucket = data.setdefault("hashes", {}).setdefault(key, {})
            if mapping:
                bucket.update(mapping)
            elif field is not None and value is not None:
                bucket[field] = value
            else:
                raise ValueError("hset requires either field/value or mapping")
            await self._write(data)

    async def delete(self, *keys: str) -> None:
        async with self._lock:
            data = await self._read()
            for key in keys:
                data.get("values", {}).pop(key, None)
                data.get("hashes", {}).pop(key, None)
            await self._write(data)

    async def aclose(self) -> None:
        return None

_store: Optional[Any] = None

async def get_store() -> Any:
    global _store
    if _store is None:
        if MEMPOOL_STORE == "firebase":
            _store = FirebaseStore()
        elif MEMPOOL_STORE in {"file", "local", "json"}:
            _store = FileStore()
            logger.info("Using local TSN mempool store: %s", MEMPOOL_FILE)
        else:
            raise RuntimeError("Set MEMPOOL_STORE to file or firebase.")
    return _store

async def get_mempool_store() -> Any:
    return await get_store()

def k_intents() -> str: return f"{MEMPOOL_NS}:intents"
def k_claims()  -> str: return f"{MEMPOOL_NS}:claims"
def k_proofs()  -> str: return f"{MEMPOOL_NS}:proofs"
def k_epoch()   -> str: return f"{MEMPOOL_NS}:epoch"
def k_crankers() -> str: return f"{MEMPOOL_NS}:crankers"


async def hget_all_json(key: str) -> list:
    r = await get_mempool_store()
    raw: dict = await r.hgetall(key)
    return [json.loads(v) for v in raw.values()]


async def read_epoch_state() -> dict:
    r = await get_mempool_store()
    raw = await r.get(k_epoch())
    if raw:
        return json.loads(raw)
    now_iso = datetime.now(timezone.utc).isoformat()
    state = {"epoch_number": 1, "started_at": now_iso}
    await r.set(k_epoch(), json.dumps(state))
    return state


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def next_close_for_state(state: dict) -> datetime:
    started_dt = parse_iso(state["started_at"])
    return datetime.fromtimestamp(started_dt.timestamp() + EPOCH_SECS, tz=timezone.utc)


def is_epoch_due(state: dict) -> bool:
    return datetime.now(timezone.utc) >= next_close_for_state(state)


def is_processing_stale(claim: dict, now: datetime) -> bool:
    if claim.get("status") != "processing":
        return False
    updated_at = claim.get("updatedAt") or claim.get("postedAt")
    if not updated_at:
        return True
    return (now - parse_iso(str(updated_at))).total_seconds() >= CLAIM_PROCESSING_TIMEOUT_SECS


async def build_epoch_status() -> EpochStatus:
    r = await get_mempool_store()
    state        = await read_epoch_state()
    intent_count = await r.hlen(k_intents())
    claim_count  = await r.hlen(k_claims())
    proof_count  = await r.hlen(k_proofs())
    next_close   = next_close_for_state(state)
    return EpochStatus(
        epoch_number    = state["epoch_number"],
        epoch_started_at= state["started_at"],
        next_close_at   = next_close.isoformat(),
        intent_count    = int(intent_count),
        claim_count     = int(claim_count),
        proof_count     = int(proof_count),
    )

async def get_token_account_balance_ui(token_account: str) -> tuple[float, int]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountBalance",
        "params": [token_account],
    }
    async with httpx.AsyncClient(timeout=12) as client:
        response = await client.post(SOLANA_RPC_URL, json=payload)
    response.raise_for_status()
    value = response.json().get("result", {}).get("value", {})
    return float(value.get("uiAmountString") or value.get("uiAmount") or 0), int(value.get("decimals") or 0)

async def get_program_accounts(account_size: int) -> list[dict[str, Any]]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getProgramAccounts",
        "params": [
            TSN_PROGRAM_ID,
            {
                "encoding": "base64",
                "filters": [{"dataSize": account_size}],
            },
        ],
    }
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(SOLANA_RPC_URL, json=payload)
    response.raise_for_status()
    return response.json().get("result") or []

async def read_onchain_cranker_vaults() -> list[dict[str, Any]]:
    """Discover CrankerVault accounts from the TSN program and read their public fields."""
    accounts = await get_program_accounts(CRANKER_VAULT_ACCOUNT_SIZE)
    results: list[dict[str, Any]] = []
    supported_metadata = get_supported_token_metadata()
    supported_mints = set(supported_metadata.keys())
    for account in accounts:
        encoded = (((account.get("account") or {}).get("data") or [None])[0])
        if not encoded:
            continue
        try:
            data = base64.b64decode(encoded)
        except Exception:
            continue
        if len(data) != CRANKER_VAULT_ACCOUNT_SIZE or data[:8] != CRANKER_VAULT_DISCRIMINATOR:
            continue
        mother_escrow = encode_base58(data[8:40])
        cranker = encode_base58(data[40:72])
        mint = encode_base58(data[72:104])
        token_account = encode_base58(data[104:136])
        if supported_mints and mint not in supported_mints:
            continue
        total_liquidity_base_units = int.from_bytes(data[137:145], "little")
        total_withdrawn_base_units = int.from_bytes(data[145:153], "little")
        total_rewards_base_units = int.from_bytes(data[153:161], "little")
        metadata = supported_metadata.get(mint, {})
        results.append({
            "cranker_vault": account.get("pubkey"),
            "mother_escrow": mother_escrow,
            "cranker": cranker,
            "token_mint": mint,
            "token_symbol": metadata.get("symbol") or mint[:6].upper(),
            "token_name": metadata.get("name") or metadata.get("symbol") or "Token",
            "unit_price_usd": metadata.get("unit_price_usd"),
            "vault_token_account": token_account,
            "program_total_liquidity_base_units": total_liquidity_base_units,
            "program_total_withdrawn_base_units": total_withdrawn_base_units,
            "program_total_rewards_base_units": total_rewards_base_units,
        })
    return results

async def read_public_vault_liquidity() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for vault in await read_onchain_cranker_vaults():
        balance_ui = 0.0
        decimals = 0
        try:
            balance_ui, decimals = await get_token_account_balance_ui(vault["vault_token_account"])
        except Exception:
            logger.exception("Could not read on-chain vault token balance for %s", vault["vault_token_account"])

        results.append({
            **vault,
            "total_liquidity": balance_ui,
            "total_liquidity_usd": balance_ui * float(vault.get("unit_price_usd") or 0),
            "decimals": decimals,
        })
    return results

async def read_public_vault_liquidity_cached() -> list[dict[str, Any]]:
    """Read vault liquidity from Solana RPC at most once per epoch by default."""
    global _vault_liquidity_cache

    state = await read_epoch_state()
    epoch_number = int(state["epoch_number"])
    now = time.monotonic()
    cached = _vault_liquidity_cache

    if (
        cached
        and cached.get("epoch_number") == epoch_number
        and now - float(cached.get("loaded_at", 0)) < VAULT_LIQUIDITY_REFRESH_SECS
    ):
        return list(cached.get("vaults") or [])

    async with _vault_liquidity_lock:
        now = time.monotonic()
        cached = _vault_liquidity_cache
        if (
            cached
            and cached.get("epoch_number") == epoch_number
            and now - float(cached.get("loaded_at", 0)) < VAULT_LIQUIDITY_REFRESH_SECS
        ):
            return list(cached.get("vaults") or [])

        vaults = await read_public_vault_liquidity()
        _vault_liquidity_cache = {
            "epoch_number": epoch_number,
            "loaded_at": now,
            "vaults": vaults,
        }
        logger.info(
            "vault.liquidity.refreshed epoch=%s vaults=%s next_refresh_secs=%s",
            epoch_number,
            len(vaults),
            VAULT_LIQUIDITY_REFRESH_SECS,
        )
        return list(vaults)

# ── Models ────────────────────────────────────────────────────────────────────
class CreateIntentRequest(BaseModel):
    paymentId:        str           = Field(..., description="Unique payment ID")
    intentSeedHash:   str           = Field(..., description="SHA-256 hex of paymentId")
    recipientHash:    str           = Field(..., description="Hashed recipient")
    tokenMintAddress: str           = Field(..., description="SPL token mint address")
    amount:           float         = Field(..., description="Payment amount")
    recipientAmount:  Optional[float] = Field(None, description="Amount paid to recipient; amount minus this is protocol fee")
    underlyingPayment: Optional[str] = Field(None, description="Protocol payment reference for the authorization")
    senderWallet: Optional[str] = Field(None, description="Wallet that signed the TSN payment authorization")
    senderAuthorizationMessage: Optional[str] = Field(None, description="Canonical TSN payment authorization message")
    senderAuthorizationSignature: Optional[str] = Field(None, description="Wallet signature over the authorization message")
    senderAuthorizationNonce: Optional[str] = Field(None, description="Unique authorization nonce")
    senderAuthorizationIssuedAt: Optional[str] = Field(None, description="Authorization issue timestamp")
    senderAuthorizationExpiresAt: Optional[str] = Field(None, description="Authorization expiry timestamp")
    senderFeeAmount: Optional[float] = Field(None, description="Sender-side protocol fee routed to treasury")
    senderSignedSettlementTransaction: Optional[str] = Field(None, description="Sender co-signed settlement transaction for cranker sponsorship")
    senderSignedSettlementFeePayer: Optional[str] = Field(None, description="Cranker fee payer expected to complete and broadcast the settlement")
    senderSettlementMode: Optional[str] = Field(None, description="Settlement authority model")
    senderTokenAccount: Optional[str] = Field(None, description="Sender token account used by the sponsored settlement")
    settlementVault: Optional[str] = Field(None, description="Per-payment vault PDA")
    settlementTokenAccount: Optional[str] = Field(None, description="Per-payment vault token account")
    settlementPaymentIntentId: Optional[str] = Field(None, description="u64 payment intent id used by the TSN vault instruction")
    source:            Optional[str] = Field(None)

class MempoolIntent(CreateIntentRequest):
    id:                   str
    status:               str           = "pending"
    assignedCrankerPubkey: Optional[str] = None
    escrowTxSig:          Optional[str] = None
    claimTxSig:           Optional[str] = None
    proofTxSig:           Optional[str] = None
    settlementResolution: Optional[str] = None
    settlementReason:     Optional[str] = None
    postedAt:             str
    updatedAt:            str

class PostClaimRequest(BaseModel):
    paymentId:         str           = Field(...)
    intentId:          str           = Field(...)
    recipientHash:     str           = Field(...)
    destinationWallet: str           = Field(...)
    autoclaim:         bool          = Field(False)
    source:            Optional[str] = Field(None)

class MempoolClaimRequest(PostClaimRequest):
    id:               str
    status:           str           = "pending"
    settlementReason: Optional[str] = None
    postedAt:         str
    updatedAt:        str

class ProofOfPayment(BaseModel):
    intent_id:         str           = Field(...)
    timestamp:         str           = Field(...)
    cranker_pubkey:    str           = Field(...)
    proof_tx:          str           = Field(...)
    encrypted_payload: Optional[str] = Field(None)

class WorkItem(BaseModel):
    intent:       MempoolIntent
    claimRequest: MempoolClaimRequest

class IntentWorkItem(BaseModel):
    intent: MempoolIntent

class UpdateStatusRequest(BaseModel):
    status:               str           = Field(...)
    assignedCrankerPubkey: Optional[str] = Field(None)
    escrowTxSig:          Optional[str] = Field(None)
    claimTxSig:           Optional[str] = Field(None)
    proofTxSig:           Optional[str] = Field(None)
    settlementResolution: Optional[str] = Field(None)
    settlementReason:     Optional[str] = Field(None)

class CrankerHeartbeatRequest(BaseModel):
    operator_pubkey: str = Field(...)
    cranker_pubkey: Optional[str] = Field(None)
    version: Optional[str] = Field(None)
    source: Optional[str] = Field(None)

class CrankerHeartbeatRecord(CrankerHeartbeatRequest):
    first_seen_at: str
    last_seen_at: str
    online: bool = True

class EpochStatus(BaseModel):
    epoch_number:    int
    epoch_started_at: str
    next_close_at:   str
    intent_count:    int
    claim_count:     int
    proof_count:     int

class EpochCloseResult(BaseModel):
    epoch_number:     int
    intents_archived: int
    claims_archived:  int
    proofs_archived:  int
    intents_rolled_over: int = 0
    claims_rolled_over:  int = 0
    intents_pruned:      int = 0
    claims_pruned:       int = 0
    proofs_pruned:       int = 0
    github_commit_url: str
    new_epoch_number:  int
    message:           str

class MempoolStatusRequest(BaseModel):
    action: Optional[str] = Field(default="status")

class MempoolStatusResponse(BaseModel):
    status: str = "ok"
    epoch:  EpochStatus

class IntentToClaimMetrics(BaseModel):
    sample_count: int
    average_ms: float
    min_ms: float
    max_ms: float
    last_ms: float
    updated_at: Optional[str] = None

class UptimeMetrics(BaseModel):
    service_started_at: str
    uptime_seconds: int
    uptime_days: float
    downtime_events: int = 0

class MetricsResponse(BaseModel):
    intent_to_claim: IntentToClaimMetrics
    uptime: UptimeMetrics
    active_crankers_last_epoch: int

class TokenNetworkStatus(BaseModel):
    token_mint: str
    token_symbol: Optional[str] = None
    token_name: Optional[str] = None
    unit_price_usd: Optional[float] = None
    vault_token_account: Optional[str] = None
    cranker_vault: Optional[str] = None
    total_vault_liquidity_units: float = 0
    total_vault_liquidity_usd: float = 0
    total_vault_liquidity: float = 0
    total_intent_amount: float
    pending_intent_amount: float
    executed_intent_amount: float
    vault_liquidity_estimate: float
    liquidity_source: str = "program_scan"

class NetworkOverviewResponse(BaseModel):
    online_crankers_last_epoch: int
    total_crankers_seen: int
    total_vault_liquidity_usd: float
    total_vault_liquidity: float
    tokens: list[TokenNetworkStatus]

SERVICE_STARTED_AT = datetime.now(timezone.utc)

# ── GitHub archive ────────────────────────────────────────────────────────────
async def commit_epoch_to_github(
    epoch_number: int,
    intents: list, claims: list, proofs: list,
    closed_at: str,
) -> str:
    token = os.environ["GITHUB_TOKEN"]
    record = {
        "epoch_number": epoch_number,
        "closed_at":    closed_at,
        "summary": {
            "intent_count": len(intents),
            "claim_count":  len(claims),
            "proof_count":  len(proofs),
        },
        "intents":        intents,
        "claim_requests": claims,
        "proofs":         proofs,
    }
    content_b64 = base64.b64encode(
        (json.dumps(record, indent=2) + "\n").encode()
    ).decode()
    date_str  = closed_at[:10]
    file_path = f"epochs/epoch-{epoch_number}-{date_str}.json"
    commit_msg = (
        f"epoch {epoch_number} closed at {closed_at} -- "
        f"{len(intents)} intents, {len(claims)} claims, {len(proofs)} proofs"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        check = await client.get(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{file_path}",
            headers=headers,
        )
        payload: dict[str, Any] = {"message": commit_msg, "content": content_b64}
        if check.status_code == 200:
            payload["sha"] = check.json().get("sha")
        resp = await client.put(
            f"{GITHUB_API}/repos/{GITHUB_REPO}/contents/{file_path}",
            json=payload, headers=headers,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"GitHub commit failed ({resp.status_code}): {resp.text[:400]}")
        return resp.json()["content"]["html_url"]


async def close_epoch_task() -> EpochCloseResult:
    r = await get_mempool_store()
    intents = await hget_all_json(k_intents())
    claims  = await hget_all_json(k_claims())
    proofs  = await hget_all_json(k_proofs())
    state   = await read_epoch_state()
    epoch_number = state["epoch_number"]
    closed_at    = datetime.now(timezone.utc).isoformat()

    logger.info("Closing epoch %d: %d intents, %d claims, %d proofs",
                epoch_number, len(intents), len(claims), len(proofs))

    commit_url = await commit_epoch_to_github(
        epoch_number, intents, claims, proofs, closed_at
    )

    now = datetime.now(timezone.utc)
    proof_intent_ids = {proof["intent_id"] for proof in proofs}
    terminal_claim_intent_ids = {
        claim["intentId"]
        for claim in claims
        if claim.get("status") in TERMINAL_CLAIM_STATUSES
    }

    rollover_intents = []
    pruned_intents = []
    for intent in intents:
        status = str(intent.get("status", "pending"))
        should_prune = (
            status in TERMINAL_INTENT_STATUSES
            or intent["id"] in proof_intent_ids
            or intent["id"] in terminal_claim_intent_ids
        )
        if should_prune:
            pruned_intents.append(intent)
        else:
            rollover_intents.append(intent)

    rollover_intent_ids = {intent["id"] for intent in rollover_intents}
    rollover_claims = []
    pruned_claims = []
    for claim in claims:
        status = str(claim.get("status", "pending"))
        if status in TERMINAL_CLAIM_STATUSES or claim.get("intentId") not in rollover_intent_ids:
            pruned_claims.append(claim)
            continue

        if is_processing_stale(claim, now):
            claim = {
                **claim,
                "status": "pending",
                "settlementReason": "Rolled over after stale processing lease.",
                "updatedAt": closed_at,
            }
        rollover_claims.append(claim)

    await r.delete(k_intents())
    await r.delete(k_claims())
    await r.delete(k_proofs())
    if rollover_intents:
        await r.hset(
            k_intents(),
            mapping={intent["id"]: json.dumps(intent) for intent in rollover_intents},
        )
    if rollover_claims:
        await r.hset(
            k_claims(),
            mapping={claim["id"]: json.dumps(claim) for claim in rollover_claims},
        )

    new_epoch = epoch_number + 1
    await r.set(k_epoch(), json.dumps({
        "epoch_number": new_epoch, "started_at": closed_at,
    }))
    return EpochCloseResult(
        epoch_number=epoch_number,
        intents_archived=len(intents), claims_archived=len(claims),
        proofs_archived=len(proofs),
        intents_rolled_over=len(rollover_intents),
        claims_rolled_over=len(rollover_claims),
        intents_pruned=len(pruned_intents),
        claims_pruned=len(pruned_claims),
        proofs_pruned=len(proofs),
        github_commit_url=commit_url,
        new_epoch_number=new_epoch,
        message=(
            f"Epoch {epoch_number} archived. Epoch {new_epoch} started. "
            f"Rolled over {len(rollover_intents)} intents and {len(rollover_claims)} claims."
        ),
    )

# ── Background scheduler ──────────────────────────────────────────────────────
async def epoch_scheduler():
    while True:
        try:
            state = await read_epoch_state()
            next_close = next_close_for_state(state)
            sleep_for = max(1, int((next_close - datetime.now(timezone.utc)).total_seconds()))
            await asyncio.sleep(sleep_for)
            logger.info("Auto epoch close triggered")
            result = await close_epoch_task()
            logger.info(
                "Auto epoch closed: %s; rolled_over=%d/%d",
                result.github_commit_url,
                result.intents_rolled_over,
                result.claims_rolled_over,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Auto epoch close failed; retrying in 60 seconds")
            await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialise the configured mempool store.
    await get_store()
    if is_epoch_due(await read_epoch_state()):
        logger.info("Epoch was overdue on startup; closing before accepting work")
        try:
            result = await close_epoch_task()
            logger.info("Startup epoch close completed: %s", result.message)
        except Exception:
            logger.exception("Startup epoch close failed; live work remains available")
    task = asyncio.create_task(epoch_scheduler())
    logger.info("TSN Mempool started on port %d (epoch every %dh)", PORT, EPOCH_HOURS)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if _store:
        await _store.aclose()

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="TSN Mempool",
    description=(
        "Shared off-chain settlement queue for the Transfer Settlement Network. "
        f"Epoch every {EPOCH_HOURS}h — archives to GitHub (bigdreamsweb3/tsn-epoch-records)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow frontend to call this API from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Root ──────────────────────────────────────────────────────────────────────
@app.post("/", response_model=MempoolStatusResponse)
async def mempool_status(request: MempoolStatusRequest) -> MempoolStatusResponse:
    """Mempool health check and current epoch info."""
    return MempoolStatusResponse(
        status="ok",
        epoch=await build_epoch_status(),
    )

# ── Intents ───────────────────────────────────────────────────────────────────
@app.post("/intents", response_model=MempoolIntent)
async def post_intent(req: CreateIntentRequest) -> MempoolIntent:
    """Submit a payment intent. Idempotent by paymentId."""
    r = await get_mempool_store()
    existing = await r.hget(k_intents(), req.paymentId)
    if existing:
        return MempoolIntent(**json.loads(existing))
    now = datetime.now(timezone.utc).isoformat()
    intent = MempoolIntent(**req.model_dump(), id=req.paymentId,
                           status="pending", postedAt=now, updatedAt=now)
    await r.hset(k_intents(), req.paymentId, json.dumps(intent.model_dump()))
    logger.info("Intent posted: %s", intent.id)
    return intent

@app.get("/intents", response_model=list[MempoolIntent])
async def list_intents(status: Optional[str] = Query(None)) -> list[MempoolIntent]:
    items = [MempoolIntent(**i) for i in await hget_all_json(k_intents())]
    if status:
        items = [i for i in items if i.status == status]
    return sorted(items, key=lambda i: i.postedAt)

@app.patch("/intents/{intent_id}/status", response_model=MempoolIntent)
async def update_intent_status(
    intent_id: str = ApiPath(...),
    body: UpdateStatusRequest = ...,
) -> MempoolIntent:
    r = await get_mempool_store()
    raw = await r.hget(k_intents(), intent_id)
    if not raw:
        raise HTTPException(404, f"Intent {intent_id} not found")
    data = json.loads(raw)
    data.update({"status": body.status, "updatedAt": datetime.now(timezone.utc).isoformat()})
    if body.assignedCrankerPubkey is not None:
        data["assignedCrankerPubkey"] = body.assignedCrankerPubkey
    if body.escrowTxSig is not None:
        data["escrowTxSig"] = body.escrowTxSig
    if body.claimTxSig is not None:
        data["claimTxSig"] = body.claimTxSig
    if body.proofTxSig is not None:
        data["proofTxSig"] = body.proofTxSig
    if body.settlementResolution is not None:
        data["settlementResolution"] = body.settlementResolution
    if body.settlementReason is not None:
        data["settlementReason"] = body.settlementReason
    await r.hset(k_intents(), intent_id, json.dumps(data))
    return MempoolIntent(**data)

# ── Claim Requests ────────────────────────────────────────────────────────────
@app.post("/claim-requests", response_model=MempoolClaimRequest)
async def post_claim_request(req: PostClaimRequest) -> MempoolClaimRequest:
    """Post a claim request. Idempotent — returns existing active claim for intent."""
    r = await get_mempool_store()
    intent_raw = await r.hget(k_intents(), req.intentId)
    if not intent_raw:
        raise HTTPException(409, f"Intent {req.intentId} must exist before a claim request can be posted")
    intent = json.loads(intent_raw)
    if intent.get("status") not in ("pending", "escrowed", "onchain", "claimed", "processing"):
        raise HTTPException(409, f"Intent {req.intentId} is not claimable")
    for c in await hget_all_json(k_claims()):
        if c["intentId"] == req.intentId and c["status"] not in ("failed", "canceled"):
            return MempoolClaimRequest(**c)
    now = datetime.now(timezone.utc).isoformat()
    claim = MempoolClaimRequest(**req.model_dump(), id=str(uuid4()),
                                status="pending", postedAt=now, updatedAt=now)
    await r.hset(k_claims(), claim.id, json.dumps(claim.model_dump()))
    logger.info("Claim posted: %s for intent %s", claim.id, req.intentId)
    return claim

@app.get("/claim-requests", response_model=list[MempoolClaimRequest])
async def list_claim_requests(
    intent_id: Optional[str] = Query(None),
    status:    Optional[str] = Query(None),
) -> list[MempoolClaimRequest]:
    intent_ids = {intent["id"] for intent in await hget_all_json(k_intents())}
    items = [MempoolClaimRequest(**c) for c in await hget_all_json(k_claims())]
    items = [c for c in items if c.intentId in intent_ids]
    if intent_id: items = [c for c in items if c.intentId == intent_id]
    if status:    items = [c for c in items if c.status   == status]
    return sorted(items, key=lambda c: c.postedAt)

@app.patch("/claim-requests/{claim_id}/status", response_model=MempoolClaimRequest)
async def update_claim_status(
    claim_id: str = ApiPath(...),
    body: UpdateStatusRequest = ...,
) -> MempoolClaimRequest:
    r = await get_mempool_store()
    raw = await r.hget(k_claims(), claim_id)
    if not raw:
        raise HTTPException(404, f"Claim {claim_id} not found")
    data = json.loads(raw)
    data.update({"status": body.status, "updatedAt": datetime.now(timezone.utc).isoformat()})
    if body.settlementReason is not None:
        data["settlementReason"] = body.settlementReason
    await r.hset(k_claims(), claim_id, json.dumps(data))
    return MempoolClaimRequest(**data)

# ── Proofs of Payment ─────────────────────────────────────────────────────────
@app.post("/proofs", response_model=ProofOfPayment)
async def post_proof(proof: ProofOfPayment) -> ProofOfPayment:
    """Cranker submits Proof of Payment. Auto-advances intent to 'executed'."""
    r = await get_mempool_store()
    await r.hset(k_proofs(), proof.intent_id, json.dumps(proof.model_dump()))
    # Auto-advance intent: claimed → executed
    raw = await r.hget(k_intents(), proof.intent_id)
    if raw:
        data = json.loads(raw)
        if data.get("status") in ("escrowed", "onchain", "claimed"):
            data["status"]    = "executed"
            data["proofTxSig"] = proof.proof_tx
            data["updatedAt"] = datetime.now(timezone.utc).isoformat()
            await r.hset(k_intents(), proof.intent_id, json.dumps(data))
    logger.info("Proof posted: intent=%s cranker=%s", proof.intent_id, proof.cranker_pubkey)
    return proof

@app.get("/proofs", response_model=list[ProofOfPayment])
async def list_proofs(
    intent_id:     Optional[str] = Query(None),
    cranker_pubkey: Optional[str] = Query(None),
) -> list[ProofOfPayment]:
    items = [ProofOfPayment(**p) for p in await hget_all_json(k_proofs())]
    if intent_id:     items = [p for p in items if p.intent_id     == intent_id]
    if cranker_pubkey: items = [p for p in items if p.cranker_pubkey == cranker_pubkey]
    return sorted(items, key=lambda p: p.timestamp)

# ── Work queue ────────────────────────────────────────────────────────────────
@app.get("/intent-work", response_model=list[IntentWorkItem])
async def list_pending_intent_work(
    limit: int = Query(50, ge=1, le=500)
) -> list[IntentWorkItem]:
    """Pending payment-intent submissions for crankers to create on chain."""
    intents = sorted(
        [
            MempoolIntent(**intent)
            for intent in await hget_all_json(k_intents())
            if intent.get("status") == "pending"
        ],
        key=lambda intent: intent.postedAt,
    )[:limit]
    return [IntentWorkItem(intent=intent) for intent in intents]

@app.get("/work", response_model=list[WorkItem])
async def list_pending_work(
    limit: int = Query(50, ge=1, le=500)
) -> list[WorkItem]:
    """Claim execution work. Intents must already be escrowed by a cranker-sponsored transaction."""
    intents = await hget_all_json(k_intents())
    claims  = await hget_all_json(k_claims())
    intent_map = {i["id"]: i for i in intents}
    pending = sorted(
        [c for c in claims if c["status"] == "pending"],
        key=lambda c: c["postedAt"],
    )[:limit]
    result = []
    for c in pending:
        intent = intent_map.get(c["intentId"])
        if intent and intent["status"] in ("escrowed", "onchain", "claimed"):
            result.append(WorkItem(
                intent=MempoolIntent(**intent),
                claimRequest=MempoolClaimRequest(**c),
            ))
    return result

# ── Epoch management ──────────────────────────────────────────────────────────

@app.get("/metrics", response_model=MetricsResponse)
async def get_metrics() -> MetricsResponse:
    intents = await hget_all_json(k_intents())
    claims = await hget_all_json(k_claims())
    claims_by_payment = {claim["paymentId"]: claim for claim in claims if claim.get("paymentId")}
    samples: list[float] = []
    latest: Optional[str] = None
    for intent in intents:
        claim = claims_by_payment.get(intent.get("paymentId"))
        if not claim:
            continue
        try:
            intent_time = parse_iso(intent["postedAt"])
            claim_time = parse_iso(claim["postedAt"])
        except (KeyError, ValueError):
            continue
        samples.append(max(0, (claim_time - intent_time).total_seconds() * 1000))
        latest = claim.get("postedAt") or latest

    uptime_seconds = int((datetime.now(timezone.utc) - SERVICE_STARTED_AT).total_seconds())
    crankers = {
        proof["cranker_pubkey"]
        for proof in await hget_all_json(k_proofs())
        if proof.get("cranker_pubkey")
    }
    return MetricsResponse(
        intent_to_claim=IntentToClaimMetrics(
            sample_count=len(samples),
            average_ms=sum(samples) / len(samples) if samples else 0,
            min_ms=min(samples) if samples else 0,
            max_ms=max(samples) if samples else 0,
            last_ms=samples[-1] if samples else 0,
            updated_at=latest,
        ),
        uptime=UptimeMetrics(
            service_started_at=SERVICE_STARTED_AT.isoformat(),
            uptime_seconds=uptime_seconds,
            uptime_days=uptime_seconds / 86400,
        ),
        active_crankers_last_epoch=len(crankers),
    )

@app.post("/crankers/heartbeat", response_model=CrankerHeartbeatRecord)
async def post_cranker_heartbeat(req: CrankerHeartbeatRequest) -> CrankerHeartbeatRecord:
    r = await get_mempool_store()
    now_iso = datetime.now(timezone.utc).isoformat()
    existing_raw = await r.hget(k_crankers(), req.operator_pubkey)
    first_seen = now_iso
    if existing_raw:
        try:
            first_seen = json.loads(existing_raw).get("first_seen_at") or now_iso
        except json.JSONDecodeError:
            pass
    record = CrankerHeartbeatRecord(
        **req.model_dump(),
        first_seen_at=first_seen,
        last_seen_at=now_iso,
        online=True,
    )
    await r.hset(k_crankers(), req.operator_pubkey, json.dumps(record.model_dump()))
    return record

@app.get("/network/overview", response_model=NetworkOverviewResponse)
async def get_network_overview() -> NetworkOverviewResponse:
    supported_mints = get_supported_token_mints()
    intents = [
        intent for intent in await hget_all_json(k_intents())
        if intent.get("tokenMintAddress") in supported_mints
    ]
    proofs = await hget_all_json(k_proofs())
    proof_crankers = {
        proof["cranker_pubkey"]
        for proof in proofs
        if proof.get("cranker_pubkey")
    }
    heartbeat_records = await hget_all_json(k_crankers())
    now = datetime.now(timezone.utc)
    online_crankers = set()
    for record in heartbeat_records:
        operator_pubkey = record.get("operator_pubkey")
        last_seen_at = record.get("last_seen_at")
        if not operator_pubkey or not last_seen_at:
            continue
        try:
            if (now - parse_iso(str(last_seen_at))).total_seconds() <= CRANKER_HEARTBEAT_TTL_SECS:
                online_crankers.add(operator_pubkey)
        except ValueError:
            logger.warning("Ignoring cranker heartbeat with invalid last_seen_at=%s", last_seen_at)
    total_seen = proof_crankers.union({
        record.get("operator_pubkey")
        for record in heartbeat_records
        if record.get("operator_pubkey")
    })

    by_mint: dict[str, dict[str, float]] = {}
    for intent in intents:
        mint = intent.get("tokenMintAddress")
        if not mint:
            continue
        bucket = by_mint.setdefault(mint, {"total": 0.0, "pending": 0.0, "executed": 0.0})
        amount = float(intent.get("amount") or 0)
        status = str(intent.get("status", "pending"))
        bucket["total"] += amount
        if status in ("executed", "settled", "completed"):
            bucket["executed"] += amount
        elif status in ("pending", "claimed", "processing"):
            bucket["pending"] += amount

    vaults = await read_public_vault_liquidity_cached()
    token_rows: dict[str, TokenNetworkStatus] = {}
    for vault in vaults:
        mint = vault["token_mint"]
        amounts = by_mint.get(mint, {"total": 0.0, "pending": 0.0, "executed": 0.0})
        liquidity_units = float(vault.get("total_liquidity") or 0)
        liquidity_usd = float(vault.get("total_liquidity_usd") or 0)
        token_rows[mint] = TokenNetworkStatus(
            token_mint=mint,
            token_symbol=vault.get("token_symbol"),
            token_name=vault.get("token_name"),
            unit_price_usd=vault.get("unit_price_usd"),
            vault_token_account=vault.get("vault_token_account"),
            cranker_vault=vault.get("cranker_vault"),
            total_vault_liquidity_units=liquidity_units,
            total_vault_liquidity_usd=liquidity_usd,
            total_vault_liquidity=liquidity_usd,
            total_intent_amount=amounts["total"],
            pending_intent_amount=amounts["pending"],
            executed_intent_amount=amounts["executed"],
            vault_liquidity_estimate=liquidity_usd,
            liquidity_source="program_scan_epoch_cache",
        )

    for mint, amounts in by_mint.items():
        if mint in token_rows:
            continue
        token_rows[mint] = TokenNetworkStatus(
            token_mint=mint,
            total_vault_liquidity=0,
            total_vault_liquidity_units=0,
            total_vault_liquidity_usd=0,
            total_intent_amount=amounts["total"],
            pending_intent_amount=amounts["pending"],
            executed_intent_amount=amounts["executed"],
            vault_liquidity_estimate=0,
            liquidity_source="mempool_intents",
        )

    tokens = sorted(token_rows.values(), key=lambda token: token.total_vault_liquidity_usd, reverse=True)
    return NetworkOverviewResponse(
        online_crankers_last_epoch=len(online_crankers),
        total_crankers_seen=len(total_seen),
        total_vault_liquidity_usd=sum(token.total_vault_liquidity_usd for token in tokens),
        total_vault_liquidity=sum(token.total_vault_liquidity_usd for token in tokens),
        tokens=tokens,
    )

@app.get("/epoch/status", response_model=EpochStatus)
async def get_epoch_status() -> EpochStatus:
    return await build_epoch_status()

@app.post("/epoch/close", response_model=EpochCloseResult)
async def close_epoch() -> EpochCloseResult:
    """Manually close the current epoch, archive it, and roll unresolved work forward."""
    logger.info("Manual epoch close triggered")
    return await close_epoch_task()

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)
