"""
Proof Verification Module for TSN Mempool

Validates proof of payment submissions to prevent
fraudulent claims and payout manipulation.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ProofVerificationResult:
    valid: bool
    discrepancies: list
    risk_level: str  # "low" | "medium" | "high" | "critical"
    confidence: float


@dataclass
class ProofSubmission:
    intent_id: str
    cranker_pubkey: str
    payout_tx_sig: str
    payout_amount: int
    timestamp: int


@dataclass
class IntentData:
    amount: int
    recipient_hash: str
    claimed_by: Optional[str] = None
    claimed_at: Optional[int] = None


class ProofSubmissionCache:
    """Proof submission cache to detect replay attacks"""
    
    def __init__(self):
        self.submissions: Dict[str, dict] = {}
    
    def is_submitted(self, intent_id: str) -> bool:
        return intent_id in self.submissions
    
    def record_submission(self, intent_id: str, tx_sig: str):
        self.submissions[intent_id] = {
            "tx_sig": tx_sig,
            "timestamp": int(__import__('time').time() * 1000)
        }
    
    def prune(self, max_age_ms: int = 86400000):
        """Remove old submissions"""
        cutoff = int(__import__('time').time() * 1000) - max_age_ms
        self.submissions = {
            k: v for k, v in self.submissions.items()
            if v["timestamp"] > cutoff
        }


class MempoolProofVerifier:
    """
    Main proof verifier for TSN mempool.
    Validates proof of payment submissions.
    """
    
    def __init__(self):
        self.cache = ProofSubmissionCache()
    
    def verify_proof(self, submission: dict, intent: dict) -> ProofVerificationResult:
        """
        Verify a proof submission against expected values.
        
        Args:
            submission: Dict with intent_id, cranker_pubkey, payout_tx_sig, 
                       payout_amount, timestamp
            intent: Dict with amount, recipient_hash, claimed_by
        """
        discrepancies = []
        
        # Check for double-submission (replay attack)
        if self.cache.is_submitted(submission.get("intent_id", "")):
            discrepancies.append("Proof already submitted for this intent")
        
        # Verify payout amount matches intent
        intent_amount = intent.get("amount", 0)
        payout_amount = submission.get("payout_amount", 0)
        amount_tolerance = 0.001  # 0.1%
        
        if intent_amount > 0:
            amount_diff = abs(payout_amount - intent_amount) / intent_amount
            if amount_diff > amount_tolerance:
                discrepancies.append(
                    f"Payout amount mismatch: {payout_amount} vs {intent_amount}"
                )
        
        # Verify transaction signature format (64 chars)
        tx_sig = submission.get("payout_tx_sig", "")
        if len(tx_sig) != 64:
            discrepancies.append(f"Invalid transaction signature length: {len(tx_sig)}")
        
        # Verify timestamp is reasonable
        now = int(__import__('time').time() * 1000)
        proof_timestamp = submission.get("timestamp", now)
        
        if proof_timestamp > now + 60000:  # Future by more than 1 minute
            discrepancies.append("Proof timestamp is in the future")
        
        if now - proof_timestamp > 3600000:  # Older than 1 hour
            discrepancies.append("Proof is older than 1 hour - may be stale")
        
        # Check cranker authorization
        claimed_by = intent.get("claimed_by")
        cranker = submission.get("cranker_pubkey", "")
        if claimed_by and cranker != claimed_by:
            discrepancies.append(f"Cranker mismatch: {cranker} vs {claimed_by}")
        
        risk_level = self._calculate_risk_level(discrepancies)
        confidence = 0.95 if not discrepancies else max(0, 1 - len(discrepancies) * 0.2)
        
        return ProofVerificationResult(
            valid=len(discrepancies) == 0,
            discrepancies=discrepancies,
            risk_level=risk_level,
            confidence=confidence
        )
    
    def record_proof(self, intent_id: str, tx_sig: str):
        """Record a verified proof submission"""
        self.cache.record_submission(intent_id, tx_sig)
    
    def has_proof(self, intent_id: str) -> bool:
        """Check if intent already has proof submitted"""
        return self.cache.is_submitted(intent_id)
    
    def _calculate_risk_level(self, discrepancies: list) -> str:
        if any("already submitted" in d for d in discrepancies):
            return "critical"
        if any("mismatch" in d for d in discrepancies):
            return "high"
        if any("mismatch" in d.lower() for d in discrepancies):
            return "high"
        if discrepancies:
            return "medium"
        return "low"


def create_proof_verifier() -> MempoolProofVerifier:
    """Factory function to create a proof verifier"""
    return MempoolProofVerifier()