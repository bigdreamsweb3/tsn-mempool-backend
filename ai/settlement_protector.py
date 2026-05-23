"""
Settlement Protection Module for TSN Mempool

Monitors and protects epoch settlement operations
from manipulation and fraud.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class SettlementManipulationType(str, Enum):
    DOUBLE_SPEND_ATTEMPT = "double_spend_attempt"
    EPOCH_GRIEFING = "epoch_griefing"
    REIMBURSEMENT_MANIPULATION = "reimbursement_manipulation"
    FEE_DISTRIBUTION_ANOMALY = "fee_distribution_anomaly"
    TIMESTAMP_MANIPULATION = "timestamp_manipulation"


@dataclass
class SettlementProtectionResult:
    safe: bool
    issues: List[str]
    manipulation_type: Optional[str]
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class SettlementProof:
    intent_id: str
    cranker_pubkey: str
    payout_tx_sig: str
    payout_amount: int
    proof_timestamp: int


@dataclass
class EpochSettlement:
    epoch_id: int
    timestamp: int
    total_reimbursements: int
    cranker_payments: Dict[str, int]
    lp_distribution: Dict[str, int]
    treasury_payment: int


class ProofTracker:
    """Tracks proof submissions per epoch for double-spend detection"""
    
    def __init__(self):
        self.proofs: Dict[str, SettlementProof] = {}
        self.epoch_proofs: Dict[int, Set[str]] = {}
    
    def record_proof(self, proof: SettlementProof, epoch_id: int):
        self.proofs[proof.intent_id] = proof
        
        if epoch_id not in self.epoch_proofs:
            self.epoch_proofs[epoch_id] = set()
        self.epoch_proofs[epoch_id].add(proof.intent_id)
    
    def is_double_spend(self, intent_id: str, new_payout_amount: int) -> bool:
        existing = self.proofs.get(intent_id)
        if not existing:
            return False
        
        # If same intent but different amount, might be manipulation
        return existing.payout_amount != new_payout_amount
    
    def get_epoch_proof_count(self, epoch_id: int) -> int:
        return len(self.epoch_proofs.get(epoch_id, set()))
    
    def prune(self, max_epochs: int = 100):
        """Remove old epochs"""
        sorted_epochs = sorted(self.epoch_proofs.keys(), reverse=True)
        for epoch in sorted_epochs[max_epochs:]:
            for intent_id in self.epoch_proofs.get(epoch, set()):
                self.proofs.pop(intent_id, None)
            self.epoch_proofs.pop(epoch, None)


class MempoolSettlementProtector:
    """
    Main settlement protector for TSN mempool.
    Guards epoch settlement operations from manipulation.
    """
    
    def __init__(self):
        self.proof_tracker = ProofTracker()
    
    def validate_proof(self, proof: dict, epoch_id: int) -> SettlementProtectionResult:
        """
        Validate a settlement proof against protocol rules.
        
        Args:
            proof: Dict with intent_id, cranker_pubkey, payout_tx_sig, 
                   payout_amount, proof_timestamp
            epoch_id: Current epoch ID
        """
        issues = []
        now = int(__import__('time').time() * 1000)
        
        # Check for double-spend attempt
        if self.proof_tracker.is_double_spend(
            proof.get("intent_id", ""), 
            proof.get("payout_amount", 0)
        ):
            issues.append("Double-spend attempt detected - same intent with different amount")
        
        # Verify proof timestamp is within epoch window
        epoch_duration_ms = 25200000  # 7 hours
        proof_timestamp = proof.get("proof_timestamp", now)
        
        epoch_start = epoch_id * epoch_duration_ms
        epoch_end = epoch_start + epoch_duration_ms
        
        if proof_timestamp < epoch_start or proof_timestamp > epoch_end:
            issues.append(
                f"Proof timestamp {proof_timestamp} outside epoch window [{epoch_start}, {epoch_end}]"
            )
        
        # Check for timestamp manipulation (proof too close to epoch end)
        time_to_epoch_end = epoch_end - proof_timestamp
        if time_to_epoch_end < 60000:  # Less than 1 minute
            issues.append("Proof submitted with less than 1 minute to epoch end - potential griefing")
        
        # Verify payout amount is reasonable
        payout_amount = proof.get("payout_amount", 0)
        if payout_amount <= 0:
            issues.append("Payout amount must be positive")
        
        # Check transaction signature format
        tx_sig = proof.get("payout_tx_sig", "")
        if len(tx_sig) != 64:
            issues.append(f"Invalid transaction signature length: {len(tx_sig)}")
        
        # Determine manipulation type
        manipulation_type = None
        if any("Double-spend" in i for i in issues):
            manipulation_type = SettlementManipulationType.DOUBLE_SPEND_ATTEMPT.value
        elif any("less than 1 minute" in i for i in issues):
            manipulation_type = SettlementManipulationType.EPOCH_GRIEFING.value
        elif any("outside epoch window" in i for i in issues):
            manipulation_type = SettlementManipulationType.TIMESTAMP_MANIPULATION.value
        
        severity = self._calculate_severity(issues, manipulation_type)
        
        return SettlementProtectionResult(
            safe=len(issues) == 0,
            issues=issues,
            manipulation_type=manipulation_type,
            severity=severity
        )
    
    def validate_epoch_settlement(self, settlement: dict) -> SettlementProtectionResult:
        """
        Validate an epoch settlement operation.
        
        Args:
            settlement: Dict with epoch_id, timestamp, total_reimbursements,
                       cranker_payments, lp_distribution, treasury_payment
        """
        issues = []
        now = int(__import__('time').time() * 1000)
        
        # Verify epoch timestamp sequence
        expected_interval = 25200000  # 7 hours
        expected_timestamp = settlement.get("epoch_id", 0) * expected_interval
        timestamp_drift = abs(settlement.get("timestamp", now) - expected_timestamp)
        
        if timestamp_drift > 3600000:  # 1 hour
            issues.append(f"Epoch timestamp drift of {timestamp_drift / 3600000:.1f} hours detected")
        
        # Verify total reimbursements sum
        cranker_total = sum(settlement.get("cranker_payments", {}).values())
        lp_total = sum(settlement.get("lp_distribution", {}).values())
        treasury_payment = settlement.get("treasury_payment", 0)
        expected_total = cranker_total + lp_total + treasury_payment
        total_reimbursements = settlement.get("total_reimbursements", 0)
        
        if abs(total_reimbursements - expected_total) > 1:
            issues.append("Total reimbursements don't match sum of distributions")
        
        # Check for fee distribution anomaly
        if treasury_payment > total_reimbursements * 0.1:
            issues.append("Treasury payment exceeds 10% of total - possible manipulation")
        
        # Verify cranker and LP payments don't exceed total
        if cranker_total + lp_total > total_reimbursements:
            issues.append("Cranker + LP payments exceed total reimbursements")
        
        manipulation_type = None
        if any("don't match" in i for i in issues):
            manipulation_type = SettlementManipulationType.REIMBURSEMENT_MANIPULATION.value
        elif any("exceeds 10%" in i for i in issues):
            manipulation_type = SettlementManipulationType.FEE_DISTRIBUTION_ANOMALY.value
        
        severity = self._calculate_severity(issues, manipulation_type)
        
        return SettlementProtectionResult(
            safe=len(issues) == 0,
            issues=issues,
            manipulation_type=manipulation_type,
            severity=severity
        )
    
    def record_proof(self, proof: dict, epoch_id: int):
        """Record a valid proof"""
        self.proof_tracker.record_proof(SettlementProof(
            intent_id=proof.get("intent_id", ""),
            cranker_pubkey=proof.get("cranker_pubkey", ""),
            payout_tx_sig=proof.get("payout_tx_sig", ""),
            payout_amount=proof.get("payout_amount", 0),
            proof_timestamp=proof.get("proof_timestamp", 0)
        ), epoch_id)
    
    def get_epoch_proof_count(self, epoch_id: int) -> int:
        """Get proof count for an epoch"""
        return self.proof_tracker.get_epoch_proof_count(epoch_id)
    
    def _calculate_severity(self, issues: List[str], manipulation_type: Optional[str]) -> str:
        if manipulation_type == SettlementManipulationType.DOUBLE_SPEND_ATTEMPT.value:
            return "critical"
        if any("exceed" in i for i in issues):
            return "high"
        if manipulation_type:
            return "medium"
        if issues:
            return "low"
        return "low"


def create_settlement_protector() -> MempoolSettlementProtector:
    """Factory function to create a settlement protector"""
    return MempoolSettlementProtector()