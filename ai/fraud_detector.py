"""
Fraud Detection Module for TSN Mempool

Detects fraudulent patterns in payment intents, claim requests,
and cranker operations.
"""

from dataclasses import dataclass, field
from typing import Set, Optional
from enum import Enum


class FraudIndicator(str, Enum):
    DUPLICATE_INTENT = "duplicate_intent"
    REPLAY_ATTACK = "replay_attack"
    SYBIL_ATTEMPT = "sybil_attempt"
    COORDINATED_CLAIM = "coordinated_claim"
    PAYOUT_MANIPULATION = "payout_manipulation"
    FRONT_RUNNING = "front_running"
    SETTLEMENT_MANIPULATION = "settlement_manipulation"
    AMOUNT_THRESHOLD_BREACH = "amount_threshold_breach"
    VELOCITY_EXCEEDED = "velocity_exceeded"
    BLACKLISTED_RECIPIENT = "blacklisted_recipient"


@dataclass
class FraudReport:
    detected: bool
    indicators: list
    confidence: float
    severity: str  # "low" | "medium" | "high" | "critical"
    details: list


@dataclass
class FraudDetectorConfig:
    max_intents_per_payment_id: int = 1
    intent_time_window_ms: int = 60000
    amount_threshold: int = 1000000000  # 1B = ~$1000 USDC
    velocity_window_ms: int = 3600000
    max_velocity_per_window: int = 100
    blacklisted_wallets: Set[str] = field(default_factory=set)


class IntentFraudTracker:
    """Tracks intent patterns to detect fraud within the mempool"""
    
    def __init__(self, config: FraudDetectorConfig):
        self.config = config
        self.seen_payments: dict = {}
        self.recent_intents: dict = {}
    
    def check_duplicate(self, payment_id: str) -> bool:
        return payment_id in self.seen_payments
    
    def record_intent(self, payment_id: str, recipient_hash: str, amount: int):
        self.seen_payments[payment_id] = {"timestamp": self._now()}
        
        if recipient_hash not in self.recent_intents:
            self.recent_intents[recipient_hash] = {"timestamp": self._now(), "count": 0}
        
        self.recent_intents[recipient_hash]["count"] += 1
        self.recent_intents[recipient_hash]["timestamp"] = self._now()
    
    def detect_velocity_anomaly(self, recipient_hash: str) -> bool:
        if recipient_hash not in self.recent_intents:
            return False
        
        entry = self.recent_intents[recipient_hash]
        if self._now() - entry["timestamp"] > self.config.velocity_window_ms:
            del self.recent_intents[recipient_hash]
            return False
        
        return entry["count"] > self.config.max_velocity_per_window
    
    def _now(self) -> int:
        return int(__import__('time').time() * 1000)
    
    def prune(self):
        """Remove old entries"""
        cutoff = self._now() - self.config.velocity_window_ms
        self.recent_intents = {
            k: v for k, v in self.recent_intents.items() 
            if v["timestamp"] > cutoff
        }


class MempoolFraudDetector:
    """
    Main fraud detector for TSN mempool operations.
    Analyzes intents and claim requests for fraud patterns.
    """
    
    def __init__(self, config: Optional[FraudDetectorConfig] = None):
        self.config = config or FraudDetectorConfig()
        self.tracker = IntentFraudTracker(self.config)
    
    def analyze_intent(self, intent: dict) -> FraudReport:
        """
        Analyze a new intent for fraud before mempool admission.
        
        Args:
            intent: Dict with payment_id, amount, recipient_hash
        """
        indicators = []
        details = []
        
        # Check for duplicates
        if self.tracker.check_duplicate(intent.get("payment_id", "")):
            indicators.append(FraudIndicator.DUPLICATE_INTENT.value)
            details.append(f"Payment {intent.get('payment_id')} already in mempool")
        
        # Check amount threshold
        amount = intent.get("amount", 0)
        if amount > self.config.amount_threshold:
            indicators.append(FraudIndicator.AMOUNT_THRESHOLD_BREACH.value)
            details.append(f"Amount {amount} exceeds threshold")
        
        # Check velocity anomaly
        recipient = intent.get("recipient_hash", "")
        if self.tracker.detect_velocity_anomaly(recipient):
            indicators.append(FraudIndicator.VELOCITY_EXCEEDED.value)
            details.append("Recipient exceeds velocity limit")
        
        # Check blacklist
        if recipient in self.config.blacklisted_wallets:
            indicators.append(FraudIndicator.BLACKLISTED_RECIPIENT.value)
            details.append("Recipient is on fraud blacklist")
        
        severity = self._calculate_severity(indicators)
        confidence = self._calculate_confidence(indicators)
        
        return FraudReport(
            detected=len(indicators) > 0,
            indicators=indicators,
            confidence=confidence,
            severity=severity,
            details=details
        )
    
    def analyze_claim_request(self, claim_request: dict) -> FraudReport:
        """
        Analyze a claim request for fraud patterns.
        
        Args:
            claim_request: Dict with recipient_hash, destination_wallet, autoclaim, intent_id
        """
        indicators = []
        details = []
        
        destination = claim_request.get("destination_wallet", "")
        
        if destination in self.config.blacklisted_wallets:
            indicators.append(FraudIndicator.BLACKLISTED_RECIPIENT.value)
            details.append("Destination wallet on blacklist")
        
        if claim_request.get("autoclaim", False):
            # Autoclaim with no history is suspicious
            if self.tracker.check_duplicate(claim_request.get("intent_id", "")):
                indicators.append(FraudIndicator.COORDINATED_CLAIM.value)
                details.append("Autoclaim pattern detected")
        
        severity = self._calculate_severity(indicators)
        confidence = self._calculate_confidence(indicators)
        
        return FraudReport(
            detected=len(indicators) > 0,
            indicators=indicators,
            confidence=confidence,
            severity=severity,
            details=details
        )
    
    def validate_payout_amount(self, claimed_amount: int, intent_amount: int) -> dict:
        """
        Validate payout amounts match intent.
        
        Returns:
            Dict with valid (bool) and discrepancy (float)
        """
        if intent_amount == 0:
            return {"valid": False, "discrepancy": 1.0}
        
        discrepancy = abs(claimed_amount - intent_amount) / intent_amount
        return {
            "valid": discrepancy <= 0.001,  # 0.1% tolerance
            "discrepancy": discrepancy
        }
    
    def record_intent(self, payment_id: str, recipient_hash: str, amount: int):
        """Record intent after successful fraud check"""
        self.tracker.record_intent(payment_id, recipient_hash, amount)
    
    def _calculate_severity(self, indicators: list) -> str:
        if FraudIndicator.BLACKLISTED_RECIPIENT.value in indicators:
            return "critical"
        if FraudIndicator.REPLAY_ATTACK.value in indicators:
            return "critical"
        if FraudIndicator.PAYOUT_MANIPULATION.value in indicators:
            return "high"
        if FraudIndicator.SYBIL_ATTEMPT.value in indicators or FraudIndicator.COORDINATED_CLAIM.value in indicators:
            return "medium"
        return "low"
    
    def _calculate_confidence(self, indicators: list) -> float:
        if not indicators:
            return 0.0
        return min(1.0, 0.5 + len(indicators) * 0.15)


def create_fraud_detector(config: Optional[FraudDetectorConfig] = None) -> MempoolFraudDetector:
    """Factory function to create a fraud detector"""
    return MempoolFraudDetector(config)