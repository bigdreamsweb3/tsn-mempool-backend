"""
Mempool Guardian - Unified AI Protection Layer for TSN Mempool

Combines all AI protection components into a single interface
for securing the TSN mempool against fraud and manipulation.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum


class GuardianDecision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass
class GuardianResult:
    decision: str
    fraud_report: dict
    risk_score: dict
    anomalies: List[dict]
    behavioral_profile: Optional[dict] = None
    block_reasons: Optional[List[str]] = None
    recommendations: List[str] = []


@dataclass
class GuardianConfig:
    fraud_threshold: float = 0.5
    risk_threshold: int = 70
    auto_block_critical: bool = True


class MempoolGuardian:
    """
    Unified AI protection layer for TSN mempool.
    Combines fraud detection, risk scoring, anomaly detection,
    and behavioral analysis into a single interface.
    """
    
    def __init__(self, config: Optional[GuardianConfig] = None):
        self.config = config or GuardianConfig()
        
        # Import and initialize all AI components
        from .fraud_detector import MempoolFraudDetector, FraudDetectorConfig
        from .risk_scorer import MempoolRiskScorer
        from .anomaly_detector import MempoolAnomalyDetector
        from .behavioral_analyzer import MempoolBehavioralAnalyzer
        from .proof_verifier import MempoolProofVerifier
        from .quote_validator import MempoolQuoteValidator
        from .settlement_protector import MempoolSettlementProtector
        from .cranker_jail import MempoolCrankerJail
        
        self.fraud_detector = MempoolFraudDetector()
        self.risk_scorer = MempoolRiskScorer()
        self.anomaly_detector = MempoolAnomalyDetector()
        self.behavioral_analyzer = MempoolBehavioralAnalyzer()
        self.proof_verifier = MempoolProofVerifier()
        self.quote_validator = MempoolQuoteValidator()
        self.settlement_protector = MempoolSettlementProtector()
        self.cranker_jail = MempoolCrankerJail()
    
    def screen_intent(self, params: dict) -> GuardianResult:
        """
        Pre-transaction screening - analyze intent before mempool admission.
        
        Args:
            params: Dict with payment_id, amount, recipient_hash, timestamp
        """
        anomalies = []
        
        # Fraud detection
        fraud_report = self.fraud_detector.analyze_intent(params)
        
        # Risk scoring
        risk_score = self.risk_scorer.score_intent(params)
        
        # Velocity anomaly detection
        velocity_anomaly = self.anomaly_detector.detect_velocity_anomaly(
            params.get("recipient_hash", ""),
            params.get("velocity_count", 1)
        )
        if velocity_anomaly.detected:
            anomalies.append({
                "type": velocity_anomaly.type,
                "detected": velocity_anomaly.detected,
                "severity": velocity_anomaly.severity,
                "description": velocity_anomaly.description,
                "metrics": velocity_anomaly.metrics
            })
        
        # Amount anomaly detection
        amount_anomaly = self.anomaly_detector.detect_amount_anomaly(params.get("amount", 0))
        if amount_anomaly.detected:
            anomalies.append({
                "type": amount_anomaly.type,
                "detected": amount_anomaly.detected,
                "severity": amount_anomaly.severity,
                "description": amount_anomaly.description,
                "metrics": amount_anomaly.metrics
            })
        
        # Behavioral analysis
        behavioral_result = self.behavioral_analyzer.detect_suspicious_intent({
            "wallet_hash": params.get("recipient_hash", ""),
            "amount": params.get("amount", 0)
        })
        
        # Determine decision
        decision = self._make_decision(fraud_report, risk_score, anomalies, behavioral_result)
        block_reasons = self._generate_block_reasons(fraud_report, anomalies) if decision == GuardianDecision.BLOCK.value else None
        
        # Record for future analysis if allowed
        if decision != GuardianDecision.BLOCK.value:
            self._record_intent(params)
        
        # Get behavioral profile
        profile = self.behavioral_analyzer.analyze_recipient(params.get("recipient_hash", ""))
        behavioral_profile = {
            "wallet_hash": profile.wallet_hash,
            "pattern": profile.pattern,
            "risk_score": profile.risk_score,
            "transaction_count": profile.transaction_count,
            "average_amount": profile.average_amount
        }
        
        return GuardianResult(
            decision=decision,
            fraud_report={
                "detected": fraud_report.detected,
                "indicators": fraud_report.indicators,
                "confidence": fraud_report.confidence,
                "severity": fraud_report.severity,
                "details": fraud_report.details
            },
            risk_score={
                "score": risk_score.score,
                "level": risk_score.level,
                "factors": [
                    {"name": f.name, "contribution": f.contribution}
                    for f in risk_score.factors
                ],
                "recommendations": risk_score.recommendations
            },
            anomalies=anomalies,
            behavioral_profile=behavioral_profile,
            block_reasons=block_reasons,
            recommendations=[]
        )
    
    def screen_claim_request(self, params: dict) -> GuardianResult:
        """
        Validate claim request before processing.
        
        Args:
            params: Dict with claim_request_id, intent_id, recipient_hash,
                   destination_wallet, autoclaim
        """
        fraud_report = self.fraud_detector.analyze_claim_request(params)
        risk_score = self.risk_scorer.score_claim_request(params)
        
        behavioral_result = self.behavioral_analyzer.detect_suspicious_intent({
            "wallet_hash": params.get("recipient_hash", ""),
            "amount": 0
        })
        
        decision = self._make_decision(fraud_report, risk_score, [], behavioral_result)
        block_reasons = fraud_report.details if decision == GuardianDecision.BLOCK.value else None
        
        return GuardianResult(
            decision=decision,
            fraud_report={
                "detected": fraud_report.detected,
                "indicators": fraud_report.indicators,
                "confidence": fraud_report.confidence,
                "severity": fraud_report.severity,
                "details": fraud_report.details
            },
            risk_score={
                "score": risk_score.score,
                "level": risk_score.level,
                "factors": [
                    {"name": f.name, "contribution": f.contribution}
                    for f in risk_score.factors
                ],
                "recommendations": risk_score.recommendations
            },
            anomalies=[],
            block_reasons=block_reasons
        )
    
    def authorize_crunker_operation(self, params: dict) -> dict:
        """
        Validate cranker operation authorization.
        
        Args:
            params: Dict with cranker_pubkey, intent_id, payout_amount
        """
        return self.cranker_jail.can_operate(params.get("cranker_pubkey", ""))
    
    def screen_proof(self, params: dict) -> dict:
        """
        Screen proof submission.
        
        Args:
            params: Dict with intent_id, cranker_pubkey, payout_tx_sig,
                   payout_amount, timestamp
        """
        return self.proof_verifier.verify_proof(params, {"amount": 0})
    
    def validate_quote(self, quote: dict, request: dict) -> dict:
        """
        Validate fee quote.
        
        Args:
            quote: Dict with sender_fee, claim_fee, network_fee_estimate,
                  total_fee, timestamp, expires_at, token_mint
            request: Dict with amount, token_mint, recipient_hash
        """
        return self.quote_validator.validate_quote(quote, request)
    
    def validate_settlement_proof(self, params: dict, epoch_id: int) -> dict:
        """
        Validate settlement proof.
        
        Args:
            params: Dict with intent_id, cranker_pubkey, payout_tx_sig,
                   payout_amount, proof_timestamp
            epoch_id: Current epoch ID
        """
        return self.settlement_protector.validate_proof(params, epoch_id)
    
    def record_crunker_result(self, cranker_pubkey: str, success: bool, reason: str = None):
        """
        Record cranker operation result.
        
        Args:
            cranker_pubkey: Cranker wallet address
            success: Whether operation succeeded
            reason: Failure reason if applicable
        """
        if success:
            self.cranker_jail.record_success(cranker_pubkey)
        elif reason:
            self.cranker_jail.record_failure(cranker_pubkey, reason)
    
    def get_crunker_status(self, cranker_pubkey: str) -> dict:
        """Get cranker status"""
        return self.cranker_jail.get_status(cranker_pubkey)
    
    def _make_decision(self, fraud_report, risk_score, anomalies, behavioral) -> str:
        # Auto-block critical fraud
        if fraud_report.severity == "critical" and self.config.auto_block_critical:
            return GuardianDecision.BLOCK.value
        
        # Block if fraud confidence is high
        if fraud_report.detected and fraud_report.confidence > self.config.fraud_threshold:
            return GuardianDecision.BLOCK.value
        
        # Block if risk score is critical
        if risk_score.level == "critical":
            return GuardianDecision.BLOCK.value
        
        # Block if risk score exceeds threshold
        if risk_score.score > self.config.risk_threshold:
            return GuardianDecision.FLAG.value
        
        # Flag if anomalies detected
        if any(a.get("severity") in ["high", "critical"] for a in anomalies):
            return GuardianDecision.FLAG.value
        
        # Flag if behavioral suspicion
        if behavioral.get("suspicious") and behavioral.get("reasons"):
            return GuardianDecision.FLAG.value
        
        return GuardianDecision.ALLOW.value
    
    def _generate_block_reasons(self, fraud_report, anomalies) -> List[str]:
        reasons = list(fraud_report.details)
        for anomaly in anomalies:
            if anomaly.get("severity") in ["high", "critical"]:
                reasons.append(anomaly.get("description", ""))
        return reasons
    
    def _record_intent(self, params: dict):
        """Record intent for future analysis"""
        self.fraud_detector.record_intent(
            params.get("payment_id", ""),
            params.get("recipient_hash", ""),
            params.get("amount", 0)
        )
        self.risk_scorer.record_velocity(params.get("recipient_hash", ""))
        self.anomaly_detector.record_intent(params.get("amount", 0))
        self.behavioral_analyzer.record_intent(
            params.get("recipient_hash", ""),
            params.get("amount", 0)
        )


def create_mempool_guardian(config: Optional[GuardianConfig] = None) -> MempoolGuardian:
    """Factory function to create a mempool guardian"""
    return MempoolGuardian(config)