"""
Risk Scoring Module for TSN Mempool

Provides real-time risk scoring for all mempool operations
using multiple signal analysis.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class RiskFactor:
    name: str
    weight: float
    contribution: float
    description: str


@dataclass
class RiskScore:
    score: int  # 0-100
    level: str  # "minimal" | "low" | "medium" | "high" | "critical"
    factors: List[RiskFactor]
    recommendations: List[str]


@dataclass
class RiskScorerConfig:
    weights: Dict[str, float] = None
    
    def __post_init__(self):
        if self.weights is None:
            self.weights = {
                "velocity": 0.25,
                "amount": 0.20,
                "time_pattern": 0.15,
                "wallet_reputation": 0.15,
                "device_fingerprint": 0.10,
                "geographic": 0.05,
                "historical": 0.10,
            }
        
        self.thresholds = {
            "minimal": 0,
            "low": 20,
            "medium": 40,
            "high": 70,
        }


class MempoolRiskScorer:
    """
    Main risk scoring engine for TSN mempool.
    Provides real-time risk assessment using multiple signals.
    """
    
    def __init__(self, config: Optional[RiskScorerConfig] = None):
        self.config = config or RiskScorerConfig()
        self.velocity_counts: Dict[str, int] = {}
        self.reputation_scores: Dict[str, float] = {}
    
    def score_intent(self, params: dict) -> RiskScore:
        """
        Score a payment intent for risk.
        
        Args:
            params: Dict with payment_id, amount, recipient_hash, timestamp
        """
        factors = []
        amount = params.get("amount", 0)
        recipient = params.get("recipient_hash", "")
        
        # Amount score
        amount_score = self._score_amount(amount)
        factors.append(RiskFactor(
            name="amount",
            weight=self.config.weights["amount"],
            contribution=amount_score * self.config.weights["amount"],
            description=f"Amount: {amount} base units"
        ))
        
        # Velocity score
        velocity_count = self.velocity_counts.get(recipient, 0)
        velocity_score = min(1.0, velocity_count / 100)
        factors.append(RiskFactor(
            name="velocity",
            weight=self.config.weights["velocity"],
            contribution=velocity_score * self.config.weights["velocity"],
            description=f"Recent intents: {velocity_count}"
        ))
        
        # Reputation score
        reputation_score = self._get_reputation_score(recipient)
        factors.append(RiskFactor(
            name="wallet_reputation",
            weight=self.config.weights["wallet_reputation"],
            contribution=(1 - reputation_score) * self.config.weights["wallet_reputation"],
            description=f"Reputation: {reputation_score * 100:.0f}%"
        ))
        
        # Calculate total score
        total_score = sum(f.contribution for f in factors)
        normalized_score = min(100, max(0, total_score * 100))
        
        return RiskScore(
            score=round(normalized_score),
            level=self._score_to_level(normalized_score),
            factors=factors,
            recommendations=self._generate_recommendations(normalized_score)
        )
    
    def score_claim_request(self, params: dict) -> RiskScore:
        """
        Score a claim request for risk.
        
        Args:
            params: Dict with claim_request_id, destination_wallet, autoclaim
        """
        factors = []
        wallet = params.get("destination_wallet", "")
        autoclaim = params.get("autoclaim", False)
        
        # Autoclaim score (higher risk)
        autoclaim_score = 0.6 if autoclaim else 0.1
        factors.append(RiskFactor(
            name="autoclaim_pattern",
            weight=0.15,
            contribution=autoclaim_score * 0.15,
            description=f"Autoclaim: {autoclaim}"
        ))
        
        # Wallet reputation
        reputation_score = self._get_reputation_score(wallet)
        factors.append(RiskFactor(
            name="wallet_reputation",
            weight=self.config.weights["wallet_reputation"],
            contribution=(1 - reputation_score) * self.config.weights["wallet_reputation"],
            description=f"Wallet reputation: {reputation_score * 100:.0f}%"
        ))
        
        total_score = sum(f.contribution for f in factors)
        normalized_score = min(100, max(0, total_score * 100))
        
        return RiskScore(
            score=round(normalized_score),
            level=self._score_to_level(normalized_score),
            factors=factors,
            recommendations=self._generate_recommendations(normalized_score)
        )
    
    def score_crunker_operation(self, params: dict) -> RiskScore:
        """
        Score cranker operation for risk.
        
        Args:
            params: Dict with cranker_pubkey, payout_amount
        """
        factors = []
        cranker = params.get("cranker_pubkey", "")
        payout = params.get("payout_amount", 0)
        
        # Payout score
        payout_score = min(1.0, payout / 100000000)
        factors.append(RiskFactor(
            name="payout_amount",
            weight=0.3,
            contribution=payout_score * 0.3,
            description=f"Payout: {payout}"
        ))
        
        # Cranker reputation
        cranker_rep = self._get_reputation_score(cranker)
        factors.append(RiskFactor(
            name="cranker_reputation",
            weight=self.config.weights["wallet_reputation"],
            contribution=(1 - cranker_rep) * self.config.weights["wallet_reputation"],
            description=f"Cranker history: {cranker_rep * 100:.0f}%"
        ))
        
        total_score = sum(f.contribution for f in factors)
        normalized_score = min(100, max(0, total_score * 100))
        
        return RiskScore(
            score=round(normalized_score),
            level=self._score_to_level(normalized_score),
            factors=factors,
            recommendations=self._generate_recommendations(normalized_score)
        )
    
    def record_velocity(self, recipient_hash: str):
        """Record a velocity event"""
        self.velocity_counts[recipient_hash] = self.velocity_counts.get(recipient_hash, 0) + 1
    
    def update_reputation(self, identifier: str, delta: float):
        """Update reputation score (positive or negative delta)"""
        current = self.reputation_scores.get(identifier, 0.5)
        self.reputation_scores[identifier] = max(0, min(1, current + delta))
    
    def _score_amount(self, amount: int) -> float:
        return min(1.0, amount / 1000000000)  # 1B = ~$1000 USDC
    
    def _get_reputation_score(self, identifier: str) -> float:
        return self.reputation_scores.get(identifier, 0.5)
    
    def _score_to_level(self, score: float) -> str:
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "minimal"
    
    def _generate_recommendations(self, score: float) -> List[str]:
        if score >= 70:
            return ["Require additional verification", "Flag for manual review"]
        if score >= 40:
            return ["Monitor closely", "Apply rate limiting"]
        return []


def create_risk_scorer(config: Optional[RiskScorerConfig] = None) -> MempoolRiskScorer:
    """Factory function to create a risk scorer"""
    return MempoolRiskScorer(config)