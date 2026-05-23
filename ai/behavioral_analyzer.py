"""
Behavioral Analysis Module for TSN Mempool

Analyzes user behavior patterns to detect fraud and abuse.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class BehaviorPattern(str, Enum):
    NORMAL = "normal"
    RUSHING = "rushing"
    SPLITTING = "splitting"
    BATCHING = "batching"
    CIRCULAR = "circular"


@dataclass
class BehavioralProfile:
    wallet_hash: str
    pattern: str
    risk_score: int
    transaction_count: int
    average_amount: float
    autoclaim_preference: float
    first_seen: int
    last_seen: int
    flags: List[str]


class BehavioralDatabase:
    """Behavioral profile database"""
    
    def __init__(self):
        self.profiles: Dict[str, BehavioralProfile] = {}
        self.transaction_history: Dict[str, List[dict]] = {}
    
    def get_profile(self, wallet_hash: str) -> BehavioralProfile:
        if wallet_hash not in self.profiles:
            now = int(__import__('time').time() * 1000)
            self.profiles[wallet_hash] = BehavioralProfile(
                wallet_hash=wallet_hash,
                pattern=BehaviorPattern.NORMAL.value,
                risk_score=0,
                transaction_count=0,
                average_amount=0.0,
                autoclaim_preference=0.0,
                first_seen=now,
                last_seen=now,
                flags=[]
            )
        return self.profiles[wallet_hash]
    
    def update_profile(self, wallet_hash: str, amount: int, autoclaim: bool = False):
        profile = self.get_profile(wallet_hash)
        profile.transaction_count += 1
        profile.last_seen = int(__import__('time').time() * 1000)
        
        # Update average amount
        if profile.transaction_count == 1:
            profile.average_amount = float(amount)
        else:
            profile.average_amount = (
                profile.average_amount * (profile.transaction_count - 1) + amount
            ) / profile.transaction_count
        
        # Update autoclaim preference
        if profile.transaction_count == 1:
            profile.autoclaim_preference = 1.0 if autoclaim else 0.0
        else:
            profile.autoclaim_preference = (
                profile.autoclaim_preference * (profile.transaction_count - 1) + (1.0 if autoclaim else 0.0)
            ) / profile.transaction_count
        
        # Store transaction history
        if wallet_hash not in self.transaction_history:
            self.transaction_history[wallet_hash] = []
        self.transaction_history[wallet_hash].append({
            "timestamp": int(__import__('time').time() * 1000),
            "amount": amount
        })
        
        self._analyze_pattern(profile)
    
    def _analyze_pattern(self, profile: BehavioralProfile):
        history = self.transaction_history.get(profile.wallet_hash, [])
        
        if self._detect_splitting(history):
            profile.pattern = BehaviorPattern.SPLITTING.value
            profile.flags.append("splitting_detected")
        elif self._detect_rushing(history):
            profile.pattern = BehaviorPattern.RUSHING.value
            profile.flags.append("rushing_detected")
        elif self._detect_batching(history):
            profile.pattern = BehaviorPattern.BATCHING.value
            profile.flags.append("batching_detected")
        
        profile.risk_score = self._calculate_risk_score(profile)
    
    def _detect_splitting(self, history: List[dict]) -> bool:
        if len(history) < 3:
            return False
        
        amounts = [h["amount"] for h in history]
        mean = sum(amounts) / len(amounts)
        variance = sum((a - mean) ** 2 for a in amounts) / len(amounts)
        std_dev = variance ** 0.5
        
        # Low variance in amounts (similar sizes) with 3+ transactions
        return (std_dev / mean if mean > 0 else 0) < 0.1 and len(amounts) >= 3
    
    def _detect_rushing(self, history: List[dict]) -> bool:
        if len(history) < 3:
            return False
        
        recent = history[-5:]
        timestamps = sorted([h["timestamp"] for h in recent])
        
        # Check for rapid-fire transactions (within 5 minutes)
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] < 300000:  # 5 minutes
                return True
        return False
    
    def _detect_batching(self, history: List[dict]) -> bool:
        if len(history) < 5:
            return False
        
        timestamps = sorted([h["timestamp"] for h in history])
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        mean = sum(intervals) / len(intervals)
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Low coefficient of variation = regular intervals
        return (std_dev / mean if mean > 0 else 0) < 0.1
    
    def _calculate_risk_score(self, profile: BehavioralProfile) -> int:
        score = 0
        
        if profile.pattern == BehaviorPattern.SPLITTING.value:
            score += 40
        elif profile.pattern == BehaviorPattern.RUSHING.value:
            score += 30
        elif profile.pattern == BehaviorPattern.BATCHING.value:
            score += 20
        
        if profile.autoclaim_preference > 0.8:
            score += 15
        
        if profile.transaction_count < 5 and profile.average_amount > 100000000:
            score += 25
        
        return min(100, score)


class MempoolBehavioralAnalyzer:
    """
    Main behavioral analyzer for TSN mempool.
    Tracks and analyzes wallet behavior patterns over time.
    """
    
    def __init__(self):
        self.db = BehavioralDatabase()
    
    def analyze_recipient(self, wallet_hash: str) -> BehavioralProfile:
        """Get behavioral profile for a wallet"""
        return self.db.get_profile(wallet_hash)
    
    def record_intent(self, wallet_hash: str, amount: int, autoclaim: bool = False):
        """Record a new intent for behavioral tracking"""
        self.db.update_profile(wallet_hash, amount, autoclaim)
    
    def detect_suspicious_intent(self, params: dict) -> dict:
        """
        Detect if a new intent matches suspicious patterns.
        
        Returns:
            Dict with suspicious (bool), pattern (str), reasons (list)
        """
        wallet_hash = params.get("wallet_hash", "")
        amount = params.get("amount", 0)
        
        profile = self.analyze_recipient(wallet_hash)
        reasons = []
        
        # New wallet with high amount
        if profile.transaction_count < 5 and amount > 100000000:
            reasons.append("High amount from new wallet")
        
        # Pattern-based reasons
        if profile.pattern == BehaviorPattern.SPLITTING.value:
            reasons.append("Splitting pattern history")
        elif profile.pattern == BehaviorPattern.RUSHING.value:
            reasons.append("Rushing pattern history")
        elif profile.pattern == BehaviorPattern.BATCHING.value:
            reasons.append("Batching pattern (possible bot)")
        
        # Amount anomaly
        if profile.transaction_count > 5 and amount > profile.average_amount * 10:
            reasons.append(f"Amount is 10x above average")
        
        # High risk score
        if profile.risk_score > 50:
            reasons.append(f"High risk score: {profile.risk_score}")
        
        return {
            "suspicious": len(reasons) > 0,
            "pattern": profile.pattern if reasons else None,
            "reasons": reasons
        }


def create_behavioral_analyzer() -> MempoolBehavioralAnalyzer:
    """Factory function to create a behavioral analyzer"""
    return MempoolBehavioralAnalyzer()