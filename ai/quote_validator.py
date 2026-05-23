"""
Quote Validation Module for TSN Mempool

Prevents quote manipulation and fee spoofing attacks.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class QuoteManipulationType(str, Enum):
    SPOOFING = "spoofing"
    STALE_QUOTE = "stale_quote"
    AMOUNT_MISMATCH = "amount_mismatch"
    FEE_INFLATION = "fee_inflation"


@dataclass
class QuoteValidationResult:
    valid: bool
    issues: List[str]
    manipulation_type: Optional[str]
    risk_level: str  # "low" | "medium" | "high" | "critical"


@dataclass
class FeeQuote:
    sender_fee: int
    claim_fee: int
    network_fee_estimate: int
    total_fee: int
    timestamp: int
    expires_at: int
    token_mint: str


@dataclass
class QuoteRequest:
    amount: int
    token_mint: str
    recipient_hash: str


class QuoteHistory:
    """Quote history for manipulation detection"""
    
    def __init__(self, max_history: int = 100):
        self.quotes: Dict[str, List[FeeQuote]] = {}
        self.max_history = max_history
    
    def add_quote(self, key: str, quote: FeeQuote):
        if key not in self.quotes:
            self.quotes[key] = []
        
        self.quotes[key].append(quote)
        
        if len(self.quotes[key]) > self.max_history:
            self.quotes[key].pop(0)
    
    def get_recent(self, key: str, window_ms: int) -> List[FeeQuote]:
        cutoff = int(__import__('time').time() * 1000) - window_ms
        return [q for q in self.quotes.get(key, []) if q.timestamp > cutoff]
    
    def get_average_fee(self, key: str, window_ms: int) -> float:
        recent = self.get_recent(key, window_ms)
        if not recent:
            return 0.0
        return sum(q.total_fee for q in recent) / len(recent)


class MempoolQuoteValidator:
    """
    Main quote validator for TSN mempool.
    Prevents quote manipulation and fee spoofing.
    """
    
    def __init__(self):
        self.history = QuoteHistory()
    
    def validate_quote(self, quote: dict, request: dict) -> QuoteValidationResult:
        """
        Validate a fee quote against expected parameters.
        
        Args:
            quote: Dict with sender_fee, claim_fee, network_fee_estimate, 
                   total_fee, timestamp, expires_at, token_mint
            request: Dict with amount, token_mint, recipient_hash
        """
        issues = []
        now = int(__import__('time').time() * 1000)
        
        # Check for stale quote
        if quote.get("timestamp", now) > now + 5000:
            issues.append("Quote timestamp is in the future")
        
        if now > quote.get("expires_at", now):
            issues.append("Quote has expired")
        
        if now - quote.get("timestamp", now) > 300000:  # 5 minutes
            issues.append("Quote is older than 5 minutes")
        
        # Check amount mismatch
        expected_total = (
            quote.get("sender_fee", 0) + 
            quote.get("claim_fee", 0) + 
            quote.get("network_fee_estimate", 0)
        )
        total_fee = quote.get("total_fee", 0)
        
        if abs(total_fee - expected_total) > 1:
            issues.append("Total fee doesn't match sum of components")
        
        # Check for fee inflation
        key = f"{quote.get('token_mint', '')}:{request.get('recipient_hash', '')}"
        avg_fee = self.history.get_average_fee(key, 3600000)  # 1 hour
        
        if avg_fee > 0 and total_fee > avg_fee * 1.5:
            issues.append(f"Fee {total_fee} is 50%+ higher than historical average {avg_fee:.2f}")
        
        # Check sender fee reasonableness
        amount = request.get("amount", 1)
        sender_fee = quote.get("sender_fee", 0)
        sender_fee_bps = (sender_fee / amount) * 10000 if amount > 0 else 0
        
        if sender_fee_bps > 100:  # More than 1%
            issues.append(f"Sender fee {sender_fee_bps:.2f} bps is unusually high")
        
        # Determine manipulation type
        manipulation_type = None
        if any("expired" in i.lower() or "older than 5 minutes" in i.lower() for i in issues):
            manipulation_type = QuoteManipulationType.STALE_QUOTE.value
        elif any("50%+" in i for i in issues):
            manipulation_type = QuoteManipulationType.FEE_INFLATION.value
        elif any("doesn't match" in i for i in issues):
            manipulation_type = QuoteManipulationType.SPOOFING.value
        
        risk_level = self._calculate_risk_level(issues)
        
        return QuoteValidationResult(
            valid=len(issues) == 0,
            issues=issues,
            manipulation_type=manipulation_type,
            risk_level=risk_level
        )
    
    def record_quote(self, quote: dict, recipient_hash: str):
        """Record a quote for historical analysis"""
        key = f"{quote.get('token_mint', '')}:{recipient_hash}"
        self.history.add_quote(key, FeeQuote(
            sender_fee=quote.get("sender_fee", 0),
            claim_fee=quote.get("claim_fee", 0),
            network_fee_estimate=quote.get("network_fee_estimate", 0),
            total_fee=quote.get("total_fee", 0),
            timestamp=quote.get("timestamp", int(__import__('time').time() * 1000)),
            expires_at=quote.get("expires_at", 0),
            token_mint=quote.get("token_mint", "")
        ))
    
    def detect_spoofing_pattern(self, recipient_hash: str, window_ms: int = 600000) -> bool:
        """Detect quote spoofing pattern"""
        key = f"*:{recipient_hash}"
        quotes = self.history.get_recent(key, window_ms)
        
        if len(quotes) < 5:
            return False
        
        fees = [q.total_fee for q in quotes]
        mean = sum(fees) / len(fees)
        variance = sum((f - mean) ** 2 for f in fees) / len(fees)
        std_dev = variance ** 0.5
        
        # High variance in quotes might indicate spoofing
        return (std_dev / mean if mean > 0 else 0) > 0.5
    
    def _calculate_risk_level(self, issues: List[str]) -> str:
        if any("50%+" in i for i in issues):
            return "high"
        if any("unusually high" in i for i in issues):
            return "medium"
        if issues:
            return "medium"
        return "low"


def create_quote_validator() -> MempoolQuoteValidator:
    """Factory function to create a quote validator"""
    return MempoolQuoteValidator()