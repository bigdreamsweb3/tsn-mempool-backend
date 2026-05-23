"""
Cranker Jail Module for TSN Mempool

Detects and punishes malicious cranker behavior
through reputation-based enforcement.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class JailReason(str, Enum):
    FRAUDULENT_PROOFS = "fraudulent_proofs"
    PAYOUT_MANIPULATION = "payout_manipulation"
    FAILED_OBLIGATIONS = "failed_obligations"
    FRONT_RUNNING = "front_running"
    PROOF_WITHHOLDING = "proof_withholding"
    SYBIL_ATTACK = "sybil_attack"


class CrankerStatus(str, Enum):
    ACTIVE = "active"
    JAILED = "jailed"
    RELEASED = "released"
    BANNED = "banned"


@dataclass
class CrankerJailRecord:
    cranker_pubkey: str
    status: str
    jailed_at: int
    release_at: Optional[int]
    reason: str
    violations: int
    trust_score: float
    total_operations: int
    successful_operations: int


@dataclass
class JailConfig:
    trust_score_threshold: float = 0.3
    jail_duration_ms: int = 3600000  # 1 hour
    max_violations: int = 3
    grace_period_ms: int = 86400000  # 24 hours


class CrankerRegistry:
    """Tracks cranker behavior and reputation"""
    
    def __init__(self):
        self.crankers: Dict[str, CrankerJailRecord] = {}
    
    def get_or_create(self, cranker_pubkey: str) -> CrankerJailRecord:
        if cranker_pubkey not in self.crankers:
            self.crankers[cranker_pubkey] = CrankerJailRecord(
                cranker_pubkey=cranker_pubkey,
                status=CrankerStatus.ACTIVE.value,
                jailed_at=0,
                release_at=None,
                reason=JailReason.FRAUDULENT_PROOFS.value,
                violations=0,
                trust_score=1.0,
                total_operations=0,
                successful_operations=0
            )
        return self.crankers[cranker_pubkey]
    
    def update(self, cranker_pubkey: str, update: dict):
        record = self.get_or_create(cranker_pubkey)
        for key, value in update.items():
            setattr(record, key, value)
    
    def get_all(self) -> List[CrankerJailRecord]:
        return list(self.crankers.values())
    
    def get_active(self) -> List[CrankerJailRecord]:
        return [c for c in self.crankers.values() if c.status == CrankerStatus.ACTIVE.value]
    
    def prune(self, max_age_ms: int = 604800000):
        """Remove old records (7 days)"""
        cutoff = int(__import__('time').time() * 1000) - max_age_ms
        to_remove = []
        
        for key, record in self.crankers.items():
            if record.status == CrankerStatus.BANNED.value:
                continue
            if record.status == CrankerStatus.RELEASED.value:
                if record.release_at and record.release_at < cutoff:
                    to_remove.append(key)
        
        for key in to_remove:
            del self.crankers[key]


class MempoolCrankerJail:
    """
    Main cranker jail system for TSN mempool.
    Provides reputation-based enforcement.
    """
    
    def __init__(self, config: Optional[JailConfig] = None):
        self.config = config or JailConfig()
        self.registry = CrankerRegistry()
    
    def can_operate(self, cranker_pubkey: str) -> dict:
        """
        Check if a cranker is allowed to operate.
        
        Returns:
            Dict with allowed (bool) and reason (str)
        """
        record = self.registry.get_or_create(cranker_pubkey)
        now = int(__import__('time').time() * 1000)
        
        if record.status == CrankerStatus.BANNED.value:
            return {"allowed": False, "reason": "Cranker is permanently banned"}
        
        if record.status == CrankerStatus.JAILED.value:
            if record.release_at and now >= record.release_at:
                self.release(cranker_pubkey)
                return {"allowed": True}
            
            remaining_ms = (record.release_at or now) - now
            return {
                "allowed": False, 
                "reason": f"Jailed for {max(0, remaining_ms // 60000)} more minutes"
            }
        
        if record.trust_score < self.config.trust_score_threshold:
            return {"allowed": False, "reason": "Trust score too low"}
        
        return {"allowed": True}
    
    def record_success(self, cranker_pubkey: str):
        """Record a successful cranker operation"""
        record = self.registry.get_or_create(cranker_pubkey)
        record.total_operations += 1
        record.successful_operations += 1
        
        # Update trust score
        if record.total_operations > 0:
            record.trust_score = record.successful_operations / record.total_operations
        
        self.registry.update(cranker_pubkey, {
            "total_operations": record.total_operations,
            "successful_operations": record.successful_operations,
            "trust_score": record.trust_score
        })
    
    def record_failure(self, cranker_pubkey: str, reason: str):
        """Record a failed cranker operation"""
        record = self.registry.get_or_create(cranker_pubkey)
        record.total_operations += 1
        record.violations += 1
        
        # Calculate trust score impact
        base_trust_loss = 0.1
        severity_multiplier = self._get_severity_multiplier(reason)
        record.trust_score = max(0, record.trust_score - base_trust_loss * severity_multiplier)
        
        # Check if should be jailed
        if record.violations >= self.config.max_violations or record.trust_score < self.config.trust_score_threshold:
            self.jail(cranker_pubkey, reason)
        
        self.registry.update(cranker_pubkey, {
            "total_operations": record.total_operations,
            "violations": record.violations,
            "trust_score": record.trust_score
        })
    
    def jail(self, cranker_pubkey: str, reason: str):
        """Jail a cranker"""
        release_at = int(__import__('time').time() * 1000) + self.config.jail_duration_ms
        self.registry.update(cranker_pubkey, {
            "status": CrankerStatus.JAILED.value,
            "jailed_at": int(__import__('time').time() * 1000),
            "release_at": release_at,
            "reason": reason
        })
    
    def release(self, cranker_pubkey: str):
        """Release a cranker from jail"""
        self.registry.update(cranker_pubkey, {
            "status": CrankerStatus.RELEASED.value,
            "release_at": int(__import__('time').time() * 1000),
            "violations": 0
        })
    
    def ban(self, cranker_pubkey: str):
        """Permanently ban a cranker"""
        self.registry.update(cranker_pubkey, {"status": CrankerStatus.BANNED.value})
    
    def get_status(self, cranker_pubkey: str) -> CrankerJailRecord:
        """Get cranker status"""
        return self.registry.get_or_create(cranker_pubkey)
    
    def get_active_crackers(self) -> List[CrankerJailRecord]:
        """Get all active crankers"""
        return self.registry.get_active()
    
    def detect_front_running(self, operations: List[dict]) -> dict:
        """
        Detect front-running patterns.
        
        Args:
            operations: List of dicts with cranker_pubkey, intent_id, timestamp
        """
        # Group by cranker
        by_cranker: Dict[str, list] = {}
        for op in operations:
            cranker = op.get("cranker_pubkey", "")
            if cranker not in by_cranker:
                by_cranker[cranker] = []
            by_cranker[cranker].append(op)
        
        offenders = []
        for cranker, ops in by_cranker.items():
            # Check for rapid claiming followed by delayed execution
            if len(ops) > 5:
                timestamps = sorted([op.get("timestamp", 0) for op in ops])
                rapid_claims = sum(
                    1 for i in range(1, len(timestamps)) 
                    if timestamps[i] - timestamps[i-1] < 1000  # 1 second
                )
                
                if rapid_claims > len(ops) * 0.5:
                    offenders.append(cranker)
                    self.record_failure(cranker, JailReason.FRONT_RUNNING.value)
        
        return {"detected": len(offenders) > 0, "offenders": offenders}
    
    def _get_severity_multiplier(self, reason: str) -> float:
        severity_map = {
            JailReason.FRAUDULENT_PROOFS.value: 2.0,
            JailReason.PAYOUT_MANIPULATION.value: 1.5,
            JailReason.PROOF_WITHHOLDING.value: 1.5,
            JailReason.SYBIL_ATTACK.value: 2.0,
            JailReason.FRONT_RUNNING.value: 1.2,
            JailReason.FAILED_OBLIGATIONS.value: 1.0,
        }
        return severity_map.get(reason, 1.0)


def create_cranker_jail(config: Optional[JailConfig] = None) -> MempoolCrankerJail:
    """Factory function to create a cranker jail"""
    return MempoolCrankerJail(config)