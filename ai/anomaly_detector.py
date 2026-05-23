"""
Anomaly Detection Module for TSN Mempool

Detects statistical anomalies in mempool operations
using time-series analysis and pattern recognition.
"""

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class Anomaly:
    type: str  # "velocity_spike" | "amount_outlier" | "timing_pattern" | etc.
    detected: bool
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float
    description: str
    metrics: dict


class StatsUtils:
    """Statistical utilities for anomaly detection"""
    
    @staticmethod
    def mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)
    
    @staticmethod
    def std_dev(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = StatsUtils.mean(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
    
    @staticmethod
    def z_score(value: float, values: List[float]) -> float:
        mean = StatsUtils.mean(values)
        std = StatsUtils.std_dev(values)
        if std == 0:
            return 0.0
        return (value - mean) / std


class TimeSeriesStore:
    """Time-series data structure for pattern analysis"""
    
    def __init__(self, window_size: int = 1000):
        self.values: List[float] = []
        self.timestamps: List[int] = []
        self.max_window = window_size
    
    def add(self, value: float, timestamp: Optional[int] = None):
        if timestamp is None:
            timestamp = int(__import__('time').time() * 1000)
        
        self.values.append(value)
        self.timestamps.append(timestamp)
        
        if len(self.values) > self.max_window:
            self.values.pop(0)
            self.timestamps.pop(0)
    
    def get_window(self, window_ms: int) -> List[float]:
        cutoff = int(__import__('time').time() * 1000) - window_ms
        return [v for i, v in enumerate(self.values) if self.timestamps[i] > cutoff]
    
    def detect_anomaly(self, current_value: float, z_threshold: float = 3.0) -> Tuple[bool, float]:
        if len(self.values) < 2:
            return False, 0.0
        z = StatsUtils.z_score(current_value, self.values)
        return abs(z) > z_threshold, z
    
    def get_stats(self) -> dict:
        return {
            "mean": StatsUtils.mean(self.values),
            "std_dev": StatsUtils.std_dev(self.values),
            "min": min(self.values) if self.values else 0,
            "max": max(self.values) if self.values else 0,
            "count": len(self.values)
        }


class MempoolAnomalyDetector:
    """
    Main anomaly detector for TSN mempool.
    Uses statistical analysis to identify unusual patterns.
    """
    
    def __init__(self, 
                 velocity_z_threshold: float = 3.0,
                 amount_z_threshold: float = 3.0,
                 timing_z_threshold: float = 2.5):
        self.velocity_z_threshold = velocity_z_threshold
        self.amount_z_threshold = amount_z_threshold
        self.timing_z_threshold = timing_z_threshold
        
        self.intent_velocity = TimeSeriesStore()
        self.claim_velocity = TimeSeriesStore()
        self.amounts = TimeSeriesStore()
        self.cranker_response_times = TimeSeriesStore()
        self.intent_timestamps: List[int] = []
    
    def detect_velocity_anomaly(self, recipient_hash: str, current_count: int) -> Anomaly:
        """Detect velocity anomalies (too many intents from same source)"""
        result = self.intent_velocity.detect_anomaly(
            float(current_count), 
            self.velocity_z_threshold
        )
        stats = self.intent_velocity.get_stats()
        
        return Anomaly(
            type="velocity_spike",
            detected=result[0],
            severity=self._severity_from_z(abs(result[1])),
            confidence=min(1.0, abs(result[1]) / 5),
            description=f"Velocity spike: {current_count} (expected ~{stats['mean']:.1f})" if result[0] else "No velocity anomaly",
            metrics={"current": current_count, "mean": stats["mean"], "z_score": result[1]}
        )
    
    def detect_amount_anomaly(self, amount: int) -> Anomaly:
        """Detect amount outliers (unusual transaction sizes)"""
        result = self.amounts.detect_anomaly(float(amount), self.amount_z_threshold)
        stats = self.amounts.get_stats()
        
        return Anomaly(
            type="amount_outlier",
            detected=result[0],
            severity=self._severity_from_z(abs(result[1])),
            confidence=min(1.0, abs(result[1]) / 5),
            description=f"Amount outlier: {amount} (expected ~{stats['mean']:.0f})" if result[0] else "No amount anomaly",
            metrics={"current": amount, "mean": stats["mean"], "z_score": result[1]}
        )
    
    def detect_timing_anomaly(self, intents: List[dict] = None) -> Anomaly:
        """Detect timing pattern anomalies (bot-like regularity)"""
        recent = self.intent_timestamps[-20:] if self.intent_timestamps else []
        
        if len(recent) < 10:
            return Anomaly(
                type="timing_pattern",
                detected=False,
                severity="low",
                confidence=0.0,
                description="Insufficient data for timing analysis",
                metrics={}
            )
        
        sorted_ts = sorted(recent)
        intervals = [sorted_ts[i] - sorted_ts[i-1] for i in range(1, len(sorted_ts))]
        
        mean_interval = StatsUtils.mean(intervals)
        std_dev = StatsUtils.std_dev(intervals)
        cv = mean_interval / std_dev if mean_interval > 0 else 0
        
        is_periodic = cv < 0.1 and len(intervals) >= 5
        
        return Anomaly(
            type="timing_pattern",
            detected=is_periodic,
            severity="high" if is_periodic else "low",
            confidence=0.8 if is_periodic else 0.0,
            description="Regular timing pattern - possible bot" if is_periodic else "Normal timing",
            metrics={"cv": cv, "mean": mean_interval, "std_dev": std_dev, "samples": len(intervals)}
        )
    
    def detect_state_transition_anomaly(self, from_status: str, to_status: str) -> Anomaly:
        """Detect invalid state transitions"""
        allowed_transitions = {
            "pending": ["claimed", "expired", "canceled"],
            "claimed": ["executed", "failed", "reverted"],
            "executed": ["settled"],
            "settled": [],
            "expired": [],
            "canceled": [],
            "failed": ["pending"],
            "reverted": []
        }
        
        allowed = allowed_transitions.get(from_status, [])
        is_allowed = to_status in allowed
        
        return Anomaly(
            type="state_transition",
            detected=not is_allowed,
            severity="critical" if not is_allowed else "low",
            confidence=0.95,
            description=f"Invalid: {from_status} → {to_status}" if not is_allowed else f"Valid: {from_status} → {to_status}",
            metrics={"from_status": from_status, "to_status": to_status}
        )
    
    def record_intent(self, amount: int):
        """Record intent for time-series analysis"""
        count = len(self.intent_timestamps) + 1
        self.intent_velocity.add(float(count))
        self.amounts.add(float(amount))
        self.intent_timestamps.append(int(__import__('time').time() * 1000))
        
        if len(self.intent_timestamps) > 1000:
            self.intent_timestamps.pop(0)
    
    def record_claim(self):
        """Record claim request"""
        count = len([t for t in self.claim_velocity.values]) + 1
        self.claim_velocity.add(float(count))
    
    def record_crunker_response(self, response_time_ms: int):
        """Record cranker response time"""
        self.cranker_response_times.add(float(response_time_ms))
    
    def _severity_from_z(self, z: float) -> str:
        if z >= 5:
            return "critical"
        if z >= 4:
            return "high"
        if z >= 3:
            return "medium"
        return "low"


def create_anomaly_detector() -> MempoolAnomalyDetector:
    """Factory function to create an anomaly detector"""
    return MempoolAnomalyDetector()