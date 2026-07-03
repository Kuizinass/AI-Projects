from dataclasses import dataclass
from enum import Enum
from src.config.settings import settings


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskScore:
    score: int          # 0–100
    level: RiskLevel
    reasoning: str
    factors: dict[str, int]  # factor_name → contribution score


def classify(score: int) -> RiskLevel:
    if score <= settings.low_risk_max:
        return RiskLevel.LOW
    if score <= settings.medium_risk_max:
        return RiskLevel.MEDIUM
    if score <= settings.high_risk_max:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


RISK_FACTOR_WEIGHTS = {
    "affected_users":     20,   # proportion of affected users/devices
    "reversibility":      25,   # 0 = fully reversible, 25 = irreversible
    "service_impact":     20,   # potential downtime or disruption
    "data_sensitivity":   20,   # touches PII/PHI/financial data
    "change_frequency":   15,   # recently changed (high churn = higher risk)
}
