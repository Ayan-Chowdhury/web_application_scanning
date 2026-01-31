from dataclasses import dataclass
from typing import Optional

@dataclass
class ScanResult:
    target_url: str
    description: str
    vulnerability: str
    severity: str
    confidence: float
    recommendation: str
    evidence: Optional[str]=None
