from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    target_url: str

    vulnerability: str
    description: str

    severity: str
    confidence: float

    recommendation: str

    evidence: Optional[str] = None
    mechanism: Optional[str] = None

    analyzer: Optional[str] = None
    check: Optional[str] = None
# from dataclasses import dataclass
# from typing import Optional, Dict, Any

# @dataclass
# class ScanResult:
#     target_url: str
#     vulnerability: str
#     severity: str              # Low/Medium/High/Critical
#     confidence: float          # 0.0 to 1.0
#     description: str
#     recommendation: str
#     evidence: Optional[str] = None
#     extra: Optional[Dict[str, Any]] = None