from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class ScanResult:
    target_url: str
    vulnerability: str
    severity: str              # Low/Medium/High/Critical
    confidence: float          # 0.0 to 1.0
    description: str
    recommendation: str
    evidence: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None