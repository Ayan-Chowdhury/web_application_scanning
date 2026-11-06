from dataclasses import dataclass, field
from typing import List


@dataclass
class AnalyzerExecution:
    name: str

    status: str = "PENDING"

    checks: int = 0
    findings: int = 0

    message: str = ""

    errors: List[str] = field(default_factory=list)