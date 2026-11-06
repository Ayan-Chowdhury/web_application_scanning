from abc import ABC, abstractmethod
from typing import Any


class BaseAnalyzer(ABC):

    name = "Base Analyzer"
    category = "General"

    @abstractmethod
    def analyze(
        self,
        target_url: str,
        response: Any,
        client: Any = None
    ) -> list:

        """
        Analyze the target and return a list of ScanResult objects.
        """

        raise NotImplementedError