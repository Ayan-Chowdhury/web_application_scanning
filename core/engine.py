from core.execution import AnalyzerExecution


class ScanEngine:

    def __init__(self):
        self.modules = []
        self.execution_results = []

    def register(self, module):
        self.modules.append(module)

    def run(self, response):

        findings = []
        self.execution_results = []

        for module in self.modules:

            analyzer_name = getattr(
                module,
                "name",
                module.__class__.__name__
            )

            execution = AnalyzerExecution(
                name=analyzer_name,
                status="RUNNING"
            )

            self.execution_results.append(execution)

            try:

                results = module.analyze(response)

                if results is None:
                    results = []

                findings.extend(results)

                execution.status = "COMPLETED"
                execution.findings = len(results)

                execution.checks = getattr(
                    module,
                    "checks_performed",
                    0
                )

                execution.message = (
                    f"{len(results)} finding(s) detected."
                )

            except Exception as error:

                execution.status = "FAILED"

                execution.errors.append(
                    str(error)
                )

                execution.message = (
                    "Analyzer failed during execution."
                )

        return findings

    def get_execution_results(self):
        return self.execution_results