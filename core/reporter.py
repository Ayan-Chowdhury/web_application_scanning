import json
from dataclasses import asdict
from core.risk import risk_calculation

class Reporter:
    @staticmethod
    def to_console(results):
        for r in results:
            print(f"[{r.severity}] {r.target_url}")
            print(f"  - {r.vulnerability}")
            print(f"  - {r.description}")
            print(f"  - Confidence: {r.confidence}")
            if r.evidence:
                print(f"  - Evidence: {r.evidence}")
            print(f"  - Recommendation: {r.recommendation}")
            print("-" * 70)

        print(f"Total Risk Score: {risk_calculation(results)}/100")

    @staticmethod
    def to_json(results, output_file="scan_report.json"):
        data = {
            "risk_score": risk_calculation(results),
            "total_findings": len(results),
            "results": [asdict(r) for r in results]
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return output_file