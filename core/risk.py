SEVERITY = {

    "Info":0,

    "Low":2,

    "Medium":5,

    "High":8,

    "Critical":10

}


class RiskCalculator:

    @staticmethod
    def calculate(results):

        total = 0

        for r in results:

            total += SEVERITY.get(r.severity,0)

        if total>100:

            total=100

        return total
# SEVERITY_SCORE = {
#     "Info": 0,
#     "Low": 2,
#     "Medium": 5,
#     "High": 8,
#     "Critical": 10
# }

# def risk_calculation(results):
#     total = sum(SEVERITY_SCORE.get(r.severity, 0) for r in results)
#     return min(total, 100)