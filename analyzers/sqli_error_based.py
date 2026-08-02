from core.result import ScanResult
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "syntax error",
    "odbc",
    "sqlstate",
    "sqlite error",
    "psql:",
    "fatal error"
]

SAFE_TEST_VALUE = "'"

def analyze_url_sqli(target_url, client):
    results = []

    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)

    if not qs:
        return results

    for key in list(qs.keys()):
        mutated = dict(qs)
        mutated[key] = [SAFE_TEST_VALUE]

        new_query = urlencode(mutated, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        r = client.get(new_url)
        if not r:
            continue

        body = r.text.lower()

        if any(err in body for err in SQL_ERRORS):
            results.append(
                ScanResult(
                    target_url=new_url,
                    vulnerability="Possible SQL Injection (Error-Based)",
                    severity="High",
                    confidence=0.75,
                    description=f"SQL error patterns detected when testing parameter '{key}'.",
                    recommendation="Use parameterized queries and proper input validation.",
                    evidence="SQL error signature found in response body."
                )
            )

    return results