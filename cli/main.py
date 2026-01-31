from core.scanner import Scanner_Vulnerability

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    scanner = Scanner_Vulnerability(target_url)
    findings = scanner.scan()

    if not findings:
        print("No vulnerabilities detected.")
    else:
        for f in findings:
            print(f"[{f.severity}] {f.target_url} - {f.vulnerability}: {f.description}")
