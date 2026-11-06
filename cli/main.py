from core.scanner import Scanner


def print_execution(execution_results):

    print()
    print("=" * 60)
    print("ANALYZER EXECUTION")
    print("=" * 60)

    for execution in execution_results:

        print()
        print(f"[{execution.status}] {execution.name}")

        print(
            f"    Checks   : {execution.checks}"
        )

        print(
            f"    Findings : {execution.findings}"
        )

        if execution.message:
            print(
                f"    Message  : {execution.message}"
            )

        if execution.errors:

            for error in execution.errors:

                print(
                    f"    Error    : {error}"
                )


def print_findings(findings):

    print()
    print("=" * 60)
    print("SECURITY FINDINGS")
    print("=" * 60)

    if not findings:

        print()
        print("No findings detected.")
        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print()
        print(f"[{index}] {finding.vulnerability}")

        print(
            f"    Severity     : {finding.severity}"
        )

        print(
            f"    Confidence   : "
            f"{finding.confidence * 100:.0f}%"
        )

        print(
            f"    Analyzer     : "
            f"{finding.analyzer}"
        )

        print(
            f"    Check        : "
            f"{finding.check}"
        )

        print(
            f"    Description  : "
            f"{finding.description}"
        )

        print(
            f"    Mechanism    : "
            f"{finding.mechanism}"
        )

        print(
            f"    Evidence     : "
            f"{finding.evidence}"
        )

        print(
            f"    Recommendation: "
            f"{finding.recommendation}"
        )


def main():

    print("=" * 60)
    print("A Modern Framework for Web Application")
    print("Vulnerability Scanning")
    print("=" * 60)

    target_url = input(
        "\nEnter target URL: "
    ).strip()

    scanner = Scanner(target_url)

    result = scanner.scan()

    if not result:
        print("No findings detected.")
        return

    print_execution(
        result["execution"]
    )

    print_findings(
        result["findings"]
    )


if __name__ == "__main__":
    main()

# from core.scanner import ScannerVulnerability
# from core.reporter import Reporter

# def main():
#     print("==========================================================")
#     print("   VulnScanner Academic Edition - Web Security Audit Tool")
#     print("==========================================================\n")
    
#     target_url = input("[+] Enter target URL (e.g., https://example.com): ").strip()
#     if not target_url:
#         print("[!] Target URL cannot be empty.")
#         return

#     scanner = ScannerVulnerability(target_url, max_pages=20)

#     print("\n[*] Verifying target liveness and HTTP connectivity...")
#     if not scanner.check_liveness():
#         print(f"[!] Target URL '{target_url}' is offline or unreachable.")
#         return
#     print("[+] Target is LIVE and reachable.\n")

#     print("==========================================================")
#     print(" Select Scan Module:")
#     print("  1.  Security Headers & Clickjacking Check")
#     print("  2.  Technology Stack Fingerprinting")
#     print("  3.  WordPress Detection & File Enumeration")
#     print("  4.  Sensitive Backup File & Directory Inspection")
#     print("  5.  robots.txt & sitemap.xml Exposure Check")
#     print("  6.  Reflected XSS Inspection (Crawl & Parameters)")
#     print("  7.  Error-Based SQL Injection Inspection (Crawl & Parameters)")
#     print("  8.  Run Full Comprehensive Security Audit (All Modules)")
#     print("==========================================================")

#     choice = input("\n[+] Select Option [1-8]: ").strip()

#     run_passive = False
#     run_active_safe = False
#     run_parameter_checks = False

#     # Standard passive/safe modules enabled based on selection
#     if choice == "1":
#         print("\n[*] Running: Security Headers & Clickjacking Check...")
#         run_passive = True
#     elif choice == "2":
#         print("\n[*] Running: Technology Stack Fingerprinting...")
#         run_passive = True
#     elif choice == "3":
#         print("\n[*] Running: WordPress Detection & Enumeration...")
#         run_passive = True
#     elif choice == "4":
#         print("\n[*] Running: Sensitive Backup File Inspection...")
#         run_active_safe = True
#     elif choice == "5":
#         print("\n[*] Running: robots.txt & sitemap.xml Check...")
#         run_active_safe = True
#     elif choice == "6" or choice == "7":
#         print("\n[*] Running: Parameter-based Vulnerability Inspection...")
#         run_parameter_checks = True
#     elif choice == "8":
#         print("\n[*] Running: Full Comprehensive Audit...")
#         run_passive = True
#         run_active_safe = True
#         run_parameter_checks = True
#     else:
#         print("[!] Defaulting to Full Audit (Option 8)")
#         run_passive = True
#         run_active_safe = True
#         run_parameter_checks = True

#     results = scanner.scan(
#         run_passive=run_passive,
#         run_active_safe=run_active_safe,
#         run_parameter_checks=run_parameter_checks
#     )

#     if not results:
#         print("\n[+] Audit completed: No vulnerabilities or exposures detected.")
#         return

#     print("\n----------------------------------------------------------")
#     print("                    FINDINGS SUMMARY                      ")
#     print("----------------------------------------------------------")
#     Reporter.to_console(results)
#     out = Reporter.to_json(results, "scan_report.json")
#     print(f"\n[+] Detailed report exported to: {out}")

# if __name__ == "__main__":
#     main()

