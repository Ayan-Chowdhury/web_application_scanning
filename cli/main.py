from core.scanner import ScannerVulnerability
from core.reporter import Reporter

def main():
    print("========================================")
    print("   VulnScanner Academic Edition CLI")
    print("========================================\n")
    
    target_url = input("Enter target URL (e.g. https://example.com): ").strip()
    if not target_url:
        print("[!] Target URL cannot be empty.")
        return

    scanner = ScannerVulnerability(target_url, max_pages=20)

    print("\n[*] Checking target liveness...")
    if not scanner.check_liveness():
        print(f"[!] Target URL '{target_url}' is not reachable or returned a server error.")
        return
    print("[+] Target is LIVE and reachable.\n")

    print("Select scan options:")
    print(" 1. Standard Scan (Passive Headers + Safe Path Analysis)")
    print(" 2. Full Crawl & Parameter Check (Includes Passive + Deep Parameter Inspection)")
    print(" 3. Passive Only (Header & Technology Analysis)")

    choice = input("\nEnter choice [1-3] (default 1): ").strip()

    run_passive = True
    run_active_safe = True
    run_parameter_checks = False

    if choice == "2":
        run_parameter_checks = True
    elif choice == "3":
        run_active_safe = False

    print("\n[*] Starting scan execution...")
    results = scanner.scan(
        run_passive=run_passive,
        run_active_safe=run_active_safe,
        run_parameter_checks=run_parameter_checks
    )

    if not results:
        print("\n[+] Scan completed: No findings detected.")
        return

    Reporter.to_console(results)
    out = Reporter.to_json(results, "scan_report.json")
    print(f"\n[+] Saved detailed report to: {out}")

if __name__ == "__main__":
    main()