"""
scripts/capture_screenshots.py
==============================
Capture the dashboard evidence screenshots automatically with Playwright.

    python scripts/capture_screenshots.py

PREREQUISITES
-------------
    pip install playwright
    python -m playwright install chromium

    start_backend.bat   (http://127.0.0.1:8000)
    start_frontend.bat  (http://localhost:5173)

The script also fails loudly if a page logs a JavaScript error, so a broken
screenshot can never be mistaken for a working one.

Screenshots that CANNOT be automated (anything on github.com) are listed in
screenshots/README.md as MANUAL USER ACTION REQUIRED. This script never
fabricates them.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SHOTS = PROJECT_ROOT / "screenshots"

FRONTEND = "http://127.0.0.1:5173"
BACKEND = "http://127.0.0.1:8000"

# (filename, url, description, wait_selector, full_page, pre_actions)
PAGES = [
    ("04_dashboard_overview.png", f"{FRONTEND}/",
     "Dashboard - cards and charts", ".stat", True, None),
    ("05_dashboard_charts.png", f"{FRONTEND}/",
     "Dashboard - chart grid", ".recharts-wrapper", False, "scroll"),
    ("06_email_analyzer_form.png", f"{FRONTEND}/analyzer",
     "Email analyzer - input form", "#sender", False, None),
    ("07_phishing_result_high_risk.png", f"{FRONTEND}/analyzer",
     "Phishing demo scored HIGH RISK", ".score-big", True, "analyze_phishing"),
    ("08_legitimate_result_low_risk.png", f"{FRONTEND}/analyzer",
     "Legitimate demo scored LOW RISK", ".score-big", True, "analyze_legit"),
    ("09_explainable_findings.png", f"{FRONTEND}/analyzer",
     "Explainable findings - why each rule fired", ".why-list", True, "analyze_phishing"),
    ("10_url_analysis.png", f"{FRONTEND}/analyzer",
     "Standalone link checker", "#url", False, "check_url"),
    ("11_awareness_spot.png", f"{FRONTEND}/awareness",
     "Awareness - how to spot phishing", ".acc", True, None),
    ("12_awareness_checklist.png", f"{FRONTEND}/awareness",
     "Awareness - before-you-click checklist", "table", True, "tab_click"),
    ("13_awareness_mitre.png", f"{FRONTEND}/awareness",
     "Awareness - MITRE ATT&CK mapping", "table", True, "tab_mitre"),
    ("14_history_list.png", f"{FRONTEND}/history",
     "History - list with filters", "table", True, None),
    ("15_history_detail.png", f"{FRONTEND}/history",
     "History - full stored report", ".score-big", True, "open_first"),
    ("16_swagger_docs.png", f"{BACKEND}/docs",
     "FastAPI Swagger documentation", ".opblock", True, None),
    ("17_api_health.png", f"{BACKEND}/api/health",
     "Health endpoint JSON", "body", False, None),
]


def run(headed: bool = False) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[error] Playwright is not installed.")
        print("        pip install playwright")
        print("        python -m playwright install chromium")
        return 1

    SHOTS.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    written: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        context = browser.new_context(viewport={"width": 1600, "height": 1000},
                                      device_scale_factor=1)
        page = context.new_page()

        console_errors: list[str] = []
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)
        page.on("pageerror", lambda e: console_errors.append(str(e)))

        for filename, url, description, selector, full_page, action in PAGES:
            console_errors.clear()
            print(f"  {filename:<36} {description}")
            try:
                page.goto(url, wait_until="networkidle", timeout=30_000)

                if action == "analyze_phishing":
                    page.click("text=Load phishing demo")
                    page.click("button:has-text('Analyse email')")
                    page.wait_for_selector(".score-big", timeout=30_000)
                elif action == "analyze_legit":
                    page.click("text=Load legitimate demo")
                    page.click("button:has-text('Analyse email')")
                    page.wait_for_selector(".score-big", timeout=30_000)
                elif action == "check_url":
                    page.click("button:has-text('Check link')")
                    page.wait_for_selector(".pill-row", timeout=30_000)
                    page.locator("#url").scroll_into_view_if_needed()
                elif action == "tab_click":
                    page.click("text=Before you click")
                elif action == "tab_mitre":
                    page.click("text=MITRE ATT&CK")
                elif action == "open_first":
                    page.wait_for_selector("button:has-text('View')", timeout=30_000)
                    page.locator("button:has-text('View')").first.click()
                    page.wait_for_selector(".score-big", timeout=30_000)
                elif action == "scroll":
                    page.mouse.wheel(0, 500)

                page.wait_for_timeout(1400)
                page.screenshot(path=str(SHOTS / filename), full_page=full_page)
                written.append(filename)

                real = [e for e in console_errors
                        if "favicon" not in e.lower() and "404" not in e]
                if real:
                    errors.append(f"{filename}: {real[0][:160]}")
            except Exception as exc:                          # pragma: no cover
                errors.append(f"{filename}: {type(exc).__name__}: {exc}")
                print(f"      FAILED: {exc}")

        browser.close()

    print("-" * 74)
    print(f"  wrote {len(written)} screenshots to {SHOTS}")
    if errors:
        print(f"  {len(errors)} page(s) reported problems:")
        for e in errors:
            print(f"    - {e}")
        return 2
    print("  no JavaScript errors were logged on any page")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()
    raise SystemExit(run(args.headed))
