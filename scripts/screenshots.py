"""Generate README screenshots with headless Chromium.

Produces docs/screenshots/{dashboard,report-summary,findings,ai-narrative}.png
from a generated HTML report and the Streamlit dashboard.

Prerequisites:
  pip install playwright && python -m playwright install chromium
  On Linux you may also need: python -m playwright install-deps chromium

Usage:
  python scripts/screenshots.py \
      --report-violation /tmp/demo-violation.html \
      --report-ai /tmp/demo-ai.html \
      --fixture test-data/violation-nsg.json
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "docs" / "screenshots"


def _section_locator(page, header_text: str):
    return page.locator(".section").filter(has_text=header_text).first


def _shot_report(browser, html_path: Path, header_text: str, out: Path) -> None:
    page = browser.new_page(viewport={"width": 1200, "height": 900})
    page.goto(html_path.as_uri())
    page.wait_for_load_state("networkidle")
    locator = _section_locator(page, header_text)
    locator.wait_for(state="visible")
    locator.screenshot(path=str(out))
    page.close()
    print(f"wrote {out} ({header_text})")


def _wait_for_dashboard(url: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"dashboard did not start at {url}")


def _shot_dashboard(browser, fixture: Path, out: Path) -> None:
    env = dict(os.environ)
    env["STREAMLIT_SERVER_HEADLESS"] = "true"
    env["STREAMLIT_SERVER_PORT"] = "8501"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(REPO_ROOT / "src/azguard/dashboard.py"),
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_for_dashboard("http://localhost:8501/_stcore/health")
        page = browser.new_page(viewport={"width": 1400, "height": 1000})
        page.set_default_timeout(60000)
        page.goto("http://localhost:8501", wait_until="domcontentloaded")
        page.wait_for_timeout(4000)

        uploader = page.locator('input[type="file"]').first
        uploader.wait_for(state="attached")
        uploader.set_input_files(str(fixture))
        page.wait_for_timeout(1500)

        run_btn = page.get_by_role("button", name="Run scan")
        run_btn.click()
        page.get_by_role("heading", name="Findings", level=3).wait_for(state="visible")
        page.wait_for_timeout(2500)
        page.screenshot(path=str(out), full_page=True)
        page.close()
        print(f"wrote {out} (dashboard)")
    finally:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-violation", type=Path, required=True)
    parser.add_argument("--report-ai", type=Path, required=True)
    parser.add_argument(
        "--fixture", type=Path, default=REPO_ROOT / "test-data/violation-nsg.json"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        _shot_report(
            browser,
            args.report_violation,
            "1. Executive Summary",
            args.out / "report-summary.png",
        )
        _shot_report(
            browser,
            args.report_violation,
            "3. Findings Detail",
            args.out / "findings.png",
        )
        _shot_report(
            browser,
            args.report_ai,
            "5. AI-Generated Narrative",
            args.out / "ai-narrative.png",
        )
        _shot_dashboard(browser, args.fixture, args.out / "dashboard.png")
        browser.close()


if __name__ == "__main__":
    main()
