"""BatchedOracle: persistent-browser check_fires for eval throughput.

Keeps one Chromium browser open across all checks, creating a fresh page per
payload. Same semantics as browser_oracle.check_fires but ~3-5x faster because
it avoids re-launching the browser per call.
"""
from __future__ import annotations

from typing import Self

from playwright.sync_api import TimeoutError as PWTimeoutError
from playwright.sync_api import sync_playwright

from ..browser_oracle import FIRE_TIMEOUT_MS, render_page_html
from ..context import ContextSpec, simulate_reflection


class BatchedOracle:
    """Context manager that keeps a Playwright browser open for batch checking.

    Usage:
        with BatchedOracle() as oracle:
            for ctx, payload in pairs:
                fires = oracle.check_fires(ctx, payload)
    """

    def __init__(self):
        self._playwright = None
        self._browser = None

    def __enter__(self) -> Self:
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if payload fires alert() in a real browser under this context.

        Same logic as browser_oracle.check_fires but reuses the persistent browser.
        """
        reflected = simulate_reflection(ctx, payload)
        if not reflected:
            return False
        page_html = render_page_html(ctx, reflected)

        page = self._browser.new_page()
        fired = False

        def _on_dialog(_dialog) -> None:
            nonlocal fired
            fired = True
            _dialog.dismiss()

        page.on("dialog", _on_dialog)
        try:
            page.set_content(page_html, timeout=5000)
        except PWTimeoutError:
            pass  # hanging page; dialog may still have fired
        page.wait_for_timeout(FIRE_TIMEOUT_MS)
        page.close()
        return fired
