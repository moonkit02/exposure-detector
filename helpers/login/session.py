"""Browser start and interactive login.

start_chrome opens a real Chrome at the target so the user can log in by hand.
wait_for_login blocks until the user signals they are done.
"""
from playwright.sync_api import sync_playwright

def start_chrome(url, headless=False):
    # Launch real Chrome and open the target. Returns the handles the caller
    # needs; the caller instruments the context AFTER login and closes it.
    pw = sync_playwright().start()
    browser = pw.chromium.launch(channel="chrome", headless=headless)
    ctx = browser.new_context()
    page = ctx.new_page()
    page.goto(url, wait_until="domcontentloaded")
    return pw, browser, ctx, page

def wait_for_login(prompt="Type y + Enter to start detection: "):
    # Block until the user confirms login. EOFError (piped / no tty) just proceeds.
    print("\nLog in the Chrome window. When you are done, come back here.")
    try:
        input(prompt)
    except EOFError:
        pass
