"""画面（html/index.html）をブラウザで通しで動かす（C++ 版 / Python 版どちらにも使える）

Chromium の仮想認証器（DevTools Protocol の WebAuthn ドメイン）を使うので、
本物の指紋や顔は要らない。起動済みのサーバに対して:

    python tests/browser_e2e.py http://localhost:8099 [スクリーンショットの保存先]

rpId に IP アドレスは使えないので、127.0.0.1 ではなく localhost で開くこと。
Playwright（pip install playwright && playwright install chromium）が要る。
"""
import os
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
from _bootstrap import Checker

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8099"
SHOT = sys.argv[2] if len(sys.argv) > 2 else ""
USER = "e2e_%d" % int(time.time())

ck = Checker()


def add_authenticator(page):
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    r = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal",
        "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True,
    }})
    return cdp, r["authenticatorId"]


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    cdp, auth_id = add_authenticator(page)
    page.goto(BASE + "/")
    ck(page.url.endswith("/html/index.html"), "/ redirects to /html/index.html")

    print("--- sign up ---")
    page.fill("#user", USER)
    page.click("#btnSignup")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(USER in page.inner_text("#who"), "logged in as " + USER)
    ck(page.locator("#keys .key").count() == 1, "one passkey listed")
    ck("ES256" in page.inner_text("#keys"), "algorithm shown as ES256")
    creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"]
    ck(len(creds) == 1 and creds[0]["isResidentCredential"], "authenticator holds 1 discoverable credential")

    print("\n--- switch ---")
    before = "ついています" in page.inner_text("#state")
    page.click("#toggle")
    page.wait_for_function("(b) => document.getElementById('state').textContent.includes(b ? '消えて' : 'ついて')",
                           arg=before, timeout=5000)
    ck(USER in page.inner_text("#lastBy"), "switch toggled, last changed by " + USER)
    after = "ついています" in page.inner_text("#state")

    other = browser.new_page()          # ログインしていない別の人
    other.goto(BASE + "/html/index.html")
    other.wait_for_function("(a) => document.getElementById('state').textContent.includes(a ? 'ついて' : '消えて')",
                            arg=after, timeout=5000)
    ck(True, "another browser sees the same state")
    ck(other.locator("#toggle").is_disabled(), "toggle is disabled when logged out")

    print("\n--- logout / login without a name ---")
    page.click("#btnLogout")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    ck(page.locator("#toggle").is_disabled(), "toggle disabled after logout")
    page.fill("#user", "")
    page.click("#btnLogin")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(USER in page.inner_text("#who"), "discoverable login (no user name) works")
    page.click("#toggle")
    other.wait_for_function("(a) => document.getElementById('state').textContent.includes(a ? '消えて' : 'ついて')",
                            arg=after, timeout=5000)
    ck(True, "toggled again, the other browser follows")
    ck("1" in page.inner_text("#keys"), "sign count / fields rendered")

    print("\n--- login with a name ---")
    page.click("#btnLogout")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    page.fill("#user", USER)
    page.click("#btnLogin")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(USER in page.inner_text("#who"), "login with the user name works")

    print("\n--- duplicate name ---")
    page2 = browser.new_page()
    add_authenticator(page2)
    page2.goto(BASE + "/html/index.html")
    page2.fill("#user", USER)
    page2.click("#btnSignup")
    page2.wait_for_function("document.getElementById('msgOut').textContent.includes('user already exists')",
                            timeout=5000)
    ck(True, "signing up with a taken name is refused")

    if SHOT:
        page.set_viewport_size({"width": 800, "height": 1200})
        page.screenshot(path=SHOT, full_page=True)
        print("screenshot:", SHOT)

    print("\n--- delete the last passkey ---")
    page.on("dialog", lambda d: d.accept())
    page.click("#keys .key button.danger")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    ck(True, "deleting the last passkey logs out")
    browser.close()

sys.exit(ck.finish())
