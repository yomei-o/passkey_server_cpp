"""画面（html/index.html）をブラウザで通しで動かす（C++ 版 / Python 版どちらにも使える）

Chromium の仮想認証器（DevTools Protocol の WebAuthn ドメイン）を使うので、
本物の指紋や顔は要らない。**DB が空の**サーバに対して（最初の 1 人が自動で承認されるのを見るため）:

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
T = int(time.time())
USER = "first_%d" % T
USER2 = "second_%d" % T
USER3 = "third_%d" % T

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


def wait_text(page, sel, text, timeout=8000):
    page.wait_for_function("([s, t]) => (document.querySelector(s) || {}).textContent.includes(t)",
                           arg=[sel, text], timeout=timeout)


def signup(page, user):
    page.fill("#user", user)
    page.click("#btnSignup")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)


with sync_playwright() as p:
    browser = p.chromium.launch()
    # 人ごとにブラウザのコンテキストを分ける（sessionStorage は別々）
    page = browser.new_context().new_page()
    cdp, auth_id = add_authenticator(page)
    page.goto(BASE + "/")
    ck(page.url.endswith("/html/index.html"), "/ redirects to /html/index.html")

    print("--- the first user ---")
    signup(page, USER)
    ck(USER in page.inner_text("#who") and "管理者" in page.inner_text("#who"),
       "the first user is logged in as an admin")
    ck(page.locator("#pendingCard").is_hidden(), "no pending notice")
    ck(page.locator("#membersCard").is_visible(), "members card is shown")
    ck(page.locator("#keys .key").count() == 1 and "ES256" in page.inner_text("#keys"),
       "one ES256 passkey listed")
    creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"]
    ck(len(creds) == 1 and creds[0]["isResidentCredential"], "authenticator holds 1 discoverable credential")

    print("\n--- switch ---")
    before = "ついています" in page.inner_text("#state")
    page.click("#toggle")
    wait_text(page, "#state", "消えて" if before else "ついて")
    ck(USER in page.inner_text("#lastBy"), "switch toggled, last changed by " + USER)
    after = "ついています" in page.inner_text("#state")

    viewer = browser.new_context().new_page()          # ログインしていない人
    viewer.goto(BASE + "/html/index.html")
    wait_text(viewer, "#state", "ついて" if after else "消えて")
    ck(True, "a logged-out browser sees the same state")
    ck(viewer.locator("#toggle").is_disabled(), "toggle is disabled when logged out")

    print("\n--- the second user: pending -> approved as a member ---")
    page2 = browser.new_context().new_page()
    add_authenticator(page2)
    page2.goto(BASE + "/html/index.html")
    signup(page2, USER2)
    ck("承認待ち" in page2.inner_text("#who"), "the second user is logged in but pending")
    ck(page2.locator("#pendingCard").is_visible(), "pending notice is shown")
    ck(page2.locator("#membersCard").is_hidden(), "pending user cannot see members")
    ck(page2.locator("#toggle").is_disabled(), "pending user cannot toggle")

    wait_text(page, "#members", USER2)                   # 1 人目の画面に 4 秒ごとの確認で出てくる
    ck("承認待ち" in page.inner_text("#members"), "the first user sees the pending request")
    ck(page.locator("#members button[data-role=admin]").count() == 1
       and page.locator("#members button[data-role=member]").count() == 1,
       "the admin can choose admin or member")
    page.click("#members button[data-role=member]")
    wait_text(page, "#msgMembers", "一般として許可しました")
    page2.wait_for_selector("#toggle:not([disabled])", timeout=8000)
    ck(page2.locator("#pendingCard").is_hidden(), "after approval the pending notice goes away (no reload)")
    wait_text(page2, "#who", "一般")
    page2.wait_for_selector("#membersCard:not(.hidden)", timeout=8000)
    wait_text(page2, "#members", USER)
    ck(page2.locator("#members button").count() == 0, "a member sees members but no approve / delete buttons")
    page2.click("#toggle")
    wait_text(page2, "#lastBy", USER2)
    wait_text(page, "#lastBy", USER2)
    ck(True, "the approved second user toggles, the first user sees it")

    print("\n--- duplicate name ---")
    page3 = browser.new_context().new_page()
    add_authenticator(page3)
    page3.goto(BASE + "/html/index.html")
    page3.fill("#user", USER)
    page3.click("#btnSignup")
    wait_text(page3, "#msgOut", "user already exists")
    ck(True, "signing up with a taken name is refused")

    print("\n--- the last admin cannot leave ---")
    page.on("dialog", lambda d: d.accept())
    page.click("#keys .key button.danger")
    wait_text(page, "#msgIn", "退会できません")
    ck(page.locator("#keys .key").count() == 1, "the only admin's last passkey is kept")

    print("\n--- the third user: approved as an admin ---")
    signup(page3, USER3)
    wait_text(page, "#members", USER3)
    page.locator("#members .member", has_text=USER3).locator("button[data-role=admin]").click()
    wait_text(page, "#msgMembers", "管理者として許可しました")
    wait_text(page3, "#who", "管理者")
    page3.wait_for_selector("#members button.danger", timeout=8000)
    ck(True, "the new admin gets approve / delete buttons")

    if SHOT:
        page.set_viewport_size({"width": 800, "height": 1400})
        page.screenshot(path=SHOT, full_page=True)
        print("screenshot:", SHOT)

    print("\n--- delete another account ---")
    page.locator("#members .member", has_text=USER2).locator("button.danger").click()
    wait_text(page, "#msgMembers", "削除しました")
    page2.wait_for_selector("#loggedOut:not(.hidden)", timeout=8000)
    ck(True, "the deleted user is logged out on their own page")
    ck(USER2 not in page.inner_text("#members"), "the deleted user is gone from members")

    print("\n--- logout / login ---")
    page.click("#btnLogout")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    ck(page.locator("#toggle").is_disabled(), "toggle disabled after logout")
    page.fill("#user", "")
    page.click("#btnLogin")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(USER in page.inner_text("#who"), "discoverable login (no user name) works")
    page.click("#btnLogout")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    page.fill("#user", USER)
    page.click("#btnLogin")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(USER in page.inner_text("#who"), "login with the user name works")

    print("\n--- delete the last passkey ---")
    page.click("#keys .key button.danger")
    page.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    wait_text(page, "#msgOut", "アカウントを削除しました")
    ck(True, "with another admin, deleting the last passkey deletes the account and logs out")
    browser.close()

sys.exit(ck.finish())
