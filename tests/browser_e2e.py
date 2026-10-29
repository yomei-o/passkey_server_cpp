"""画面（html/index.html）をブラウザで通しで動かす（C++ 版 / Python 版どちらにも使える）

Chromium の仮想認証器（DevTools Protocol の WebAuthn ドメイン）を使うので、
本物の指紋や顔は要らない。**DB が空の**サーバに対して（最初の 1 人が全体の管理者になるのを見るため）:

    python tests/browser_e2e.py http://localhost:8099 [スクリーンショットの保存先]

rpId に IP アドレスは使えないので、127.0.0.1 ではなく localhost で開くこと。
Playwright（pip install playwright && playwright install chromium）が要る。
"""
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
from _bootstrap import Checker

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8099"
SHOT = sys.argv[2] if len(sys.argv) > 2 else ""
T = int(time.time())
ADMIN = "admin_%d" % T          # 全体の管理者（最初に登録した人）
OWNER = "owner_%d" % T          # テナントに最初に参加した人（テナントの管理者）
STAFF = "staff_%d" % T          # あとから参加申請した人
TENANT = "テナント_%d" % T

ck = Checker()


def new_page(browser):
    page = browser.new_context().new_page()
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal",
        "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True,
    }})
    page.on("dialog", lambda d: d.accept())
    return page


def read_qr(locator):
    """画面の QR コードを撮って OpenCV で読む。OpenCV が無ければ None"""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None
    png = locator.screenshot()
    img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_GRAYSCALE)
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return text


def check_qr(locator, url, what):
    text = read_qr(locator)
    if text is None:
        print("  SKIP  " + what + " (no OpenCV)")
    else:
        ck(text == url, what + " -> " + text)


def wait_text(page, sel, text, timeout=8000):
    page.wait_for_function("([s, t]) => (document.querySelector(s) || {}).textContent.includes(t)",
                           arg=[sel, text], timeout=timeout)


def signup(page, user):
    page.fill("#user", user)
    page.click("#btnSignup")
    page.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)


with sync_playwright() as p:
    browser = p.chromium.launch()

    print("--- the global admin adds a tenant ---")
    admin = new_page(browser)
    admin.goto(BASE + "/")
    ck(admin.url.endswith("/html/index.html"), "/ redirects to /html/index.html")
    signup(admin, ADMIN)
    ck("全体の管理者" in admin.inner_text("#who"), "the first user is the global admin")
    ck(admin.locator("#addTenant").is_visible() and admin.locator("#accountsCard").is_visible(),
       "the global admin sees 'add tenant' and accounts")
    admin.fill("#tenantNew", TENANT)
    admin.click("#btnAddTenant")
    wait_text(admin, "#msgTenants", "?tenant=")
    url = re.search(r"https?://\S+\?tenant=[0-9a-f]{32}", admin.inner_text("#msgTenants")).group(0)
    ck(True, "the tenant URL is shown: " + url)
    wait_text(admin, "#tenants", TENANT)
    admin.wait_for_selector("#tenants .qr-box svg", timeout=8000)
    check_qr(admin.locator("#tenants .qr-box svg"), url, "the new tenant's QR code (qr.wasm) reads back as its URL")
    admin.click("#tenants .qr-toggle")
    admin.wait_for_selector("#tenants .qr-box", state="detached", timeout=8000)
    ck(True, "the QR code can be closed")

    print("\n--- the first one to join becomes the tenant admin ---")
    owner = new_page(browser)
    owner.goto(url)
    wait_text(owner, "#tenantName", TENANT)
    ck("ログイン" in owner.inner_text("#tenantBody"), "logged out: the tenant name and a hint are shown")
    signup(owner, OWNER)
    ck("全体の管理者" not in owner.inner_text("#who"), "the 2nd account is not a global admin")
    owner.wait_for_selector("#btnJoin", timeout=8000)
    owner.click("#btnJoin")
    wait_text(owner, "#msgTenant", "管理者です")
    owner.wait_for_selector("#toggle", timeout=8000)
    ck(owner.locator("#tenantMembersCard").is_visible(), "the tenant admin sees the member list")
    owner.wait_for_selector("#tenantInvite svg", timeout=8000)
    check_qr(owner.locator("#tenantInvite svg"), url, "the tenant admin's invite QR code reads back as the URL")
    before = "ついています" in owner.inner_text("#state")
    owner.click("#toggle")
    wait_text(owner, "#state", "消えて" if before else "ついて")
    ck(OWNER in owner.inner_text("#lastBy"), "the tenant admin toggles the light")

    print("\n--- a staff member asks to join and is approved ---")
    staff = new_page(browser)
    staff.goto(url)
    signup(staff, STAFF)
    staff.wait_for_selector("#btnJoin", timeout=8000)
    staff.click("#btnJoin")
    wait_text(staff, "#msgTenant", "参加申請しました")
    wait_text(staff, "#tenantBody", "承認待ち")
    ck(staff.locator("#toggle").count() == 0, "a pending member has no light switch")
    ck(staff.locator("#tenantMembersCard").is_hidden(), "a pending member cannot see members")

    wait_text(owner, "#tenantMembers", STAFF)              # 3 秒ごとの確認で出てくる
    ck(owner.locator("#tenantMembers button[data-role=member]").count() == 1,
       "the tenant admin can approve as member or admin")
    owner.click("#tenantMembers button[data-role=member]")
    wait_text(owner, "#msgMembers", "一般として承認しました")
    staff.wait_for_selector("#toggle", timeout=8000)
    ck(True, "after approval the staff page shows the light (no reload)")
    ck(staff.locator("#tenantMembers button").count() == 0, "a plain member has no approve / remove buttons")
    ck(staff.locator("#tenantInviteBox").is_hidden(), "a plain member does not see the invite QR")
    now = "ついています" in staff.inner_text("#state")
    staff.click("#toggle")
    wait_text(staff, "#lastBy", STAFF)
    wait_text(owner, "#state", "消えて" if now else "ついて")
    ck(True, "the staff toggles, the tenant admin sees it")

    print("\n--- the global admin is not a member of the tenant ---")
    admin.goto(url)
    wait_text(admin, "#tenantName", TENANT)
    admin.wait_for_selector("#btnJoin", timeout=8000)
    ck(admin.locator("#toggle").count() == 0, "the global admin does not see the tenant's light")
    staff_list = staff.inner_text("#tenants")
    ck(TENANT in staff_list, "the staff lists the tenant they joined")

    if SHOT:
        owner.set_viewport_size({"width": 800, "height": 1400})
        owner.screenshot(path=SHOT, full_page=True)
        print("screenshot:", SHOT)

    print("\n--- remove a member ---")
    owner.locator("#tenantMembers .item", has_text=STAFF).locator("button.danger").click()
    wait_text(owner, "#msgMembers", "外しました")
    staff.wait_for_selector("#btnJoin", timeout=8000)
    ck(staff.locator("#toggle").count() == 0, "the removed member loses the light and can ask again")

    print("\n--- requests to become a global admin ---")
    ck(owner.locator("#addTenant").is_hidden(), "a plain account cannot add tenants")
    owner.click("#btnAdminRequest")
    wait_text(owner, "#adminRequestBody", "申請中")
    staff.wait_for_selector("#btnAdminRequest", timeout=8000)
    staff.click("#btnAdminRequest")
    wait_text(staff, "#adminRequestBody", "申請中")
    wait_text(admin, "#adminRequests", STAFF)               # 申請してきた人だけが並ぶ
    ck(OWNER in admin.inner_text("#adminRequests"), "the global admin sees only the 2 requests")
    admin.locator("#adminRequests .item", has_text=OWNER).locator("button.primary").click()
    wait_text(admin, "#msgAccounts", "全体の管理者にしました")
    wait_text(owner, "#who", "全体の管理者")
    owner.wait_for_selector("#addTenant:not(.hidden)", timeout=8000)
    ck(owner.locator("#adminRequestCard").is_hidden(), "the approved user can now add tenants")
    admin.locator("#adminRequests .item", has_text=STAFF).locator("button.danger").click()
    wait_text(admin, "#msgAccounts", "却下しました")
    staff.wait_for_selector("#btnAdminRequest", timeout=8000)
    ck(True, "the rejected user sees the request button again")
    wait_text(admin, "#admins", OWNER)
    ck(True, "the new admin is listed among global admins")
    admin.fill("#accountSearch", STAFF[:9])
    wait_text(admin, "#accounts", STAFF)
    ck(admin.locator("#accounts .item", has_text=STAFF).locator("button.danger").count() == 1,
       "searching by name finds the account with a delete button")

    print("\n--- the global admin deletes the tenant ---")
    admin.goto(BASE + "/html/index.html")
    admin.locator("#tenants .item", has_text=TENANT).locator("button.danger").click()
    wait_text(admin, "#msgTenants", "削除しました")
    wait_text(staff, "#tenantBody", "見つかりません")
    ck(True, "the tenant page says it no longer exists")

    print("\n--- logout / login / leave ---")
    admin.click("#btnLogout")
    admin.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    admin.fill("#user", "")
    admin.click("#btnLogin")
    admin.wait_for_selector("#loggedIn:not(.hidden)", timeout=10000)
    ck(ADMIN in admin.inner_text("#who"), "discoverable login (no user name) works")
    admin.click("#keys .key button.danger")
    admin.wait_for_selector("#loggedOut:not(.hidden)", timeout=5000)
    wait_text(admin, "#msgOut", "アカウントを削除しました")
    ck(True, "with another global admin, deleting the last passkey deletes the account")
    browser.close()

sys.exit(ck.finish())
