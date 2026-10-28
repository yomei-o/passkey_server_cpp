"""passkey API のテスト本体（C++ 版 / Python 版で共通）

ブラウザの代わりにソフトウェアの認証器（SoftKey）を使って、
navigator.credentials.create() / get() が返すのと同じ形（PublicKeyCredential.toJSON()）を作り、
サーバに投げる。正常系だけでなく、改ざん・使い回し・権限の拒否系を確認する。

呼び出し側（tests/python/test_passkey.py と tests/cpp/test_passkey.py）が用意するもの:
    post(path, body, token=None) -> dict    API を 1 回呼ぶ
    db_path                                          サーバが使っている SQLite ファイル
    origin                                           サーバから見た自分の origin
"""
import base64
import hashlib
import json
import os
import sqlite3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


#
# CBOR エンコーダ（認証器側で使う分だけ）
#
def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * size)):
            return bytes([(major << 5) | info]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor(v):
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


class SoftKey:
    """認証器の中に 1 つある鍵（= 1 つのパスキー）"""

    def __init__(self, alg=-7, counter=0, step=0):
        self.alg = alg
        self.cred_id = os.urandom(16)
        self.counter = counter      # 署名カウンタ。step=0 なら同期パスキーのように常に 0
        self.step = step
        self.user_handle = None
        if alg == -7:
            self.priv = ec.generate_private_key(ec.SECP256R1())
            n = self.priv.public_key().public_numbers()
            self.cose = cbor({1: 2, 3: -7, -1: 1,
                              -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        else:
            self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            n = self.priv.public_key().public_numbers()
            self.cose = cbor({1: 3, 3: -257,
                              -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")})

    @property
    def id(self):
        return b64u(self.cred_id)

    def sign(self, data):
        if self.alg == -7:
            return self.priv.sign(data, ec.ECDSA(hashes.SHA256()))
        return self.priv.sign(data, padding.PKCS1v15(), hashes.SHA256())


def auth_data(rp_id, flags, counter, attested=b""):
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + \
        counter.to_bytes(4, "big") + attested


def client_data(typ, challenge, origin, **extra):
    d = {"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": False}
    d.update(extra)
    return json.dumps(d, separators=(",", ":")).encode()


AAGUID = bytes.fromhex("ea9b8d664d011d213ce4b6b48cb575d4")   # Google Password Manager の AAGUID
UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40


def make_create(key, options, origin, rp_id=None, typ="webauthn.create",
                flags=UP | UV | BE | BS | AT, cred_id=None, challenge=None):
    """navigator.credentials.create() の結果（toJSON 形式）を作る"""
    pk = options["publicKey"]
    rp_id = rp_id or pk["rp"]["id"]
    if key.user_handle is None:          # 認証器は最初に登録したときの user.id を持ち続ける
        key.user_handle = pk["user"]["id"]
    cid = key.cred_id
    attested = AAGUID + len(cid).to_bytes(2, "big") + cid + key.cose
    ad = auth_data(rp_id, flags, key.counter, attested)
    att = cbor({"fmt": "none", "attStmt": {}, "authData": ad})
    cd = client_data(typ, challenge or pk["challenge"], origin)
    return {
        "id": cred_id or key.id,
        "rawId": cred_id or key.id,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(cd),
            "attestationObject": b64u(att),
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }


def make_get(key, options, origin, rp_id=None, typ="webauthn.get", flags=UP | UV | BE | BS,
             user_handle=None, tamper=False, counter=None):
    """navigator.credentials.get() の結果（toJSON 形式）を作る"""
    pk = options["publicKey"]
    rp_id = rp_id or pk["rpId"]
    if counter is None:
        key.counter += key.step
        counter = key.counter
    ad = auth_data(rp_id, flags, counter)
    cd = client_data(typ, pk["challenge"], origin)
    sig = key.sign(ad + hashlib.sha256(cd).digest())
    if tamper:
        cd = client_data(typ, pk["challenge"], origin, extra="tampered")
    return {
        "id": key.id,
        "rawId": key.id,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(cd),
            "authenticatorData": b64u(ad),
            "signature": b64u(sig),
            "userHandle": user_handle if user_handle is not None else key.user_handle,
        },
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    }


def reset_db(db_path):
    c = sqlite3.connect(db_path)
    for t in ("session", "passkey", "passkey_challenge", "switch_state", "account"):
        c.execute("delete from " + t)
    c.commit()
    c.close()


def sql(db_path, s, args=()):
    c = sqlite3.connect(db_path)
    r = list(c.execute(s, args))
    c.commit()
    c.close()
    return r


def run(ck, post, db_path, origin):
    reset_db(db_path)
    host = origin.split("://", 1)[1]
    rp_id = host.split(":")[0]

    def is_fail(r, msg):
        return r.get("status") == "fail" and r.get("message") == msg

    def check_fail(r, msg):
        ck(is_fail(r, msg), msg + "  <- " + (r.get("message") or str(r)))

    def reg_options(user=None, token=None):
        return post("/api/passkey/v0/register_options", {"user": user} if user else {}, token)

    def signup(user, key, name=None):
        o = reg_options(user)
        body = make_create(key, o, origin)
        if name:
            body["name"] = name
        return post("/api/passkey/v0/register_verify", body)

    print("--- register_options (new account) ---")
    r = reg_options("alice")
    ck(r.get("status") == "success", "register_options for a new name")
    pk = r.get("publicKey", {})
    ck(pk.get("rp", {}).get("id") == rp_id, "rp.id = %s (from Host)" % rp_id)
    ck(pk.get("user", {}).get("name") == "alice", "user.name = alice")
    ck(len(unb64u(pk.get("user", {}).get("id", ""))) == 32, "user.id is 32 random bytes")
    ck(len(unb64u(pk.get("challenge", ""))) == 32, "challenge is 32 bytes")
    ck([p["alg"] for p in pk.get("pubKeyCredParams", [])] == [-7, -257], "algs ES256, RS256")
    ck(pk.get("authenticatorSelection", {}).get("userVerification") == "required", "UV required")
    ck(pk.get("excludeCredentials") == [], "excludeCredentials empty")
    check_fail(reg_options(), "invalid user name")
    check_fail(reg_options("x" * 65), "invalid user name")
    check_fail(reg_options("a\nb"), "invalid user name")
    ck(reg_options("x" * 64).get("status") == "success", "64-byte name is ok")
    ck(reg_options("日本語の名前").get("status") == "success", "non-ASCII name is ok")
    check_fail(reg_options(token="nosuchtoken"), "not logged in")

    print("\n--- register_verify (new account) ---")
    k1 = SoftKey(-7)
    cred = make_create(k1, r, origin)
    r1 = post("/api/passkey/v0/register_verify", dict(cred, name="my phone"))
    ck(r1.get("status") == "success" and r1.get("user") == "alice", "sign up alice with an ES256 key")
    A = r1.get("access_token", "")
    ck(len(A) == 32, "sign up returns an access_token")
    me = post("/api/passkey/v0/me", {}, A)
    ck(me.get("status") == "success" and me.get("user") == "alice", "me -> alice")
    ck(r1.get("approved") is True and me.get("approved") is True, "the first user is approved at once")
    row = r1.get("passkey", {})
    ck(row.get("credential_id") == k1.id, "stored credential_id")
    ck(row.get("user") == "alice" and row.get("name") == "my phone", "stored user / name")
    ck(row.get("alg") == -7 and row.get("sign_count") == 0, "stored alg -7, sign_count 0")
    ck(unb64u(row.get("public_key", "")) == k1.cose, "stored public_key = COSE_Key")
    ck(row.get("user_handle") == pk["user"]["id"], "stored user_handle = options user.id")
    ck(row.get("transports") == ["internal", "hybrid"], "stored transports")
    ck(row.get("backup_eligible") == 1 and row.get("backed_up") == 1, "stored BE / BS flags")
    ck(row.get("aaguid") == "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "stored aaguid")

    check_fail(post("/api/passkey/v0/register_verify", cred), "challenge not found")
    check_fail(reg_options("alice"), "user already exists")

    # 同じ名前で options を 2 回取って、先に片方が登録したら後の方は弾く
    o1, o2 = reg_options("carol"), reg_options("carol")
    kc = SoftKey(-7)
    rc = post("/api/passkey/v0/register_verify", make_create(kc, o1, origin))
    C = rc.get("access_token", "")
    ck(rc.get("status") == "success" and rc.get("approved") is False and len(C) == 32,
       "carol signs up as the 2nd user -> pending, but logged in")
    check_fail(post("/api/passkey/v0/register_verify", make_create(SoftKey(-7), o2, origin)),
               "user already exists")

    def reg_fail(msg, **kw):
        key = kw.pop("key", None) or SoftKey(-7)
        tok = kw.pop("token", None)
        o = kw.pop("opts", None) or reg_options("newuser")
        r = post("/api/passkey/v0/register_verify", make_create(key, o, kw.pop("origin", origin), **kw), tok)
        check_fail(r, msg)

    reg_fail("origin mismatch", origin="https://evil.example")
    reg_fail("type mismatch", typ="webauthn.get")
    reg_fail("rpIdHash mismatch", rp_id="evil.example")
    reg_fail("user presence not set", flags=UV | AT)
    reg_fail("user verification not set", flags=UP | AT)
    reg_fail("attested credential data missing", flags=UP | UV)
    reg_fail("credential id mismatch", cred_id=b64u(b"another id"))
    reg_fail("credential already registered", key=k1)
    reg_fail("challenge not found", challenge=b64u(os.urandom(32)))
    reg_fail("not logged in", token="nosuchtoken")

    # 期限切れ: 発行したチャレンジの expire を過去にする
    o = reg_options("newuser")
    sql(db_path, "update passkey_challenge set expire='2000-01-01 00:00:00' where challenge=?",
        (o["publicKey"]["challenge"],))
    reg_fail("challenge expired", opts=o)
    ck(not sql(db_path, "select 1 from passkey_challenge where challenge=?",
               (o["publicKey"]["challenge"],)), "challenge row removed after use")
    ck(not sql(db_path, "select 1 from passkey where user='newuser'"), "no account made by failures")

    print("\n--- add a passkey to the logged-in account ---")
    k2 = SoftKey(-257, counter=5, step=1)
    o = reg_options(token=A)
    ck(o.get("publicKey", {}).get("user", {}).get("name") == "alice", "options with token -> alice")
    ck([c["id"] for c in o["publicKey"]["excludeCredentials"]] == [k1.id],
       "excludeCredentials lists the registered key")
    ck(o["publicKey"]["user"]["id"] == pk["user"]["id"], "same user.id for the 2nd key")
    r = post("/api/passkey/v0/register_verify", make_create(k2, o, origin), A)
    ck(r.get("status") == "success" and r["passkey"]["alg"] == -257
       and r["passkey"]["sign_count"] == 5, "add an RS256 key (counter 5)")
    ck("access_token" not in r, "adding a key does not issue a new token")
    ck(r.get("passkey", {}).get("name") == "passkey", "default name = passkey")

    kb = SoftKey(-7)
    rb = signup("bob", kb)
    B = rb.get("access_token", "")
    ck(rb.get("status") == "success" and rb.get("approved") is False, "bob signs up -> pending")
    reg_fail("challenge user mismatch", opts=reg_options(token=A), token=B)
    reg_fail("challenge user mismatch", opts=reg_options("dave"), token=A)

    print("\n--- login ---")
    lo = post("/api/passkey/v0/login_options", {})
    ck(lo.get("status") == "success", "login_options without user")
    ck(lo["publicKey"].get("rpId") == rp_id and lo["publicKey"].get("allowCredentials") == [],
       "rpId and empty allowCredentials (discoverable)")
    lo2 = post("/api/passkey/v0/login_options", {"user": "alice"})
    ck(sorted(c["id"] for c in lo2["publicKey"]["allowCredentials"]) == sorted([k1.id, k2.id]),
       "login_options with user lists alice's keys")

    a = make_get(k1, lo, origin)
    r = post("/api/passkey/v0/login_verify", a)
    ck(r.get("status") == "success" and r.get("user") == "alice", "login with the ES256 key")
    A2 = r.get("access_token", "")
    ck(post("/api/passkey/v0/me", {}, A2).get("user") == "alice", "new token works")
    ck(post("/api/passkey/v0/me", {}, A).get("user") == "alice", "older token still works")
    check_fail(post("/api/passkey/v0/login_verify", a), "challenge not found")

    def lopt(body=None):
        return post("/api/passkey/v0/login_options", body or {})

    def login_fail(msg, key=k1, opts=None, **kw):
        r = post("/api/passkey/v0/login_verify",
                 make_get(key, opts or lopt(), kw.pop("origin", origin), **kw))
        check_fail(r, msg)

    login_fail("origin mismatch", origin="https://evil.example")
    login_fail("type mismatch", typ="webauthn.create")
    login_fail("rpIdHash mismatch", rp_id="evil.example")
    login_fail("user presence not set", flags=UV)
    login_fail("user verification not set", flags=UP)
    login_fail("signature invalid", tamper=True)
    login_fail("unknown credential", key=SoftKey(-7))
    login_fail("user handle mismatch", user_handle=b64u(b"x" * 32))
    login_fail("challenge user mismatch", opts=lopt({"user": "bob"}))
    o = lopt()
    sql(db_path, "update passkey_challenge set expire='2000-01-01 00:00:00' where challenge=?",
        (o["publicKey"]["challenge"],))
    login_fail("challenge expired", opts=o)

    r = post("/api/passkey/v0/login_verify", make_get(k2, lopt(), origin))
    ck(r.get("status") == "success", "login with the RS256 key (counter 5 -> 6)")
    ck(sql(db_path, "select sign_count from passkey where credential_id=?", (k2.id,)) == [(6,)],
       "sign_count updated to 6")
    login_fail("sign count did not increase", key=k2, counter=6)
    r = post("/api/passkey/v0/login_verify", make_get(k1, lopt({"user": "alice"}), origin))
    ck(r.get("status") == "success", "ES256 key with counter 0 logs in again (user given)")
    ck(sql(db_path, "select last_used_at is not null from passkey where credential_id=?",
           (k1.id,)) == [(1,)], "last_used_at set")

    print("\n--- session ---")
    sql(db_path, "update session set expire='2000-01-01 00:00:00' where skey=?", (A2,))
    check_fail(post("/api/passkey/v0/me", {}, A2), "not logged in")
    check_fail(post("/api/passkey/v0/me", {}), "not logged in")
    ck(post("/api/passkey/v0/logout", {}, A).get("status") == "success", "logout")
    check_fail(post("/api/passkey/v0/me", {}, A), "not logged in")
    check_fail(post("/api/passkey/v0/logout", {}, A), "not logged in")

    print("\n--- list / delete ---")
    A = post("/api/passkey/v0/login_verify", make_get(k1, lopt(), origin)).get("access_token", "")
    r = post("/api/passkey/v0/list", {}, A)
    ck(r.get("status") == "success" and r.get("total_count") == 2 and r.get("user") == "alice",
       "alice lists 2 keys")
    ck({p["credential_id"] for p in r.get("passkey_list", [])} == {k1.id, k2.id}, "only alice's keys")
    ck("public_key" in [c["field"] for c in r.get("columns", [])], "columns include public_key")
    check_fail(post("/api/passkey/v0/list", {}), "not logged in")

    check_fail(post("/api/passkey/v0/delete", {"credential_id": kb.id}, A), "unknown credential")
    check_fail(post("/api/passkey/v0/delete", {}, A), "invalid request")
    r = post("/api/passkey/v0/delete", {"credential_id": k2.id}, A)
    ck(r.get("status") == "success", "alice deletes her RS256 key")
    ck(post("/api/passkey/v0/list", {}, A).get("total_count") == 1, "alice has 1 key left")
    login_fail("unknown credential", key=k2)

    print("\n--- broken input ---")
    check_fail(post("/api/passkey/v0/login_verify", {}), "invalid request")
    check_fail(post("/api/passkey/v0/login_verify",
                    {"id": "x", "response": {"clientDataJSON": "!!!"}}), "invalid request")
    check_fail(post("/api/passkey/v0/login_verify",
                    {"id": "x", "response": {"clientDataJSON": b64u(b"[1,2]")}}), "invalid request")
    c = make_create(SoftKey(-7), reg_options("newuser"), origin)
    c["response"]["attestationObject"] = b64u(b"\xa3\x63fmt")
    check_fail(post("/api/passkey/v0/register_verify", c), "invalid request")
    # COSE_Key が P-256 でない（crv=2: P-384）
    k = SoftKey(-7)
    k.cose = cbor({1: 2, 3: -7, -1: 2, -2: b"\0" * 32, -3: b"\0" * 32})
    check_fail(post("/api/passkey/v0/register_verify", make_create(k, reg_options("newuser"), origin)),
               "unsupported algorithm")
    # 曲線上にない点
    k.cose = cbor({1: 2, 3: -7, -1: 1, -2: b"\1" * 32, -3: b"\1" * 32})
    check_fail(post("/api/passkey/v0/register_verify", make_create(k, reg_options("newuser"), origin)),
               "invalid public key")

    print("\n--- accounts (approve / delete) ---")
    ck(post("/api/passkey/v0/me", {}, C).get("approved") is False, "me says carol is pending")
    check_fail(post("/api/account/v0/list", {}, C), "not approved")
    check_fail(post("/api/account/v0/approve", {"user": "carol"}, C), "not approved")
    check_fail(post("/api/account/v0/delete", {"user": "alice"}, C), "not approved")
    check_fail(post("/api/account/v0/list", {}), "not logged in")
    r = post("/api/account/v0/list", {}, A)
    accts = {a["user"]: a for a in r.get("account_list", [])}
    ck(r.get("status") == "success" and sorted(accts) == ["alice", "bob", "carol"],
       "alice lists alice / bob / carol")
    ck(accts.get("alice", {}).get("status") == "approved" and accts["alice"].get("approved_by") == "alice",
       "alice: approved (by herself, as the first user)")
    ck(accts.get("carol", {}).get("status") == "pending" and accts["carol"].get("approved_by") is None,
       "carol: pending")
    ck(accts.get("alice", {}).get("passkey_count") == 1 and accts.get("bob", {}).get("passkey_count") == 1,
       "passkey_count")
    check_fail(post("/api/account/v0/approve", {}, A), "invalid request")
    check_fail(post("/api/account/v0/approve", {"user": "nosuch"}, A), "unknown account")
    check_fail(post("/api/account/v0/approve", {"user": "alice"}, A), "already approved")
    r = post("/api/account/v0/approve", {"user": "carol"}, A)
    ck(r.get("status") == "success" and r.get("account", {}).get("status") == "approved"
       and r["account"].get("approved_by") == "alice" and len(r["account"].get("approved_at") or "") == 19,
       "alice approves carol")
    ck(post("/api/passkey/v0/me", {}, C).get("approved") is True, "carol is approved now")
    ck(post("/api/account/v0/list", {}, C).get("status") == "success", "carol can list accounts now")

    check_fail(post("/api/account/v0/delete", {"user": "carol"}, C), "cannot delete yourself")
    check_fail(post("/api/account/v0/delete", {"user": "nosuch"}, C), "unknown account")
    check_fail(post("/api/account/v0/delete", {}, C), "invalid request")
    kd = SoftKey(-7)
    rd = signup("dave", kd)
    D = rd.get("access_token", "")
    ck(rd.get("approved") is False, "dave signs up -> pending")
    r = post("/api/account/v0/delete", {"user": "dave"}, C)
    ck(r.get("status") == "success", "carol deletes (rejects) pending dave")
    check_fail(post("/api/passkey/v0/me", {}, D), "not logged in")
    login_fail("unknown credential", key=kd)
    ck(not sql(db_path, "select 1 from passkey where user='dave'"), "dave's passkeys are gone")
    ck(not sql(db_path, "select 1 from session where user='dave'"), "dave's sessions are gone")
    ck(reg_options("dave").get("status") == "success", "the name dave is free again")

    print("\n--- leaving: deleting your last passkey ---")
    ke = SoftKey(-7)
    re_ = signup("erin", ke)
    E = re_.get("access_token", "")
    r = post("/api/passkey/v0/delete", {"credential_id": ke.id}, E)
    ck(r.get("status") == "success" and r.get("account_deleted") is True, "erin deletes her only key")
    check_fail(post("/api/passkey/v0/me", {}, E), "not logged in")
    ck(not sql(db_path, "select 1 from account where user='erin'"), "erin's account is gone")
    r = post("/api/passkey/v0/delete", {"credential_id": k1.id}, A)
    r2 = post("/api/passkey/v0/list", {}, A)
    ck(r.get("account_deleted") is True and r2.get("message") == "not logged in",
       "alice deletes her last key -> her account is gone too")
    A = signup("alice", SoftKey(-7)).get("access_token", "")
    ck(post("/api/passkey/v0/me", {}, A).get("approved") is False,
       "alice signs up again but is pending (approved users still exist)")

    print("\n--- shared switch ---")
    r = post("/api/switch/v0/get", {})
    ck(r == {"status": "success", "on": False, "updated_by": None, "updated_at": None},
       "switch starts off, nobody touched it")
    check_fail(post("/api/switch/v0/set", {"on": True}), "not logged in")
    check_fail(post("/api/switch/v0/set", {"on": True}, "nosuchtoken"), "not logged in")
    check_fail(post("/api/switch/v0/set", {"on": True}, A), "not approved")
    check_fail(post("/api/switch/v0/set", {"on": 1}, C), "invalid request")
    check_fail(post("/api/switch/v0/set", {}, C), "invalid request")
    r = post("/api/switch/v0/set", {"on": True}, C)
    ck(r.get("status") == "success" and r.get("on") is True and r.get("updated_by") == "carol",
       "carol turns it on")
    ck(len(r.get("updated_at") or "") == 19, "updated_at is YYYY-MM-DD HH:MM:SS")
    r = post("/api/switch/v0/get", {})
    ck(r.get("on") is True and r.get("updated_by") == "carol", "everyone sees it on (by carol)")
    B = post("/api/passkey/v0/login_verify", make_get(kb, lopt(), origin)).get("access_token", "")
    check_fail(post("/api/switch/v0/set", {"on": False}, B), "not approved")
    ck(post("/api/account/v0/approve", {"user": "bob"}, C).get("status") == "success", "carol approves bob")
    r = post("/api/switch/v0/set", {"on": False}, B)
    ck(r.get("on") is False and r.get("updated_by") == "bob", "bob turns it off")
    ck(sql(db_path, "select count(*) from switch_state") == [(1,)], "one row for the switch")
