#
# passkey（WebAuthn）API
#
#   /api/passkey/v0/register_options   登録の準備。トークン無しなら新規アカウント、有りなら自分に追加
#   /api/passkey/v0/register_verify    認証器の応答を検証して公開鍵を保存
#   /api/passkey/v0/login_options      ログインの準備
#   /api/passkey/v0/login_verify       署名を検証してセッションを発行
#   /api/passkey/v0/me                 トークンの確認
#   /api/passkey/v0/logout             セッションを消す
#   /api/passkey/v0/list               自分のパスキー一覧（サーバが何を保存しているか）
#   /api/passkey/v0/delete             自分のパスキーを削除（最後の 1 本ならアカウントごと消える）
#
#   /api/account/v0/list               全アカウントの一覧（全体の管理者だけ）
#   /api/account/v0/delete             自分以外のアカウントを消す（全体の管理者だけ）
#   /api/account/v0/demote             全体の管理者を一般に戻す（全体の管理者だけ。自分も可）
#
#   /api/account/v0/admin_request          全体の管理者に申請する（ログインしていれば誰でも）
#   /api/account/v0/admin_request_cancel   自分の申請を取り下げる
#   /api/account/v0/admin_requests         申請の一覧（全体の管理者だけ）
#   /api/account/v0/admin_approve          申請を承認して全体の管理者にする（全体の管理者だけ）
#   /api/account/v0/admin_reject           申請を却下する（全体の管理者だけ）
#
# 誰でも登録できる。最初の 1 人は全体の管理者（テナントの追加・削除ができる）、2 人目からは一般。
# 2 人目からの全体の管理者は、本人が申請して、全体の管理者が承認する（一覧から選んで上げることはしない）。
# 電気を操作できるかどうかはテナントのメンバーかどうかで決まる（testsv_api_tenant.py）。
#
# C++ 版は cpp/main/testsv_api_passkey.h。検査の順番と失敗時の message を揃えてある。
#
from fastapi import APIRouter, Request, Header, Depends
from sqlalchemy.orm import Session

import base64
import datetime
import hashlib
import json
import os
import secrets
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from database import SessionLocal, engine
import model_passkey
import model_tenant

router = APIRouter()


# セッションの有効期間（時間）
SESSION_EXPIRE_HOURS = 24
# チャレンジの有効期間（秒）
PASSKEY_CHALLENGE_EXPIRE_SECONDS = 300
# ブラウザに渡す timeout（ミリ秒）
PASSKEY_TIMEOUT_MS = 60000
# ユーザ名の長さの上限（UTF-8 のバイト数）
USER_NAME_MAX_BYTES = 64

COSE_ALG_ES256 = -7
COSE_ALG_RS256 = -257

# authenticatorData の flags
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

PASSKEY_COLUMNS = [
    "user",
    "name",
    "credential_id",
    "user_handle",
    "alg",
    "public_key",
    "sign_count",
    "transports",
    "backup_eligible",
    "backed_up",
    "aaguid",
    "last_used_at",
    "created_at",
]


ACCOUNT_APPROVED = "approved"
ACCOUNT_PENDING = "pending"
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"


def init_passkey():
    print("init_passkey()")
    model_passkey.Base.metadata.create_all(bind=engine)
    # role 列が無かった頃の account テーブルには列を足す（既にあればエラーになるので無視）
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("ALTER TABLE account ADD COLUMN role TEXT")
    except Exception:
        pass
    db = SessionLocal()
    try:
        # account テーブルが無かった頃に登録した人は、承認済みのアカウントとして引き継ぐ
        users = {u for (u,) in db.query(model_passkey.Passkey.user).distinct()}
        have = {u for (u,) in db.query(model_passkey.Account.user)}
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        for u in sorted(users - have):
            db.add(model_passkey.Account(user=u, status=ACCOUNT_APPROVED, created_at=now))
        # role が無かった頃の承認済みは、許可も削除もできたので管理者として引き継ぐ
        db.query(model_passkey.Account).filter(
            model_passkey.Account.status == ACCOUNT_APPROVED,
            model_passkey.Account.role.is_(None),
        ).update({model_passkey.Account.role: ROLE_ADMIN})
        # 全体の承認待ちは無くなったので、承認待ちだった人は一般のアカウントにする
        db.query(model_passkey.Account).filter(
            model_passkey.Account.status == ACCOUNT_PENDING,
        ).update({model_passkey.Account.status: ACCOUNT_APPROVED,
                  model_passkey.Account.role: ROLE_MEMBER})
        db.commit()
    finally:
        db.close()

init_passkey()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class PasskeyError(Exception):
    pass


# 時刻は naive な UTC で保存・比較する（C++ 版と同じ DB を読めるように）
def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def extract_bearer_token(auth_header) -> str:
    if not auth_header:
        return ""
    auth_header = auth_header.strip()
    if auth_header.lower().startswith("bearer"):
        rest = auth_header[6:]
        parts = rest.lstrip().split(None, 1)
        if parts:
            return parts[0].strip()
    return ""


#
# base64url / CBOR
#

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise PasskeyError("invalid request")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise PasskeyError("invalid request")


# WebAuthn で出てくる範囲だけの CBOR デコーダ
# （整数・バイト列・文字列・配列・マップ・true/false/null）。
# 戻り値は (値, 次の位置)。COSE_Key の後ろに拡張データが続くので位置が要る。
def cbor_decode(data: bytes, pos: int = 0, depth: int = 0):
    if pos >= len(data) or depth > 16:
        raise PasskeyError("invalid request")
    ib = data[pos]
    pos += 1
    major = ib >> 5
    info = ib & 0x1F
    if info < 24:
        val = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if pos + n > len(data):
            raise PasskeyError("invalid request")
        val = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        raise PasskeyError("invalid request")

    if major == 0:
        return val, pos
    if major == 1:
        return -1 - val, pos
    if major in (2, 3):
        if pos + val > len(data):
            raise PasskeyError("invalid request")
        b = data[pos:pos + val]
        pos += val
        if major == 3:
            try:
                return b.decode("utf-8"), pos
            except Exception:
                raise PasskeyError("invalid request")
        return b, pos
    if major == 4:
        arr = []
        for _ in range(val):
            v, pos = cbor_decode(data, pos, depth + 1)
            arr.append(v)
        return arr, pos
    if major == 5:
        m = {}
        for _ in range(val):
            k, pos = cbor_decode(data, pos, depth + 1)
            v, pos = cbor_decode(data, pos, depth + 1)
            if isinstance(k, (list, dict)):
                raise PasskeyError("invalid request")
            m[k] = v
        return m, pos
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
    raise PasskeyError("invalid request")


#
# rpId / origin
#

# 期待する origin の一覧。環境変数 PASSKEY_ORIGIN（カンマ区切り）があればそれ、
# 無ければリクエストの Host から作る（このサーバ自身がページを配っている前提）。
# Lambda やトンネルの後ろでは X-Forwarded-Proto / X-Forwarded-Host を見る。
def expected_origins(request: Request) -> list:
    env = os.environ.get("PASSKEY_ORIGIN", "")
    if env:
        return [o.strip().rstrip("/") for o in env.split(",") if o.strip()]
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    if not proto:
        proto = request.url.scheme
    host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    if not host:
        host = request.headers.get("host", "")
    return [proto + "://" + host]


# rpId は環境変数 PASSKEY_RP_ID、無ければ最初の origin のホスト名（ポートは外す）
def expected_rp_id(request: Request) -> str:
    env = os.environ.get("PASSKEY_RP_ID", "")
    if env:
        return env
    origin = expected_origins(request)[0]
    host = origin.split("://", 1)[-1]
    return host.split(":")[0]


def rp_name() -> str:
    return os.environ.get("PASSKEY_RP_NAME", "passkey_server_cpp")


#
# authenticatorData / COSE_Key
#

def parse_auth_data(auth_data: bytes) -> dict:
    if len(auth_data) < 37:
        raise PasskeyError("invalid request")
    r = {
        "rp_id_hash": auth_data[0:32],
        "flags": auth_data[32],
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
    }
    if r["flags"] & FLAG_AT:
        pos = 37
        if len(auth_data) < pos + 18:
            raise PasskeyError("invalid request")
        r["aaguid"] = auth_data[pos:pos + 16]
        pos += 16
        n = int.from_bytes(auth_data[pos:pos + 2], "big")
        pos += 2
        if len(auth_data) < pos + n:
            raise PasskeyError("invalid request")
        r["credential_id"] = auth_data[pos:pos + n]
        pos += n
        key, end = cbor_decode(auth_data, pos)
        if not isinstance(key, dict):
            raise PasskeyError("invalid request")
        r["cose_key"] = auth_data[pos:end]
    return r


def check_auth_data_common(ad: dict, rp_id: str):
    if ad["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise PasskeyError("rpIdHash mismatch")
    if not ad["flags"] & FLAG_UP:
        raise PasskeyError("user presence not set")
    if not ad["flags"] & FLAG_UV:
        raise PasskeyError("user verification not set")


# COSE_Key → (alg, 公開鍵)。対応は ES256(P-256) と RS256 だけ
def load_cose_key(cose: bytes):
    key, _ = cbor_decode(cose, 0)
    if not isinstance(key, dict):
        raise PasskeyError("unsupported algorithm")
    kty = key.get(1)
    alg = key.get(3)
    if kty == 2 and alg == COSE_ALG_ES256 and key.get(-1) == 1:
        x = key.get(-2)
        y = key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise PasskeyError("invalid public key")
        try:
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
        except Exception:
            raise PasskeyError("invalid public key")
        return alg, pub
    if kty == 3 and alg == COSE_ALG_RS256:
        n = key.get(-1)
        e = key.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes) or len(n) < 256:
            raise PasskeyError("invalid public key")
        try:
            pub = rsa.RSAPublicNumbers(
                int.from_bytes(e, "big"), int.from_bytes(n, "big")
            ).public_key()
        except Exception:
            raise PasskeyError("invalid public key")
        return alg, pub
    raise PasskeyError("unsupported algorithm")


def verify_signature(cose: bytes, signature: bytes, data: bytes) -> bool:
    alg, pub = load_cose_key(cose)
    try:
        if alg == COSE_ALG_ES256:
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def format_aaguid(b: bytes) -> str:
    h = b.hex()
    return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]


def format_time(t):
    if t is None:
        return None
    return t.strftime("%Y-%m-%d %H:%M:%S")


#
# clientDataJSON / チャレンジ
#

def parse_client_data(b64) -> tuple:
    raw = b64url_decode(b64)
    try:
        cd = json.loads(raw.decode("utf-8"))
    except Exception:
        raise PasskeyError("invalid request")
    if not isinstance(cd, dict):
        raise PasskeyError("invalid request")
    return raw, cd


def new_challenge(db: Session, purpose: str, user: str = None, user_handle: str = None) -> str:
    # 期限切れのチャレンジを掃除してから発行する
    db.query(model_passkey.PasskeyChallenge).filter(
        model_passkey.PasskeyChallenge.expire < utcnow()
    ).delete()
    challenge = b64url_encode(secrets.token_bytes(32))
    db.add(model_passkey.PasskeyChallenge(
        challenge=challenge,
        purpose=purpose,
        user=user,
        user_handle=user_handle,
        expire=utcnow() + datetime.timedelta(seconds=PASSKEY_CHALLENGE_EXPIRE_SECONDS),
        created_at=utcnow(),
    ))
    db.commit()
    return challenge


# clientData の challenge を引いて消す（1 回きり）。期限切れもここで弾く
def consume_challenge(db: Session, cd: dict, purpose: str) -> dict:
    ch = cd.get("challenge")
    if not isinstance(ch, str) or not ch:
        raise PasskeyError("challenge not found")
    row = db.query(model_passkey.PasskeyChallenge).filter(
        model_passkey.PasskeyChallenge.challenge == ch,
        model_passkey.PasskeyChallenge.purpose == purpose,
    ).first()
    if row is None:
        raise PasskeyError("challenge not found")
    info = {"user": row.user or "", "user_handle": row.user_handle or "", "expire": row.expire}
    db.delete(row)
    db.commit()
    if info["expire"] < utcnow():
        raise PasskeyError("challenge expired")
    return info


def check_origin(cd: dict, request: Request):
    if cd.get("origin") not in expected_origins(request):
        raise PasskeyError("origin mismatch")
    if cd.get("crossOrigin") is True:
        raise PasskeyError("origin mismatch")


#
# session
#

def create_session(db: Session, user: str) -> str:
    # 期限切れのセッションを掃除してから発行する
    db.query(model_passkey.Session).filter(model_passkey.Session.expire < utcnow()).delete()
    skey = secrets.token_hex(16)
    db.add(model_passkey.Session(
        user=user, skey=skey,
        expire=utcnow() + datetime.timedelta(hours=SESSION_EXPIRE_HOURS),
        created_at=utcnow()))
    db.commit()
    return skey


def get_session(db: Session, skey: str):
    if not skey:
        return None
    s = db.query(model_passkey.Session).filter(model_passkey.Session.skey == skey).first()
    if s is None or s.expire < utcnow():
        return None
    # アカウントが消されていればそのトークンも無効
    if get_account(db, s.user) is None:
        return None
    return s


def session_user(db: Session, skey: str) -> str:
    s = get_session(db, skey)
    if s is None:
        raise PasskeyError("not logged in")
    return s.user


#
# account
#

def get_account(db: Session, user: str):
    return db.query(model_passkey.Account).filter(model_passkey.Account.user == user).first()


def is_approved(db: Session, user: str) -> bool:
    a = get_account(db, user)
    return a is not None and a.status == ACCOUNT_APPROVED


def role_of(db: Session, user: str):
    a = get_account(db, user)
    return a.role if a is not None and a.status == ACCOUNT_APPROVED else None


def admin_count(db: Session) -> int:
    return db.query(model_passkey.Account).filter(
        model_passkey.Account.status == ACCOUNT_APPROVED,
        model_passkey.Account.role == ROLE_ADMIN).count()


# 承認済みのユーザだけが使える API の入口
def approved_user(db: Session, skey: str) -> str:
    user = session_user(db, skey)
    if not is_approved(db, user):
        raise PasskeyError("not approved")
    return user


# 全体の管理者だけが使える API の入口
def admin_user(db: Session, skey: str) -> str:
    user = approved_user(db, skey)
    if role_of(db, user) != ROLE_ADMIN:
        raise PasskeyError("admin only")
    return user


def delete_account(db: Session, user: str):
    db.query(model_passkey.Passkey).filter(model_passkey.Passkey.user == user).delete()
    db.query(model_passkey.Session).filter(model_passkey.Session.user == user).delete()
    db.query(model_passkey.Account).filter(model_passkey.Account.user == user).delete()
    db.query(model_passkey.AdminRequest).filter(model_passkey.AdminRequest.user == user).delete()
    db.query(model_tenant.TenantMember).filter(model_tenant.TenantMember.user == user).delete()
    db.commit()


def account_to_dict(db: Session, a) -> dict:
    return {
        "user": a.user,
        "status": a.status,
        "role": a.role,
        "approved_by": a.approved_by,
        "approved_at": format_time(a.approved_at),
        "created_at": format_time(a.created_at),
        "passkey_count": len(get_user_passkeys(db, a.user)),
    }


#
# passkey テーブル
#

def passkey_to_dict(p: model_passkey.Passkey) -> dict:
    return {
        "user": p.user,
        "name": p.name,
        "credential_id": p.credential_id,
        "user_handle": p.user_handle,
        "alg": p.alg,
        "public_key": p.public_key,
        "sign_count": p.sign_count,
        "transports": [t for t in (p.transports or "").split(",") if t],
        "backup_eligible": p.backup_eligible,
        "backed_up": p.backed_up,
        "aaguid": p.aaguid,
        "last_used_at": format_time(p.last_used_at),
        "created_at": format_time(p.created_at),
    }


def get_passkey(db: Session, credential_id: str):
    return db.query(model_passkey.Passkey).filter(
        model_passkey.Passkey.credential_id == credential_id).first()


def get_user_passkeys(db: Session, user: str) -> list:
    return db.query(model_passkey.Passkey).filter(
        model_passkey.Passkey.user == user).order_by(model_passkey.Passkey.id).all()


def cred_descriptor(p: model_passkey.Passkey) -> dict:
    d = {"type": "public-key", "id": p.credential_id}
    t = [t for t in (p.transports or "").split(",") if t]
    if t:
        d["transports"] = t
    return d


# ユーザ名は 1〜64 バイト、制御文字なし
def valid_user_name(user) -> bool:
    if not isinstance(user, str):
        return False
    b = user.encode("utf-8")
    if len(b) == 0 or len(b) > USER_NAME_MAX_BYTES:
        return False
    return all(c >= 0x20 and c != 0x7F for c in b)


def fail(message: str) -> dict:
    return {"status": "fail", "message": message}


#
# API 本体
#

# トークン無し: body.user の新規アカウント（まだ誰も使っていない名前）
# トークン有り: ログイン中のアカウントにパスキーを追加
def passkey_register_options(db: Session, skey: str, body: dict, request: Request) -> dict:
    if skey:
        user = session_user(db, skey)
    else:
        user = body.get("user")
        if not valid_user_name(user):
            raise PasskeyError("invalid user name")
    if not skey and get_account(db, user) is not None:
        raise PasskeyError("user already exists")
    rows = get_user_passkeys(db, user)
    # 認証器に渡す user.id。アカウントごとに 1 つ、最初の登録時にランダムに作る
    # （ユーザ名などの個人情報は入れない）
    handle = rows[0].user_handle if rows else b64url_encode(secrets.token_bytes(32))
    challenge = new_challenge(db, "register", user, handle)
    return {
        "status": "success",
        "publicKey": {
            "rp": {"id": expected_rp_id(request), "name": rp_name()},
            "user": {"id": handle, "name": user, "displayName": user},
            "challenge": challenge,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": COSE_ALG_ES256},
                {"type": "public-key", "alg": COSE_ALG_RS256},
            ],
            "timeout": PASSKEY_TIMEOUT_MS,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "excludeCredentials": [cred_descriptor(p) for p in rows],
        },
    }


def passkey_register_verify(db: Session, skey: str, body: dict, request: Request) -> dict:
    resp = body.get("response")
    cred_id = body.get("id")
    if not isinstance(resp, dict) or not isinstance(cred_id, str) or not cred_id:
        raise PasskeyError("invalid request")
    login_user = session_user(db, skey) if skey else ""
    _, cd = parse_client_data(resp.get("clientDataJSON"))
    if cd.get("type") != "webauthn.create":
        raise PasskeyError("type mismatch")
    ch = consume_challenge(db, cd, "register")
    if skey:
        if ch["user"] != login_user:
            raise PasskeyError("challenge user mismatch")
    elif get_account(db, ch["user"]) is not None:
        # options の後で同じ名前が先に登録された
        raise PasskeyError("user already exists")
    check_origin(cd, request)

    att, _ = cbor_decode(b64url_decode(resp.get("attestationObject")), 0)
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise PasskeyError("invalid request")
    ad = parse_auth_data(att["authData"])
    check_auth_data_common(ad, expected_rp_id(request))
    if "credential_id" not in ad:
        raise PasskeyError("attested credential data missing")
    if b64url_encode(ad["credential_id"]) != cred_id:
        raise PasskeyError("credential id mismatch")
    alg, _ = load_cose_key(ad["cose_key"])
    if get_passkey(db, cred_id) is not None:
        raise PasskeyError("credential already registered")

    transports = resp.get("transports")
    if not isinstance(transports, list):
        transports = []
    name = body.get("name")
    if not isinstance(name, str) or not name:
        name = "passkey"
    p = model_passkey.Passkey(
        user=ch["user"],
        credential_id=cred_id,
        user_handle=ch["user_handle"],
        public_key=b64url_encode(ad["cose_key"]),
        alg=alg,
        sign_count=ad["sign_count"],
        transports=",".join(t for t in transports if isinstance(t, str)),
        backup_eligible=1 if ad["flags"] & FLAG_BE else 0,
        backed_up=1 if ad["flags"] & FLAG_BS else 0,
        aaguid=format_aaguid(ad["aaguid"]),
        name=name,
        created_at=utcnow(),
    )
    db.add(p)
    if not skey:
        # 新規アカウント。全体の管理者がまだ誰もいなければ（＝最初の 1 人）全体の管理者、それ以外は一般
        first = admin_count(db) == 0
        db.add(model_passkey.Account(
            user=ch["user"],
            status=ACCOUNT_APPROVED,
            role=ROLE_ADMIN if first else ROLE_MEMBER,
            approved_by=ch["user"],
            approved_at=utcnow(),
            created_at=utcnow()))
    db.commit()
    db.refresh(p)
    res = {"status": "success", "user": ch["user"], "role": role_of(db, ch["user"]),
           "passkey": passkey_to_dict(p)}
    if not skey:
        # 新規アカウントはそのままログイン状態にする
        res["access_token"] = create_session(db, ch["user"])
    return res


def passkey_login_options(db: Session, body: dict, request: Request) -> dict:
    user = body.get("user")
    if not isinstance(user, str):
        user = ""
    allow = [cred_descriptor(p) for p in get_user_passkeys(db, user)] if user else []
    challenge = new_challenge(db, "login", user or None)
    return {
        "status": "success",
        "publicKey": {
            "challenge": challenge,
            "rpId": expected_rp_id(request),
            "timeout": PASSKEY_TIMEOUT_MS,
            "userVerification": "required",
            "allowCredentials": allow,
        },
    }


def passkey_login_verify(db: Session, body: dict, request: Request) -> dict:
    resp = body.get("response")
    cred_id = body.get("id")
    if not isinstance(resp, dict) or not isinstance(cred_id, str) or not cred_id:
        raise PasskeyError("invalid request")
    raw_cd, cd = parse_client_data(resp.get("clientDataJSON"))
    auth_data = b64url_decode(resp.get("authenticatorData"))
    signature = b64url_decode(resp.get("signature"))
    if cd.get("type") != "webauthn.get":
        raise PasskeyError("type mismatch")
    ch = consume_challenge(db, cd, "login")
    check_origin(cd, request)

    p = get_passkey(db, cred_id)
    if p is None:
        raise PasskeyError("unknown credential")
    if ch["user"] and ch["user"] != p.user:
        raise PasskeyError("challenge user mismatch")
    uh = resp.get("userHandle")
    if isinstance(uh, str) and uh and uh != p.user_handle:
        raise PasskeyError("user handle mismatch")

    ad = parse_auth_data(auth_data)
    check_auth_data_common(ad, expected_rp_id(request))
    if not verify_signature(b64url_decode(p.public_key), signature,
                            auth_data + hashlib.sha256(raw_cd).digest()):
        raise PasskeyError("signature invalid")
    # 署名カウンタ。どちらも 0 なら（同期パスキーはだいたいそう）見ない
    if (ad["sign_count"] != 0 or p.sign_count != 0) and ad["sign_count"] <= p.sign_count:
        raise PasskeyError("sign count did not increase")

    p.sign_count = ad["sign_count"]
    p.backed_up = 1 if ad["flags"] & FLAG_BS else 0
    p.last_used_at = utcnow()
    db.commit()
    return {"status": "success", "user": p.user, "role": role_of(db, p.user),
            "access_token": create_session(db, p.user)}


def passkey_me(db: Session, skey: str) -> dict:
    s = get_session(db, skey)
    if s is None:
        raise PasskeyError("not logged in")
    return {"status": "success", "user": s.user, "role": role_of(db, s.user),
            "admin_requested": get_admin_request(db, s.user) is not None,
            "expire": format_time(s.expire)}


def passkey_logout(db: Session, skey: str) -> dict:
    s = get_session(db, skey)
    if s is None:
        raise PasskeyError("not logged in")
    db.delete(s)
    db.commit()
    return {"status": "success"}


def passkey_list(db: Session, skey: str) -> dict:
    user = session_user(db, skey)
    rows = get_user_passkeys(db, user)
    return {
        "status": "success",
        "user": user,
        "passkey_list": [passkey_to_dict(p) for p in rows],
        "columns": [{"field": c, "title": c} for c in PASSKEY_COLUMNS],
        "total_count": len(rows),
    }


# 最後の 1 本を消すとそのアカウントには二度と入れないので、アカウントごと消す（＝退会）
def passkey_delete(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    cred_id = body.get("credential_id")
    if not isinstance(cred_id, str) or not cred_id:
        raise PasskeyError("invalid request")
    p = get_passkey(db, cred_id)
    if p is None or p.user != user:
        raise PasskeyError("unknown credential")
    # 最後の管理者が退会すると誰も承認できなくなるので止める
    if len(get_user_passkeys(db, user)) == 1 and role_of(db, user) == ROLE_ADMIN \
            and admin_count(db) == 1:
        raise PasskeyError("last admin cannot leave")
    db.delete(p)
    db.commit()
    account_deleted = not get_user_passkeys(db, user)
    if account_deleted:
        delete_account(db, user)
    return {"status": "success", "credential_id": cred_id, "account_deleted": account_deleted}


def account_list(db: Session, skey: str) -> dict:
    user = admin_user(db, skey)
    rows = db.query(model_passkey.Account).order_by(model_passkey.Account.id).all()
    return {
        "status": "success",
        "user": user,
        "account_list": [account_to_dict(db, a) for a in rows],
        "total_count": len(rows),
    }


# {user}。全体の管理者を一般に戻す（自分でもよい）。全体の管理者が 1 人もいなくなる変更はできない
def account_demote(db: Session, skey: str, body: dict) -> dict:
    admin_user(db, skey)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    a = get_account(db, target)
    if a is None:
        raise PasskeyError("unknown account")
    if a.role != ROLE_ADMIN:
        raise PasskeyError("not an admin")
    if admin_count(db) == 1:
        raise PasskeyError("last admin cannot be demoted")
    a.role = ROLE_MEMBER
    db.commit()
    return {"status": "success", "account": account_to_dict(db, a)}


#
# 全体の管理者への申請
#

def get_admin_request(db: Session, user: str):
    return db.query(model_passkey.AdminRequest).filter(model_passkey.AdminRequest.user == user).first()


def admin_request_to_dict(db: Session, r) -> dict:
    return {
        "user": r.user,
        "created_at": format_time(r.created_at),
        "passkey_count": len(get_user_passkeys(db, r.user)),
    }


def account_admin_request(db: Session, skey: str) -> dict:
    user = session_user(db, skey)
    if role_of(db, user) == ROLE_ADMIN:
        raise PasskeyError("already admin")
    if get_admin_request(db, user) is not None:
        raise PasskeyError("already requested")
    r = model_passkey.AdminRequest(user=user, created_at=utcnow())
    db.add(r)
    db.commit()
    return {"status": "success", "request": admin_request_to_dict(db, r)}


def account_admin_request_cancel(db: Session, skey: str) -> dict:
    user = session_user(db, skey)
    r = get_admin_request(db, user)
    if r is None:
        raise PasskeyError("unknown request")
    db.delete(r)
    db.commit()
    return {"status": "success", "user": user}


def account_admin_requests(db: Session, skey: str) -> dict:
    admin_user(db, skey)
    rows = db.query(model_passkey.AdminRequest).order_by(model_passkey.AdminRequest.id).all()
    return {
        "status": "success",
        "request_list": [admin_request_to_dict(db, r) for r in rows],
        "total_count": len(rows),
    }


def account_admin_approve(db: Session, skey: str, body: dict) -> dict:
    user = admin_user(db, skey)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    r = get_admin_request(db, target)
    if r is None:
        raise PasskeyError("unknown request")
    a = get_account(db, target)
    db.delete(r)
    a.role = ROLE_ADMIN
    a.approved_by = user
    a.approved_at = utcnow()
    db.commit()
    return {"status": "success", "account": account_to_dict(db, a)}


def account_admin_reject(db: Session, skey: str, body: dict) -> dict:
    admin_user(db, skey)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    r = get_admin_request(db, target)
    if r is None:
        raise PasskeyError("unknown request")
    db.delete(r)
    db.commit()
    return {"status": "success", "user": target}


# 自分以外のアカウントを消す（管理者も消せる。自分は消せないので管理者は 1 人以上残る）。
# 自分のは passkey/delete で最後の 1 本を消す（退会）
def account_delete(db: Session, skey: str, body: dict) -> dict:
    user = admin_user(db, skey)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    if target == user:
        raise PasskeyError("cannot delete yourself")
    if get_account(db, target) is None:
        raise PasskeyError("unknown account")
    delete_account(db, target)
    return {"status": "success", "user": target}


#
# routes
#

async def read_body(request: Request) -> dict:
    try:
        body = await request.json()
        if isinstance(body, dict):
            return body
    except Exception:
        pass
    return {}


def run(db: Session, func, *args) -> dict:
    try:
        return func(db, *args)
    except PasskeyError as e:
        db.rollback()
        return fail(str(e))
    except Exception as e:
        db.rollback()
        print("#### passkey error: " + repr(e), file=sys.stderr)
        return fail("invalid request")


@router.post("/passkey/v0/register_options")
async def api_passkey_register_options(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, passkey_register_options, extract_bearer_token(authorization), body, request)


@router.post("/passkey/v0/register_verify")
async def api_passkey_register_verify(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, passkey_register_verify, extract_bearer_token(authorization), body, request)


@router.post("/passkey/v0/login_options")
async def api_passkey_login_options(request: Request,
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, passkey_login_options, body, request)


@router.post("/passkey/v0/login_verify")
async def api_passkey_login_verify(request: Request,
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, passkey_login_verify, body, request)


@router.post("/passkey/v0/me")
async def api_passkey_me(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, passkey_me, extract_bearer_token(authorization))


@router.post("/passkey/v0/logout")
async def api_passkey_logout(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, passkey_logout, extract_bearer_token(authorization))


@router.post("/passkey/v0/list")
async def api_passkey_list(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, passkey_list, extract_bearer_token(authorization))


@router.post("/passkey/v0/delete")
async def api_passkey_delete(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, passkey_delete, extract_bearer_token(authorization), body)


@router.post("/account/v0/list")
async def api_account_list(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, account_list, extract_bearer_token(authorization))


@router.post("/account/v0/demote")
async def api_account_demote(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, account_demote, extract_bearer_token(authorization), body)


@router.post("/account/v0/admin_request")
async def api_account_admin_request(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, account_admin_request, extract_bearer_token(authorization))


@router.post("/account/v0/admin_request_cancel")
async def api_account_admin_request_cancel(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, account_admin_request_cancel, extract_bearer_token(authorization))


@router.post("/account/v0/admin_requests")
async def api_account_admin_requests(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    return run(db, account_admin_requests, extract_bearer_token(authorization))


@router.post("/account/v0/admin_approve")
async def api_account_admin_approve(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, account_admin_approve, extract_bearer_token(authorization), body)


@router.post("/account/v0/admin_reject")
async def api_account_admin_reject(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, account_admin_reject, extract_bearer_token(authorization), body)


@router.post("/account/v0/delete")
async def api_account_delete(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, account_delete, extract_bearer_token(authorization), body)
