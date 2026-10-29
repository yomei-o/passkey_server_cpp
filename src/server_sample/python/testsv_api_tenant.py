#
# テナントと、テナントごとの電気のスイッチ
#
# テナントは guid（ランダムな 32 桁の 16 進数）で指定する。ページの URL は /html/index.html?tenant=<guid>。
# 全体の管理者がテナントを追加して、その URL をテナントの人に渡す。
#
#   /api/tenant/v0/get          {tenant} のテナント名と自分の立場（ログインしていなくても名前は見える。
#                               電気の状態は承認済みメンバーにだけ見せる）
#   /api/tenant/v0/list         全体の管理者は全テナント、それ以外は自分が参加（申請）しているテナント
#   /api/tenant/v0/add          テナントを追加する（全体の管理者だけ）
#   /api/tenant/v0/delete       テナントを消す（全体の管理者だけ。メンバーと電気も消える）
#
#   /api/tenant/v0/join         テナントに参加申請する（ログインしていれば誰でも）
#   /api/tenant/v0/leave        テナントを抜ける（申請の取り下げも）
#   /api/tenant/v0/members      テナントのメンバー一覧（そのテナントの承認済みメンバーだけ）
#   /api/tenant/v0/approve      申請を管理者 / 一般として承認する（そのテナントの管理者だけ）
#   /api/tenant/v0/remove       自分以外のメンバーを外す（そのテナントの管理者だけ。承認待ちなら却下）
#   /api/tenant/v0/switch_set   テナントの電気を切り替える（そのテナントの承認済みメンバーだけ）
#
# テナントに管理者がいないときに参加申請した人（＝最初の 1 人）は、そのまま承認済みの管理者になる。
# C++ 版は cpp/main/testsv_api_tenant.h。検査の順番と失敗時の message を揃えてある。
#
import secrets

from fastapi import APIRouter, Request, Header, Depends
from sqlalchemy.orm import Session

from database import engine
import model_switch
import model_tenant
from testsv_api_passkey import (
    ACCOUNT_APPROVED,
    ACCOUNT_PENDING,
    ROLE_ADMIN,
    ROLE_MEMBER,
    PasskeyError,
    admin_user,
    extract_bearer_token,
    format_time,
    get_db,
    get_session,
    read_body,
    role_of,
    run,
    session_user,
    utcnow,
    valid_user_name,
)

router = APIRouter()


def init_tenant():
    print("init_tenant()")
    model_tenant.Base.metadata.create_all(bind=engine)
    model_switch.Base.metadata.create_all(bind=engine)

init_tenant()


def switch_name(guid: str) -> str:
    return "tenant/" + guid


def get_tenant(db: Session, body: dict):
    guid = body.get("tenant")
    if not isinstance(guid, str) or not guid:
        raise PasskeyError("invalid request")
    t = db.query(model_tenant.Tenant).filter(model_tenant.Tenant.guid == guid).first()
    if t is None:
        raise PasskeyError("unknown tenant")
    return t


def get_member(db: Session, tenant_id: int, user: str):
    return db.query(model_tenant.TenantMember).filter(
        model_tenant.TenantMember.tenant_id == tenant_id,
        model_tenant.TenantMember.user == user).first()


def tenant_admin_count(db: Session, tenant_id: int) -> int:
    return db.query(model_tenant.TenantMember).filter(
        model_tenant.TenantMember.tenant_id == tenant_id,
        model_tenant.TenantMember.status == ACCOUNT_APPROVED,
        model_tenant.TenantMember.role == ROLE_ADMIN).count()


def member_to_dict(m) -> dict:
    return {
        "user": m.user,
        "status": m.status,
        "role": m.role,
        "approved_by": m.approved_by,
        "approved_at": format_time(m.approved_at),
        "created_at": format_time(m.created_at),
    }


# そのテナントの承認済みメンバーだけ
def tenant_member_of(db: Session, tenant_id: int, user: str):
    m = get_member(db, tenant_id, user)
    if m is None or m.status != ACCOUNT_APPROVED:
        raise PasskeyError("tenant member only")
    return m


# そのテナントの管理者だけ
def tenant_admin_of(db: Session, tenant_id: int, user: str):
    m = get_member(db, tenant_id, user)
    if m is None or m.status != ACCOUNT_APPROVED or m.role != ROLE_ADMIN:
        raise PasskeyError("tenant admin only")
    return m


def get_switch(db: Session, guid: str):
    return db.query(model_switch.SwitchState).filter(
        model_switch.SwitchState.name == switch_name(guid)).first()


# 電気の状態はそのテナントの承認済みメンバーにだけ見せる（他は null）。user は空でもよい
def tenant_to_dict(db: Session, t, user: str) -> dict:
    m = get_member(db, t.id, user) if user else None
    d = {
        "tenant": t.guid,
        "name": t.name,
        "created_by": t.created_by,
        "created_at": format_time(t.created_at),
        "member_count": db.query(model_tenant.TenantMember).filter(
            model_tenant.TenantMember.tenant_id == t.id,
            model_tenant.TenantMember.status == ACCOUNT_APPROVED).count(),
        "my_status": m.status if m is not None else None,
        "my_role": m.role if m is not None else None,
        "on": None,
        "updated_by": None,
        "updated_at": None,
    }
    if m is not None and m.status == ACCOUNT_APPROVED:
        s = get_switch(db, t.guid)
        d["on"] = s is not None and s.value == 1
        d["updated_by"] = s.updated_by if s is not None else None
        d["updated_at"] = format_time(s.updated_at) if s is not None else None
    return d


#
# テナント
#

# ログインしていなくてもテナント名は見える（URL を開いた人に何のテナントか見せるため）
def tenant_get(db: Session, skey: str, body: dict) -> dict:
    s = get_session(db, skey) if skey else None
    if skey and s is None:
        raise PasskeyError("not logged in")
    t = get_tenant(db, body)
    return {"status": "success", "tenant": tenant_to_dict(db, t, s.user if s else "")}


def tenant_list(db: Session, skey: str) -> dict:
    user = session_user(db, skey)
    q = db.query(model_tenant.Tenant)
    if role_of(db, user) != ROLE_ADMIN:
        ids = [m.tenant_id for m in db.query(model_tenant.TenantMember).filter(
            model_tenant.TenantMember.user == user)]
        q = q.filter(model_tenant.Tenant.id.in_(ids))
    rows = q.order_by(model_tenant.Tenant.id).all()
    return {
        "status": "success",
        "user": user,
        "tenant_list": [tenant_to_dict(db, t, user) for t in rows],
        "total_count": len(rows),
    }


# テナント名はユーザ名と同じ規則（1〜64 バイト、制御文字なし）。同じ名前は作れない
def tenant_add(db: Session, skey: str, body: dict) -> dict:
    user = admin_user(db, skey)
    name = body.get("name")
    if not valid_user_name(name):
        raise PasskeyError("invalid tenant name")
    if db.query(model_tenant.Tenant).filter(model_tenant.Tenant.name == name).first() is not None:
        raise PasskeyError("tenant already exists")
    t = model_tenant.Tenant(guid=secrets.token_hex(16), name=name, created_by=user, created_at=utcnow())
    db.add(t)
    db.commit()
    return {"status": "success", "tenant": tenant_to_dict(db, t, user)}


def tenant_delete(db: Session, skey: str, body: dict) -> dict:
    admin_user(db, skey)
    t = get_tenant(db, body)
    guid = t.guid
    db.query(model_tenant.TenantMember).filter(model_tenant.TenantMember.tenant_id == t.id).delete()
    db.query(model_switch.SwitchState).filter(model_switch.SwitchState.name == switch_name(guid)).delete()
    db.delete(t)
    db.commit()
    return {"status": "success", "tenant": guid}


#
# メンバー
#

def tenant_join(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    if get_member(db, t.id, user) is not None:
        raise PasskeyError("already requested")
    # このテナントに管理者がまだいなければ（＝最初の 1 人）そのまま承認済みの管理者
    first = tenant_admin_count(db, t.id) == 0
    m = model_tenant.TenantMember(
        tenant_id=t.id,
        user=user,
        status=ACCOUNT_APPROVED if first else ACCOUNT_PENDING,
        role=ROLE_ADMIN if first else None,
        approved_by=user if first else None,
        approved_at=utcnow() if first else None,
        created_at=utcnow())
    db.add(m)
    db.commit()
    return {"status": "success", "member": member_to_dict(m)}


# 抜ける（承認待ちなら取り下げ）。最後の管理者は、他にメンバーがいる間は抜けられない
def tenant_leave(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    m = get_member(db, t.id, user)
    if m is None:
        raise PasskeyError("unknown member")
    others = db.query(model_tenant.TenantMember).filter(
        model_tenant.TenantMember.tenant_id == t.id,
        model_tenant.TenantMember.user != user).count()
    if m.status == ACCOUNT_APPROVED and m.role == ROLE_ADMIN and tenant_admin_count(db, t.id) == 1 \
            and others > 0:
        raise PasskeyError("last admin cannot leave")
    db.delete(m)
    db.commit()
    return {"status": "success", "tenant": t.guid}


def tenant_members(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    me = tenant_member_of(db, t.id, user)
    rows = db.query(model_tenant.TenantMember).filter(
        model_tenant.TenantMember.tenant_id == t.id).order_by(model_tenant.TenantMember.id).all()
    return {
        "status": "success",
        "tenant": t.guid,
        "me": member_to_dict(me),
        "member_list": [member_to_dict(m) for m in rows],
        "total_count": len(rows),
    }


# {tenant, user, role}。role は "admin"（管理者）か "member"（一般）
def tenant_approve(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    tenant_admin_of(db, t.id, user)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    role = body.get("role")
    if role not in (ROLE_ADMIN, ROLE_MEMBER):
        raise PasskeyError("invalid role")
    m = get_member(db, t.id, target)
    if m is None:
        raise PasskeyError("unknown member")
    if m.status == ACCOUNT_APPROVED:
        raise PasskeyError("already approved")
    m.status = ACCOUNT_APPROVED
    m.role = role
    m.approved_by = user
    m.approved_at = utcnow()
    db.commit()
    return {"status": "success", "member": member_to_dict(m)}


# 自分以外を外す（承認待ちなら却下）。自分は外せないので、そのテナントの管理者は 1 人以上残る
def tenant_remove(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    tenant_admin_of(db, t.id, user)
    target = body.get("user")
    if not isinstance(target, str) or not target:
        raise PasskeyError("invalid request")
    if target == user:
        raise PasskeyError("cannot delete yourself")
    m = get_member(db, t.id, target)
    if m is None:
        raise PasskeyError("unknown member")
    db.delete(m)
    db.commit()
    return {"status": "success", "user": target}


def tenant_switch_set(db: Session, skey: str, body: dict) -> dict:
    user = session_user(db, skey)
    t = get_tenant(db, body)
    tenant_member_of(db, t.id, user)
    on = body.get("on")
    if not isinstance(on, bool):
        raise PasskeyError("invalid request")
    s = get_switch(db, t.guid)
    if s is None:
        s = model_switch.SwitchState(name=switch_name(t.guid))
        db.add(s)
    s.value = 1 if on else 0
    s.updated_by = user
    s.updated_at = utcnow()
    db.commit()
    return {"status": "success", "tenant": tenant_to_dict(db, t, user)}


#
# routes
#

def route(path, func, with_body=True):
    async def handler(request: Request,
                      authorization: str = Header(None),
                      db: Session = Depends(get_db)):
        skey = extract_bearer_token(authorization)
        if with_body:
            return run(db, func, skey, await read_body(request))
        return run(db, func, skey)
    handler.__name__ = "api_tenant_" + func.__name__
    router.post(path)(handler)


route("/tenant/v0/get", tenant_get)
route("/tenant/v0/list", tenant_list, with_body=False)
route("/tenant/v0/add", tenant_add)
route("/tenant/v0/delete", tenant_delete)
route("/tenant/v0/join", tenant_join)
route("/tenant/v0/leave", tenant_leave)
route("/tenant/v0/members", tenant_members)
route("/tenant/v0/approve", tenant_approve)
route("/tenant/v0/remove", tenant_remove)
route("/tenant/v0/switch_set", tenant_switch_set)
