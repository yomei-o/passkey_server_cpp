#
# みんなの電気のスイッチ（パスキーでログインした人だけが切り替えられる）
#
#   /api/switch/v0/get    いまの状態。誰でも見られる
#   /api/switch/v0/set    {on: true/false} で切り替える。承認済みのアカウントでログインしていること
#
# C++ 版は cpp/main/testsv_api_switch.h。
#
from fastapi import APIRouter, Request, Header, Depends
from sqlalchemy.orm import Session

from database import engine
import model_switch
from testsv_api_passkey import (
    PasskeyError,
    extract_bearer_token,
    format_time,
    get_db,
    read_body,
    run,
    approved_user,
    utcnow,
)

router = APIRouter()

SWITCH_NAME = "light"


def init_switch():
    print("init_switch()")
    model_switch.Base.metadata.create_all(bind=engine)

init_switch()


def get_state(db: Session):
    return db.query(model_switch.SwitchState).filter(
        model_switch.SwitchState.name == SWITCH_NAME).first()


def state_to_dict(s) -> dict:
    if s is None:
        return {"status": "success", "on": False, "updated_by": None, "updated_at": None}
    return {
        "status": "success",
        "on": s.value == 1,
        "updated_by": s.updated_by,
        "updated_at": format_time(s.updated_at),
    }


def switch_get(db: Session) -> dict:
    return state_to_dict(get_state(db))


def switch_set(db: Session, skey: str, body: dict) -> dict:
    user = approved_user(db, skey)
    on = body.get("on")
    if not isinstance(on, bool):
        raise PasskeyError("invalid request")
    s = get_state(db)
    if s is None:
        s = model_switch.SwitchState(name=SWITCH_NAME)
        db.add(s)
    s.value = 1 if on else 0
    s.updated_by = user
    s.updated_at = utcnow()
    db.commit()
    return state_to_dict(s)


@router.post("/switch/v0/get")
async def api_switch_get(request: Request,
    db: Session = Depends(get_db),
    ):
    return run(db, switch_get)


@router.post("/switch/v0/set")
async def api_switch_set(request: Request,
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    ):
    body = await read_body(request)
    return run(db, switch_set, extract_bearer_token(authorization), body)
