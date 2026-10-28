from sqlalchemy import (
    Column,
    Integer,
    Text,
    DateTime,
    func,
)
from database import Base


# 登録済みのパスキー（認証器 1 つにつき 1 行）
#   credential_id / user_handle / public_key は base64url の文字列
#   public_key は認証器が返した COSE_Key をそのまま入れている
class Passkey(Base):
    __tablename__ = "passkey"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    user = Column(Text, nullable=False)
    credential_id = Column(Text, nullable=False)
    user_handle = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    alg = Column(Integer, nullable=False)
    sign_count = Column(Integer, nullable=False)
    transports = Column(Text)
    backup_eligible = Column(Integer)
    backed_up = Column(Integer)
    aaguid = Column(Text)
    name = Column(Text)
    last_used_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.current_timestamp())
    updated_at = Column(
        DateTime,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )


# 発行したチャレンジ。検証に来たら（成否にかかわらず）消す
#   purpose は "register" / "login"
#   user は register なら発行先、login ならユーザ名指定があったときだけ入る
class PasskeyChallenge(Base):
    __tablename__ = "passkey_challenge"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    challenge = Column(Text, nullable=False)
    purpose = Column(Text, nullable=False)
    user = Column(Text)
    user_handle = Column(Text)
    expire = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.current_timestamp())


# アカウント。status は "approved"（承認済み）/ "pending"（承認待ち）
#   最初の 1 人は登録した時点で approved、2 人目からは承認済みの誰かが approve する
class Account(Base):
    __tablename__ = "account"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    user = Column(Text, nullable=False)
    status = Column(Text, nullable=False)
    approved_by = Column(Text)
    approved_at = Column(DateTime)
    created_at = Column(DateTime)


# ログイン中のセッション。skey が Bearer トークン、expire は naive な UTC
class Session(Base):
    __tablename__ = "session"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    user = Column(Text, nullable=False)
    skey = Column(Text, nullable=False)
    expire = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.current_timestamp())
