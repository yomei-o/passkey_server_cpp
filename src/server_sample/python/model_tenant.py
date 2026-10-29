from sqlalchemy import (
    Column,
    Integer,
    Text,
    DateTime,
)
from database import Base


# テナント。外からは guid（ランダムな 32 桁の 16 進数）で指定する。
# ページの URL は /html/index.html?tenant=<guid>。電気のスイッチを 1 つ持つ
# （switch_state の name = "tenant/<guid>"）
class Tenant(Base):
    __tablename__ = "tenant"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    guid = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    created_by = Column(Text)
    created_at = Column(DateTime)


# テナントのメンバー。1 人が複数のテナントに入れる
#   status は "approved" / "pending"、role は "admin" / "member"（承認待ちの間は NULL）
#   そのテナントに管理者がいないときに参加申請した人は、そのまま承認済みの管理者になる
class TenantMember(Base):
    __tablename__ = "tenant_member"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    tenant_id = Column(Integer, nullable=False)
    user = Column(Text, nullable=False)
    status = Column(Text, nullable=False)
    role = Column(Text)
    approved_by = Column(Text)
    approved_at = Column(DateTime)
    created_at = Column(DateTime)
