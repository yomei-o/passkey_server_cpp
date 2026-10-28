from sqlalchemy import (
    Column,
    Integer,
    Text,
    DateTime,
)
from database import Base


# みんなで共有するスイッチ。name ごとに 1 行（いまは "light" だけ）
#   value は 0 / 1、updated_by は最後に切り替えたユーザ、updated_at は naive な UTC
class SwitchState(Base):
    __tablename__ = "switch_state"

    id = Column(Integer, primary_key=True, autoincrement=True, comment="ID")
    name = Column(Text, nullable=False)
    value = Column(Integer, nullable=False)
    updated_by = Column(Text)
    updated_at = Column(DateTime)
