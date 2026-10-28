"""Python 版サーバのテストの共通初期化。

- `src/server_sample/python` を import できるようにする
- `DATABASE_URL` が未設定なら SQLite を使う（本番の MySQL を触らないため）

**`database` を import する前に `setup()` を呼ぶ必要がある**（database.py は
import 時に engine を作るので、後から DATABASE_URL を変えても効かない）。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SERVER = os.path.join(REPO, "src", "server_sample", "python")


def setup(db_name, fresh=True):
    """DATABASE_URL を決めて sys.path を通す。決まった URL を返す。

    db_name : 自動生成する SQLite ファイル名（このディレクトリに作る）
    fresh   : True なら既存の SQLite ファイルを消してから始める
              （DATABASE_URL を外から指定した場合は消さない）
    """
    if os.environ.get("DATABASE_URL"):
        url = os.environ["DATABASE_URL"]
    else:
        path = os.path.join(HERE, db_name)
        if fresh and os.path.exists(path):
            os.remove(path)
        url = "sqlite:///" + path.replace("\\", "/")
        os.environ["DATABASE_URL"] = url

    if SERVER not in sys.path:
        sys.path.insert(0, SERVER)
    return url


def utcnow():
    """session.expire は naive な UTC で保存されているので、比較もこれで行う。
    ローカル時刻で比較すると JST では 9 時間ずれて落ちる。"""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class Checker:
    """PASS/FAIL を数えるだけの小さなヘルパ"""

    def __init__(self):
        self.fails = []

    def __call__(self, cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        if not cond:
            self.fails.append(msg)
        return cond

    def finish(self):
        print("")
        print("%d failure(s)" % len(self.fails))
        for f in self.fails:
            print("  -", f)
        return 1 if self.fails else 0
