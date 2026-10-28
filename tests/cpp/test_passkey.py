"""passkey API（C++ 版 / SQLite）

中身は tests/passkey_common.py（Python 版と共通）。先に C++ サーバ（SQLite ビルド）を起動しておくこと:

    bash tests/cpp/build_sqlite_server.sh        # ビルド
    cd build/cpp_sqlite_test && POST=8099 ./lambda_server_test.exe

そのうえで、サーバの作業ディレクトリで:

    python ../../tests/cpp/test_passkey.py

別の場所から実行する場合は CPP_TEST_URL / CPP_TEST_DB を指定する。
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

import passkey_common
from _bootstrap import Checker

# 起動済みの C++ サーバの URL と、そのサーバが使っている SQLite ファイル
B = os.environ.get("CPP_TEST_URL", "http://127.0.0.1:8099")
DB = os.environ.get("CPP_TEST_DB", "test_db.db")


def post(path, body, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(B + path, data=json.dumps(body).encode(), headers=h)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


ck = Checker()
passkey_common.run(ck, post, DB, B)
sys.exit(ck.finish())
