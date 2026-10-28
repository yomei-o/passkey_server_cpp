"""passkey API（Python 版 / SQLite）

中身は tests/passkey_common.py（C++ 版と共通）。

    python tests/python/test_passkey.py
"""
import os
import sys

import _bootstrap
print("db:", _bootstrap.setup("test_passkey.db"))
sys.path.insert(0, os.path.join(_bootstrap.HERE, ".."))

from fastapi import FastAPI
from fastapi.testclient import TestClient
import testsv_api_passkey as P
import testsv_api_switch as S
import passkey_common

app = FastAPI()
app.include_router(P.router, prefix="/api")
app.include_router(S.router, prefix="/api")
client = TestClient(app)


def post(path, body, token=None):
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    return client.post(path, json=body, headers=h).json()


db_path = os.environ["DATABASE_URL"][len("sqlite:///"):]
ck = _bootstrap.Checker()
passkey_common.run(ck, post, db_path, "http://testserver")
sys.exit(ck.finish())
