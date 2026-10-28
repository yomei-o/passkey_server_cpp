# tests

C++ 版と Python 版が**同じ挙動になっていること**を確認するためのスクリプトです。
pytest などは使っていません。素の Python スクリプトで `PASS` / `FAIL` を出し、失敗があれば終了コード 1 を返します。

```
tests/
├── passkey_common.py      テスト本体（両言語で共通）。ソフトウェア認証器と、確認する項目の一覧
├── python/test_passkey.py Python 版を SQLite で直接叩く（TestClient）
├── cpp/test_passkey.py    起動した C++ 版（SQLite ビルド）を HTTP で叩く
├── cpp/build_sqlite_server.sh       C++ 版を g++ でビルド
├── cpp/build_sqlite_server_msvc.bat C++ 版を MSVC でビルド
└── browser_e2e.py         画面を Chromium の仮想認証器で通しで動かす
```

片方だけ通っても意味がないので、**両方を実行してください**。依存は `cryptography`（テスト側のソフトウェア認証器が使う）、Python 版はさらに `fastapi sqlalchemy httpx` です。

## Python 版

```sh
python tests/python/test_passkey.py
```

SQLite のファイルは `tests/python/test_passkey.db` に作られ、実行のたびに作り直されます。

## C++ 版

```sh
bash tests/cpp/build_sqlite_server.sh          # build/cpp_sqlite_test/ に出る（1 分ほど）
cd build/cpp_sqlite_test
rm -f test_db.db
POST=8099 ./lambda_server_test.exe &           # ポートは POST（PORT ではない）
python ../../tests/cpp/test_passkey.py
```

Windows では g++ の exe をウイルス対策ソフトが消すことがあります。その場合は、同じディレクトリで
`cmd //c "..\..\tests\cpp\build_sqlite_server_msvc.bat"` を実行して `srv_msvc.exe` を使ってください。

テストは、サーバと同じ SQLite ファイル（既定はカレントディレクトリの `test_db.db`）を直接書き換えて、期限切れなどを作ります。
別の場所から実行するときは、`CPP_TEST_URL` / `CPP_TEST_DB` を指定してください。

## 画面

```sh
pip install playwright && playwright install chromium
python tests/browser_e2e.py http://localhost:8099 [スクリーンショット.png]
```

rpId に IP アドレスは使えないので、`127.0.0.1` ではなく `localhost` で開いてください。

## 確認していること

| 区分 | 主な項目 |
|---|---|
| 新規登録 | options の中身（rp.id / user.id 32 バイト / challenge 32 バイト / ES256・RS256 / UV 必須）、ユーザ名の検査、保存される列、名前の重複（options の後で先を越された場合も） |
| 登録の拒否 | origin・type・rpIdHash・UP・UV・AT フラグ・credential ID の不一致、登録済み credential、未知・期限切れ・使用済みのチャレンジ、他人のチャレンジ |
| 追加 | ログイン中のアカウントへの追加（同じ user.id、excludeCredentials） |
| ログイン | ユーザ名あり / なし（discoverable）、ES256 / RS256、使い回し、改ざんした署名、未知の credential、userHandle の不一致、署名カウンタの巻き戻り |
| セッション | me / logout / 期限切れ |
| 一覧・削除 | 自分の分だけ見える、他人のものは消せない |
| 壊れた入力 | base64 / JSON / CBOR の破損、P-256 以外の曲線、曲線上にない点 |
| スイッチ | 未ログインでは切り替えられない、切り替えた人と時刻が全員に見える |
