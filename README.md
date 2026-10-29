# passkey_server_cpp

パスキー（WebAuthn）でログインするサーバの実装例です。**C++ 版と Python 版が同じ API を提供**します。

- C++ 版は、ほぼヘッダオンリーのライブラリだけで書いています。`main/lambda_server.cpp` を 1 つコンパイルすれば動きます。署名検証には同梱の mbedtls を使います。
- Python 版は FastAPI + SQLAlchemy で書いています。署名検証には cryptography を使います。
- DB は SQLite（既定）と MySQL を切り替えられます。
- デモとして「**テナントごとの電気のスイッチ**」が付いています。テナントのメンバーだけが、そのテナントの電気をオン・オフできます。
- **誰でも登録できます。** 最初に登録した人は「**全体の管理者**」になり、テナントの追加・削除、アカウントの削除、ほかの人を全体の管理者にすることができます。
- テナントは推測できない **GUID の URL**（`/html/index.html?tenant=<GUID>`）で開きます。全体の管理者がテナントを追加し、その URL をテナントの人に渡します。
- URL を開いた人は「参加申請」します。**そのテナントに管理者がまだいなければ、申請した人がそのままテナントの管理者**になります。それ以降の申請は、テナントの管理者が「管理者」か「一般」として承認します（却下・外すのもテナントの管理者だけ）。

```
ブラウザ                                   サーバ
  │  register_options {user}        ──▶  チャレンジを発行（DB に保存、5 分で失効）
  │  navigator.credentials.create()       ↑ 端末が顔・指紋・PIN で本人確認して鍵ペアを作る
  │  register_verify {attestation}  ──▶  検証して「公開鍵」だけを保存 → access_token
  │
  │  login_options                  ──▶  チャレンジを発行
  │  navigator.credentials.get()          ↑ 端末が本人確認して秘密鍵で署名
  │  login_verify {signature}       ──▶  保存してある公開鍵で署名を検証 → access_token
  │
  │  tenant/switch_set {tenant, on} ──▶  そのテナントの承認済みメンバーだけが切り替えられる
```

**生体情報も秘密鍵もサーバには届きません。** サーバが持つのは公開鍵とその付帯情報だけです。画面の「サーバが保存しているもの」で中身をそのまま見られます。

---

## 1. 動かす

パスキーは **https か `localhost`** でしか使えません。rpId に IP アドレスは使えないので、
`http://127.0.0.1:8080` ではなく **`http://localhost:8080`** で開いてください。

### Python 版

```sh
cd src/server_sample/python
pip install -r requirements.txt
python lambda_server.py                 # http://localhost:8080/
```

`POST=8098 python lambda_server.py` のように、環境変数 `POST` でポートを変えられます（C++ 版と同じ変数名です）。

### C++ 版

```sh
# Linux / WSL / Windows の Git Bash（g++）
bash tests/cpp/build_sqlite_server.sh   # build/cpp_sqlite_test/ に出力（1 分ほど）
cd build/cpp_sqlite_test
POST=8080 ./lambda_server_test.exe      # http://localhost:8080/
```

Windows で g++ のビルドを使うと、34 MB 前後の exe ができます。これをウイルス対策ソフトが誤検知して、数秒後に消してしまうことがあります。その場合は、上のスクリプトを 1 度実行してから MSVC でビルドし直してください（1.5 MB の exe になり、消されません）。

```sh
cd build/cpp_sqlite_test
cmd //c "..\..\tests\cpp\build_sqlite_server_msvc.bat"
POST=8080 ./srv_msvc.exe
```

### スマホから試す

スマホから PC の `http://192.168.x.x:8080` を開いても、パスキーは使えません（https ではないうえ、IP アドレスだから）。https のトンネルを使うのが簡単です。

```sh
cloudflared tunnel --url http://localhost:8080      # https://xxxx.trycloudflare.com が出る
```

サーバは `X-Forwarded-Proto` / `X-Forwarded-Host`（無ければ `Host`）から origin と rpId を決めます。そのため、トンネルの URL のままで動きます。固定したいときは次の環境変数を使います。

| 環境変数 | 意味 | 既定 |
|---|---|---|
| `PASSKEY_ORIGIN` | 受け付ける origin（カンマ区切り） | リクエストの Host から作る |
| `PASSKEY_RP_ID` | rpId | origin のホスト名 |
| `PASSKEY_RP_NAME` | 認証器の画面に出るサービス名 | `passkey_server_cpp` |

---

## 2. サーバが保存しているもの

| テーブル | 中身 |
|---|---|
| `passkey` | パスキー 1 つにつき 1 行。`user` / `credential_id` / `user_handle` / `public_key`（COSE_Key を base64url） / `alg` / `sign_count` / `transports` / `backup_eligible` / `backed_up` / `aaguid` / `name` / `last_used_at` |
| `passkey_challenge` | 発行したチャレンジ。検証に来たら成否にかかわらず消す（使い回し防止）。5 分で失効 |
| `account` | アカウント 1 つにつき 1 行。`role` は `admin`（全体の管理者）/ `member`。`status` は常に `approved`（昔の承認制の名残） |
| `session` | ログイン中のトークン（`skey`）。24 時間で失効。アカウントが消えると無効 |
| `tenant` | テナント。`guid`（URL に使うランダムな 32 桁の 16 進数）/ `name` / `created_by` |
| `tenant_member` | テナントのメンバー。`tenant_id` / `user` / `status`（`approved` / `pending`）/ `role`（`admin` / `member`、承認待ちの間は NULL）/ `approved_by` / `approved_at` |
| `switch_state` | テナントの電気。`name = "tenant/<guid>"` / `value` / `updated_by` / `updated_at` |

- パスワードはありません。アカウントの最後のパスキーを消すと、アカウントごと消えます（退会）。
- 古い版の DB で起動すると自動で引き継ぎます。`account` テーブル（や `role` 列）が無かった頃の承認済みユーザーは全体の管理者に、承認待ちだったユーザーは一般になります。
- `user_handle` は認証器に渡す `user.id` です。アカウントごとにランダムな 32 バイトで、個人情報は入れていません。
- 時刻はすべて naive な UTC（`YYYY-MM-DD HH:MM:SS`）で保存します。C++ 版と Python 版が同じ DB を読めます。

---

## 3. API

すべて `POST`、本文は JSON、応答は `{"status": "success", ...}` か `{"status": "fail", "message": "..."}` です。
ログインが必要な API は `Authorization: Bearer <access_token>` を付けて呼びます。

| パス | 認証 | 入力 → 出力 |
|---|---|---|
| `/api/passkey/v0/register_options` | 任意 | トークン無し: `{user}` で**新規アカウント**。トークン有り: **自分にパスキーを追加**。→ `{publicKey}`（`PublicKeyCredentialCreationOptionsJSON`） |
| `/api/passkey/v0/register_verify` | 任意 | `credential.toJSON()` の形 + `name` → `{user, passkey}`。新規アカウントなら `access_token` も返す |
| `/api/passkey/v0/login_options` | 不要 | `{user?}` → `{publicKey}`（`user` を省くと `allowCredentials` が空になり、端末のパスキーから選ぶ） |
| `/api/passkey/v0/login_verify` | 不要 | `credential.toJSON()` の形 → `{user, access_token}` |
| `/api/passkey/v0/me` | 要 | → `{user, role, expire}`（`register_verify` / `login_verify` も `role` を返す） |
| `/api/passkey/v0/logout` | 要 | このトークンのセッションを消す |
| `/api/passkey/v0/list` | 要 | 自分のパスキー一覧 → `{user, passkey_list, columns, total_count}` |
| `/api/passkey/v0/delete` | 要 | `{credential_id}` → `{account_deleted}`。最後の 1 本ならアカウントごと消える（最後の全体の管理者は不可） |
| `/api/account/v0/list` | 全体の管理者 | 全アカウント → `{account_list: [{user, status, role, approved_by, approved_at, created_at, passkey_count}]}` |
| `/api/account/v0/set_role` | 全体の管理者 | `{user, role: "admin" / "member"}`。全体の管理者が 0 人になる変更は不可 |
| `/api/account/v0/delete` | 全体の管理者 | `{user}` で自分以外のアカウントを消す（パスキー・セッション・テナントの所属も消える） |
| `/api/tenant/v0/get` | 任意 | `{tenant}` → `{tenant: {tenant, name, created_by, created_at, member_count, my_status, my_role, on, updated_by, updated_at}}`。名前は誰でも見えるが、`on` などの電気の状態は承認済みメンバーにだけ返す（他は `null`） |
| `/api/tenant/v0/list` | 要 | 全体の管理者は全テナント、それ以外は自分が参加（申請）しているテナント → `{tenant_list}` |
| `/api/tenant/v0/add` | 全体の管理者 | `{name}` → `{tenant}`（`tenant.tenant` が GUID） |
| `/api/tenant/v0/delete` | 全体の管理者 | `{tenant}`。メンバーと電気の状態も消える |
| `/api/tenant/v0/join` | 要 | `{tenant}` で参加申請 → `{member}`。管理者がいないテナントなら、そのまま承認済みの管理者 |
| `/api/tenant/v0/leave` | 要 | `{tenant}` で抜ける（申請の取り下げも）。最後の管理者は、ほかにメンバーがいる間は不可 |
| `/api/tenant/v0/members` | テナントのメンバー | `{tenant}` → `{me, member_list, total_count}` |
| `/api/tenant/v0/approve` | テナントの管理者 | `{tenant, user, role: "admin" / "member"}` |
| `/api/tenant/v0/remove` | テナントの管理者 | `{tenant, user}` で自分以外を外す（承認待ちなら却下） |
| `/api/tenant/v0/switch_set` | テナントのメンバー | `{tenant, on: true/false}` → `{tenant}` |

### 検証していること（失敗時の `message`）

検査の順番と `message` は C++ 版と Python 版で同じです。

| 段階 | 内容 | message |
|---|---|---|
| clientDataJSON | `type` が `webauthn.create` / `webauthn.get` か | `type mismatch` |
| | `challenge` が発行済みで未使用か、期限内か | `challenge not found` / `challenge expired` |
| | チャレンジの発行先と同じユーザか | `challenge user mismatch` |
| | `origin` が期待どおりか、`crossOrigin` でないか | `origin mismatch` |
| authenticatorData | `rpIdHash` = SHA-256(rpId) か | `rpIdHash mismatch` |
| | UP（ユーザがいる）/ UV（本人確認した）が立っているか | `user presence not set` / `user verification not set` |
| 登録 | attested credential data があるか、ID が一致するか | `attested credential data missing` / `credential id mismatch` |
| | 公開鍵が ES256(P-256) か RS256(2048 bit 以上) か、曲線上の点か | `unsupported algorithm` / `invalid public key` |
| | 同じ credential が登録済みでないか、新規の名前が空いているか | `credential already registered` / `user already exists` |
| ログイン | 登録済みの credential か、userHandle が一致するか | `unknown credential` / `user handle mismatch` |
| | 署名が正しいか | `signature invalid` |
| | 署名カウンタが増えているか（どちらも 0 なら見ない） | `sign count did not increase` |
| その他 | 壊れた base64 / JSON / CBOR | `invalid request` |
| | ユーザ名が 1〜64 バイトで制御文字を含まないか | `invalid user name` |
| | トークンが無効・期限切れ・アカウントが消えた | `not logged in` |
| アカウント | 全体の管理者だけの API を一般が呼んだ | `admin only` |
| | `role` が `admin` / `member` でない | `invalid role` |
| | 存在しない / 自分自身 | `unknown account` / `cannot delete yourself` |
| | 全体の管理者が 0 人になる | `last admin cannot be demoted` / `last admin cannot leave` |
| テナント | GUID が無い / 存在しない | `invalid request` / `unknown tenant` |
| | テナント名が 1〜64 バイトでない、同じ名前がある | `invalid tenant name` / `tenant already exists` |
| | 承認済みメンバー / 管理者でない | `tenant member only` / `tenant admin only` |
| | 申請済み / 承認済み / メンバーにいない | `already requested` / `already approved` / `unknown member` |
| | ほかにメンバーがいるのに最後の管理者が抜けようとした | `last admin cannot leave` |

### やっていないこと

- **attestation の検証はしていません**（`attestation: "none"` を要求し、`attStmt` は見ません）。認証器の機種を制限したい場合は、追加の実装が必要です。
- 対応するアルゴリズムは ES256 と RS256 だけです。EdDSA などは `unsupported algorithm` になります。
- レート制限やアカウント回復（パスキーを全部なくした場合）はありません。
- CORS は `*` です。別ドメインのページから使う場合は `PASSKEY_ORIGIN` にそのページの origin を入れてください。

---

## 4. ディレクトリ構成

```
src/server_sample/
├── cpp/
│   ├── main/
│   │   ├── lambda_server.cpp       エントリポイント
│   │   ├── testsv_api_passkey.h    パスキー API（CBOR / COSE / 署名検証 / セッション）
│   │   ├── testsv_api_tenant.h     テナントとテナントごとの電気の API
│   │   ├── lambda_server.h         Bearer の取り出し、CORS
│   │   └── database.h              SQLite / MySQL の切替（#define USE_MYSQL）
│   ├── models/                     sqlpp11 のテーブル定義（*.ddl → ddl2cpp で model_*.h）
│   ├── html/index.html             画面（python/html/ と同じファイル）
│   ├── include/ sqlpp11/ sqlite/ mysql_8_4/ date/ openssl/ gen/   同梱ライブラリ
│   └── build_lambda_image.sh       AWS Lambda 用 zip（MySQL 版）
└── python/
    ├── lambda_server.py            エントリポイント（FastAPI、Lambda では Mangum）
    ├── testsv_api_passkey.py       パスキー API
    ├── testsv_api_tenant.py        テナントとテナントごとの電気の API
    ├── model_passkey.py model_tenant.py model_switch.py   SQLAlchemy のモデル
    ├── database.py                 接続先（既定 SQLite、RDS_PROXY_HOST / DATABASE_URL で切替）
    └── html/index.html

tests/
├── passkey_common.py      C++ / Python 共通のテスト本体（ソフトウェア認証器でブラウザの代わりをする）
├── python/test_passkey.py Python 版を TestClient で叩く
├── cpp/test_passkey.py    起動した C++ 版を HTTP で叩く
└── browser_e2e.py         Chromium の仮想認証器で画面を通しで動かす
```

- **C++ と Python の両方に同じ API を実装すること。** 片方だけ直すのは避けてください。
- `html/index.html` は `cpp/html` と `python/html` に**同じファイル**を置いています。
- C++ のモデルは `models/*.ddl` から生成します（`python ddl2cpp passkey.ddl model_passkey test::passkey`、`make_header.bat` に全部載っています）。`model_*.h` は直接編集しないでください。DDL を変えたら、`testsv_api_*.h` の中の `CREATE TABLE`（MySQL と SQLite の両方）にも同じ変更を入れてください。

### MySQL を使う

- **C++**：`main/database.h` の `#define USE_MYSQL 1` を有効にします（`-DUSE_MYSQL=1` でも可）。接続先は環境変数 `RDS_PROXY_HOST` / `USER_NAME` / `PASSWORD` / `DB_NAME` で渡します。`libmysqlclient`（Linux は `libmysqlclient.so`、Windows は `libmysql.dll`）を実行ファイルの横に置いてください。GPL のバイナリなので、このリポジトリには入れていません。
- **Python**：環境変数 `RDS_PROXY_HOST` があれば MySQL に接続します。`DATABASE_URL` を指定すると、その URL をそのまま使います。

AWS Lambda に載せる場合は、各ディレクトリの `build_lambda_image.sh` で zip を作ります（C++ 版は Lambda Web Adapter 経由）。Lambda ではローカルファイルが残らないので、MySQL（RDS など）を使ってください。**MySQL 版は、コンパイルが通る（`g++ -fsyntax-only -DUSE_MYSQL=1`）ところまでしか確認していません。実際の MySQL への接続と Lambda への配置は未確認です。**

---

## 5. テスト

```sh
# Python 版（SQLite、サーバの起動は不要）
python tests/python/test_passkey.py

# C++ 版（起動したサーバに対して）
cd build/cpp_sqlite_test && rm -f test_db.db && POST=8099 ./srv_msvc.exe &
python ../../tests/cpp/test_passkey.py

# 画面（どちらのサーバでも。Playwright と chromium が要る）
python tests/browser_e2e.py http://localhost:8099
```

`passkey_common.py` はソフトウェアの認証器（P-256 / RSA の鍵を持ち、authenticatorData を組み立てて署名する）を使います。正常系に加えて、改ざん、使い回し、期限切れ、他人の credential、壊れた入力といった拒否系、全体の役割、テナントの追加・参加・承認・電気・外す・抜ける・削除も確認します（C++ / Python とも 188 項目）。`browser_e2e.py` は Chromium の仮想認証器（DevTools Protocol の `WebAuthn` ドメイン）を使い、全体の管理者がテナントを追加 → URL を開いた人が参加して自動でテナントの管理者 → 別の人が参加申請 → テナントの管理者が一般として承認 → 電気を切り替えて相手の画面に反映 → 全体の管理者にはテナントの電気が見えない → メンバーを外す → 全体の管理者を増やす → テナント削除 → ログアウト・ログイン → 退会までを、3 人分のブラウザで画面から通します。**DB が空のサーバ**に対して実行してください。

---

## 6. 今後やりたいこと

- テナントに電気を複数持たせる（部屋ごとなど）
- テナントの管理者が、承認済みメンバーの役割（管理者 / 一般）をあとから変える機能
- テナントの URL（GUID）を作り直す機能（URL が漏れたとき用）
- MySQL での実際の動作確認と、AWS Lambda への配置の確認

---

## 7. ライセンス

このリポジトリのコードは [MIT License](LICENSE) です。同梱ライブラリは、それぞれ下の表のライセンスに従います。

## 8. 同梱ライブラリ

| ディレクトリ | ライブラリ | ライセンス |
|---|---|---|
| `cpp/main/httplib*.h` | cpp-httplib | MIT |
| `cpp/main/json.hpp` | nlohmann/json | MIT |
| `cpp/main/picosha2.h` | PicoSHA2 | MIT |
| `cpp/main/mbedtlspp.hpp`, `cpp/include/` | Mbed TLS 3.6（ヘッダオンリー化したもの） | Apache-2.0 |
| `cpp/sqlpp11/` | sqlpp11 | BSD-2-Clause |
| `cpp/date/` | Howard Hinnant's date | MIT |
| `cpp/sqlite/` | SQLite | Public Domain |
| `cpp/mysql_8_4/`, `cpp/postgre_17/` | MySQL / PostgreSQL のクライアントヘッダ | 各ライセンス |
| `cpp/lambda-adapter` | AWS Lambda Web Adapter | Apache-2.0 |
