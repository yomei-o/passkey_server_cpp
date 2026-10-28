#!/bin/bash
#
# ローカル検証用に C++ サーバの SQLite 版をビルドする。
#
#   bash tests/cpp/build_sqlite_server.sh [出力ディレクトリ]
#
# MySQL/SQLite の切替は main/database.h の #define USE_MYSQL で決まる（既定は
# SQLite）。MySQL に切り替えてあっても SQLite でビルドできるよう、main/ を
# 出力ディレクトリにコピーしてそちら側だけ書き換える。
# 検証に不要な test_db は外してある。
#
# ビルド後:
#   cd <出力ディレクトリ> && POST=8099 ./lambda_server_test.exe
#   （html/ を配るので、必要なら cpp/html をコピーしておく）
#
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CPP="$REPO/src/server_sample/cpp"
OUT="${1:-$REPO/build/cpp_sqlite_test}"

mkdir -p "$OUT"
cd "$OUT"
echo "### output: $OUT"

rm -rf main
cp -r "$CPP/main" .

python - <<'PYEOF'
# 改行は環境次第（Windows でクローンすると作業ツリーが CRLF になる）
d = open('main/database.h', 'rb').read()
for nl in (b'\r\n', b'\n'):
    old = nl + b'#define USE_MYSQL 1'
    if d.count(old) == 1:
        d = d.replace(old, nl + b'//#define USE_MYSQL 1  (test build: sqlite)')
        break
# 既定が SQLite（コメントアウト済み）ならそのまま
assert (nl + b'#define USE_MYSQL') not in d
open('main/database.h', 'wb').write(d)

d = open('main/lambda_server.cpp', 'rb').read()
for m in (b'ENABLE_API_TEST_DB 1',):
    d = d.replace(b'#define ' + m, b'//#define ' + m)
open('main/lambda_server.cpp', 'wb').write(d)
print('patched main/database.h (sqlite) and main/lambda_server.cpp')
PYEOF

if [ ! -f sqlite3.o ]; then
    echo "### compiling sqlite3.c (初回のみ)"
    gcc -c -O1 -o sqlite3.o "$CPP/sqlite/sqlite3.c" -I"$CPP/sqlite" -DSQLITE_THREADSAFE=1
fi

# -Wa,-mbig-obj が無いと Windows/gcc で "too many sections" になる
echo "### compiling lambda_server (1〜2分かかる)"
BIGOBJ=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) BIGOBJ="-Wa,-mbig-obj"; LIBS="-lws2_32 -lbcrypt" ;;
    *)                    LIBS="-pthread -ldl" ;;
esac

g++ $BIGOBJ -o lambda_server_test.exe main/lambda_server.cpp sqlite3.o --std=c++2a \
    -I main -I "$CPP/gen" -I "$CPP/date" -I "$CPP/models" -I "$CPP/sqlpp11" \
    -I "$CPP/sqlite" -I "$CPP/include" -I "$CPP/openssl" $LIBS

mkdir -p html
cp -r "$CPP/html/." html/

echo
echo "### done: $OUT/lambda_server_test.exe"
echo "起動:  cd $OUT && rm -f test_db.db && POST=8099 ./lambda_server_test.exe"
echo "テスト: cd $OUT && python $REPO/tests/cpp/test_passkey.py"
