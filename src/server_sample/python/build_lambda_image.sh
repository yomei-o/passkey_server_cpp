#!/bin/bash
#
# AWS Lambda（Python ランタイム、x86_64）用の zip を作る。
#
#   bash build_lambda_image.sh                     # python3.14 用
#   PYTHON_VERSION=3.12 bash build_lambda_image.sh # 関数のランタイムに合わせる
#
# Linux 用のライブラリ（manylinux の wheel）を pip で集めるだけなので、Windows の Git Bash でも
# WSL でも作れる。出力は build_image.zip。
# ハンドラは lambda_server.handler でも lambda_function.lambda_handler（作成時の既定）でもよい。
#
set -e  # エラー時にスクリプトを停止

PYTHON_VERSION="${PYTHON_VERSION:-3.14}"
# Windows の python3 は Microsoft Store のエイリアス（実体なし）のことがあるので、-V が通る方を使う
PY=""
for c in python3 python; do
    if "$c" -V 2>&1 | grep -q '^Python 3'; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "python3 が見つからない" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

rm -rf image build_image.zip
mkdir image

echo "Installing Lambda dependencies for python $PYTHON_VERSION ..."
"$PY" -m pip install -q \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_28_x86_64 \
    --platform manylinux_2_34_x86_64 \
    --implementation cp \
    --python-version "$PYTHON_VERSION" \
    --only-binary=:all: \
    --target image \
    -r requirements.txt

cp ./*.py image/
cp -r html image/
rm -rf image/__pycache__

echo "Creating Lambda deployment package..."
# zip コマンドが無い環境（Git Bash）でも作れるよう Python の zipfile を使う
"$PY" - <<'PYEOF'
import os, zipfile
with zipfile.ZipFile("build_image.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk("image"):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            path = os.path.join(root, f)
            z.write(path, os.path.relpath(path, "image"))
print("build_image.zip: %.1f MB" % (os.path.getsize("build_image.zip") / 1e6))
PYEOF
echo "Build completed: $HERE/build_image.zip"
