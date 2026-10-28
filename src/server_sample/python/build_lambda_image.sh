#!/bin/bash
set -e  # エラー時にスクリプトを停止

#arm windows
if [ "$(uname -m)" = "aarch64" ]; then
export CC="x86_64-linux-gnu-gcc"
export CXX="x86_64-linux-gnu-g++"
fi


rm -r -f image
mkdir image
cd image
cp -r ../html .

echo "Installing Lambda dependencies..."

# Lambda用の基本パッケージ
# pip3 ではなく python3 -m pip。WSL の /usr/bin/pip3 は Python 3.8 時代の
# easy-install スクリプトで、3.12 に上がった環境では pkg_resources が無くて
# 動かない（実際に踏んだ）。
PIP="python3 -m pip"
$PIP install starlette==0.50.0 fastapi uvicorn mangum -t .

# プラットフォーム固有のパッケージを統一してインストール
$PIP install \
    --platform manylinux2014_x86_64 \
    --target=. \
    --implementation cp \
    --python-version 3.12 \
    --only-binary=:all: \
    --upgrade \
    pydantic \
    mysql-connector-python \
    SQLAlchemy \
    requests \
    jinja2 \
    pymysql \
    cryptography \
    requests

echo "Dependencies installed successfully"


cp ../*.py .

# zipファイルを作成（上位ディレクトリに）
echo "Creating Lambda deployment package..."
# zip -r は既存zipに追記するため、必ず消してから作り直す
rm -f ../build_image.zip
zip -r ../build_image.zip * 
echo "Build completed: build_image.zip created in impl/ directory"
