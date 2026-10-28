#!/bin/bash
set -e  # エラー時にスクリプトを停止

export CC="gcc"
export CXX="g++"

#arm windows
if [ "$(uname -m)" = "aarch64" ]; then
export CC="x86_64-linux-gnu-gcc"	
export CXX="x86_64-linux-gnu-g++"
fi

echo "Compiling Lambda Server..."

# Lambda ではファイルが消えるので MySQL（RDS など）を使う。接続先は Lambda の環境変数
# RDS_PROXY_HOST / USER_NAME / PASSWORD / DB_NAME で渡す（main/database.h）
${CXX} -o lambda_server -DUSE_MYSQL=1 main/lambda_server.cpp gen/mysql_dynamic_loading.cpp \
    -pthread -ldl -Wl,-rpath,. --std=c++2a \
    -I main -I gen -I date -I models -I mysql_8_4 -I sqlpp11 -I include -I openssl -I date

chmod a+x lambda_server
chmod a+x bootstrap
chmod a+x lambda-adapter

echo "Copyging files..."

rm -r -f image
mkdir image
cd image
mkdir lib
cp -r ../html .

cp ../lambda_server .
# libmysqlclient.so はリポジトリに入れていない（GPL のバイナリのため）。
# MySQL 8.x の Linux x86_64 用クライアントから、このディレクトリに置いておくこと
if ! ls ../libmysqlclient.so >/dev/null 2>&1; then
    echo "libmysqlclient.so をこのディレクトリに置いてください" >&2
    exit 1
fi
cp ../lib*.so lib/
cp ../bootstrap .
cp ../lambda-adapter .

# zipファイルを作成（上位ディレクトリに）
echo "Creating Lambda deployment package..."
# zip -r は既存zipに追記するため、必ず消してから作り直す
rm -f ../build_image.zip
zip -r ../build_image.zip * 
echo "Build completed: build_image.zip"
