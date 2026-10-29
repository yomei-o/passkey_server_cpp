# AWS Lambda の既定のハンドラ名（lambda_function.lambda_handler）のための入口。
# 関数を作ったときのハンドラ設定のままで動くように、lambda_server の Mangum をそのまま渡す。
from lambda_server import handler as lambda_handler  # noqa: F401
