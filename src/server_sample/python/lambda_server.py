import os

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

import uvicorn
from mangum import Mangum

from testsv_api_passkey import router as passkey_router
from testsv_api_tenant import router as tenant_router


app = FastAPI()
handler = Mangum(app)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/html", StaticFiles(directory="html"), name="static")


@app.get("/")
def root():
    return RedirectResponse(url="/html/index.html")


app.include_router(passkey_router, prefix="/api")
app.include_router(tenant_router, prefix="/api")


if __name__ == "__main__":
    # ポートは C++ 版と同じく環境変数 POST（既定 8080）
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("POST", "8080")), log_level="info")
