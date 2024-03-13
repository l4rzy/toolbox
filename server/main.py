from fastapi import FastAPI
import uvicorn

from pydantic import BaseModel
from typing import Dict


class TunnelObject(BaseModel):
    url: str
    headers: str


class DummyObj(BaseModel):
    pass


app = FastAPI()


@app.get("/health")
def get_health():
    return {"health": "ok"}


@app.get("/tunnel")
def handle_tunnel(req: DummyObj):
    print(req)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5058)
