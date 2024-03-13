from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import uvicorn
import pycurl
import io

from pydantic import BaseModel

class TunnelObject(BaseModel):
    url: str
    headers: list[str] | None

app = FastAPI()


@app.get("/health")
def get_health():
    return {"health": "ok"}


@app.post("/tunnel", response_class=PlainTextResponse)
def handle_tunnel(target: TunnelObject):
    url = target.url
    headers = target.headers
    try:
        handle = pycurl.Curl()
        # if self.debug:

        handle.setopt(
            pycurl.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        )

        buffer = io.BytesIO()
        handle.setopt(pycurl.WRITEFUNCTION, buffer.write)
        handle.setopt(pycurl.URL, url)

        if headers is not None:
            handle.setopt(pycurl.HTTPHEADER, headers)
        handle.perform()
        #code: int = handle.getinfo(pycurl.RESPONSE_CODE)
        body = buffer.getvalue()

        handle.close()
        buffer.close()
    except Exception as e:
        print(e)
        return {}

    return body

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5058)
