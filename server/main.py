from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import uvicorn
import pycurl
import io
import logging

from pydantic import BaseModel

ABUSEIPDB_KEY = ""
VIRUSTOTAL_KEY = ""


class TunnelObject(BaseModel):
    service: str | None = None
    url: str
    headers: list[str] | None = []


class LocalIPDBObject(BaseModel):
    ip4: str
    ip6: str | None = None


app = FastAPI(title="DTS Toolbox", openapi_url=None, redoc_url=None)
logger = logging.getLogger()


def process_tunnel_obj(target: TunnelObject) -> TunnelObject:
    if target.service == "abuseipdb" or "abuseipdb.com" in target.url:
        for h in target.headers:
            if "Key" in h and h != "Key: None":
                return target
        logger.warn("missing api key for abuseipdb, using default")
        try:
            target.headers.remove("Key: None")
        except Exception:
            pass
        target.headers.append(f"Key: {ABUSEIPDB_KEY}")

    elif target.service == "virustotal" or "virustotal.com" in target.url:
        for h in target.headers:
            if "x-apikey" in h and "x-apikey: None" != h:
                return target
        logger.warn("missing api key for virustotal, using default")
        try:
            target.headers.remove("x-apikey: None")
        except Exception:
            pass
        target.headers.append(f"x-apikey: {VIRUSTOTAL_KEY}")
    else:
        pass
    return target


@app.get("/health")
def get_health():
    return {"health": "ok"}


@app.post("/tunnel", response_class=PlainTextResponse)
def handle_tunnel(target: TunnelObject):
    try:
        target = process_tunnel_obj(target)
        url = target.url
        headers = target.headers
        handle = pycurl.Curl()

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
        # code: int = handle.getinfo(pycurl.RESPONSE_CODE)
        body = buffer.getvalue()

        handle.close()
        buffer.close()
    except Exception as e:
        print(e)
        return {}

    return body


@app.post("/localip", response_class=PlainTextResponse)
def handle_localip(target: LocalIPDBObject):
    print(target)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5058)
