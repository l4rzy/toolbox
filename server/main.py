from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import uvicorn
import pycurl
import io
import logging
import csv
import ipaddress

from pydantic import BaseModel
from enum import Enum
from typing import Optional

VERSION_MAJOR = 0
VERSION_MINOR = 4
VERSION_PATCH = 5
VERSION_DATE = "2024 Mar 18"

ABUSEIPDB_KEY = ""
VIRUSTOTAL_KEY = ""


class TunnelService(str, Enum):
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    CIRCLCVE = "circl"
    SHODAN = "shodan"
    LOCALIP = "localip"


class TunnelObject(BaseModel):
    service: TunnelService
    url: Optional[str] = ""
    ip: Optional[str] = ""
    headers: Optional[list[str]] = []


class LocalIpInfo:
    def __init__(self, dataFile):
        self.db = None
        self.dataFile = dataFile
        self.disabled = False

    async def query(self, ip):
        if self.db is None:
            try:
                file = open(self.dataFile, "rt")
                reader = csv.reader(file, delimiter=",")
                # schema cidr,usage,location,comment
                self.db = list(reader)
                file.close()
            except Exception as e:
                print(f"[localipinfo] error: {e}")
                self.disabled = True
        res = f"Local IP {ip} not found in database!"

        for row in self.db:
            try:
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(row[0]):
                    res = f"Local IP Address {ip} belongs to {row[0]}\nUsed for: {row[1]}\nLocated at: {row[2]}\nComment: {row[3]}"
            except Exception:
                continue

        return res


app = FastAPI(title="DTS Toolbox", redoc_url=None)
localIPInfo = LocalIpInfo("localIPDB.csv")
logger = logging.getLogger()


async def process_tunnel_obj(target: TunnelObject) -> TunnelObject:
    if target.service == TunnelService.ABUSEIPDB:
        for h in target.headers:
            if "Key" in h and h != "Key: None":
                return target
        logger.warn("missing api key for abuseipdb, using default")
        try:
            target.headers.remove("Key: None")
        except Exception:
            pass
        target.headers.append(f"Key: {ABUSEIPDB_KEY}")

    elif target.service == TunnelService.VIRUSTOTAL:
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
async def get_health():
    return {
        "health": "ok",
        "version": f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH} ({VERSION_DATE})",
    }


@app.post("/tunnel", response_class=PlainTextResponse)
async def handle_tunnel(target: TunnelObject):
    print(target)
    if target.service == TunnelService.LOCALIP:
        return await localIPInfo.query(target.ip)
    try:
        target = await process_tunnel_obj(target)
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
        logger.error(e)
        return "{}"

    return body


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5058)
