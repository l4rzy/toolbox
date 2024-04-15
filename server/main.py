from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
import uvicorn
import pycurl
import io
import logging
import csv
import ipaddress
import hashlib

from pydantic import BaseModel
from enum import Enum
from typing import Optional
import random
from datetime import datetime, timedelta
import yaml

VERSION_MAJOR = 0
VERSION_MINOR = 4
VERSION_PATCH = 6
VERSION_DATE = "2024 Mar 18"

ABUSEIPDB_KEYS = ("",)
VIRUSTOTAL_KEYS = ("",)


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


class YamlConfigParser:
    """
    A class for parsing YAML configuration files.

    Args:
        configPath (str, optional): The path to the YAML configuration file. Defaults to "./config.yaml".

    Attributes:
        configPath (str): The path to the YAML configuration file.
        config (dict): The parsed YAML configuration.

    Methods:
        load(): Loads and parses the YAML configuration file.
        get(key): Retrieves the value associated with the specified key in the configuration.

    """

    def __init__(self, configPath="./config.yaml"):
        self.configPath = configPath
        self.config = {}

    def load(self):
        """
        Loads and parses the YAML configuration file.

        Raises:
            FileNotFoundError: If the configuration file is not found.
            yaml.YAMLError: If there is an error parsing the YAML configuration.

        """
        try:
            with open(self.configPath, "r") as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[yamlconfig] configuration file not found: {self.configPath}")
        except yaml.YAMLError as e:
            print(f"[yamlconfig] error parsing configuration: {e}")

    def get(self, key):
        """
        Retrieves the value associated with the specified key in the configuration.

        Args:
            key (str): The key name in the configuration.

        Returns:
            Any: The value associated with the specified key, or None if not found.

        """
        try:
            return self.config.get(key)
        except Exception:
            return []


class LocalIpInfo:
    """
    A class that provides information about local IP addresses.

    Attributes:
        db (list): The database containing IP address information.
        dataFile (str): The path to the data file used for the database.
        disabled (bool): A flag indicating if the database is disabled.
    """

    def __init__(self, dataFile):
        self.db = None
        self.dataFile = dataFile
        self.disabled = False

    async def query(self, ip):
        """
        Queries the database for information about the given IP address.

        Args:
            ip (str): The IP address to query.

        Returns:
            str: The information about the IP address.
        """
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

        if self.disabled:
            return res

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
config = YamlConfigParser("config.yaml")
config.load()
cache = {}

def hash_str(itemStr: str):
    return hashlib.sha512(itemStr.encode()).hexdigest()

async def process_tunnel_obj(target: TunnelObject) -> TunnelObject:
    """
    Process the given TunnelObject and add missing API keys for specified services.

    Args:
        target (TunnelObject): The TunnelObject to be processed.

    Returns:
        TunnelObject: The processed TunnelObject with added API keys.

    """
    if target.service == TunnelService.ABUSEIPDB:
        for h in target.headers:
            if "Key" in h and h != "Key: None":
                return target
        logger.warn("missing api key for abuseipdb, using default")
        try:
            target.headers.remove("Key: None")
        except Exception:
            pass
        target.headers.append(f"Key: {random.choice(config.get('abuseipdb'))}")

    elif target.service == TunnelService.VIRUSTOTAL:
        for h in target.headers:
            if "x-apikey" in h and "x-apikey: None" != h:
                return target
        logger.warn("missing api key for virustotal, using default")
        try:
            target.headers.remove("x-apikey: None")
        except Exception:
            pass
        target.headers.append(f"x-apikey: {random.choice(config.get('virustotal'))}")
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
    """
    Handles the tunnel request and returns the response body.

    Args:
        target (TunnelObject): The tunnel object containing the request details.

    Returns:
        bytes: The response body.

    Raises:
        Exception: If an error occurs during the tunnel request.

    """
    if target.service == TunnelService.LOCALIP:
        return await localIPInfo.query(target.ip)

    # Check if result is already cached
    url_hash = hash_str(target.url)
    if url_hash in cache and datetime.now() - cache[url_hash][
        "timestamp"
    ] < timedelta(minutes=1):
        return cache[url_hash]["result"]

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

        # Cache the result
        cache[hash_str(target.url)] = {"result": body, "timestamp": datetime.now()}
    except Exception as e:
        logger.error(e)
        return "{}"

    return body


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5058)
