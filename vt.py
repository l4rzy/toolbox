# generated by datamodel-codegen:
#   filename:  vt2.json
#   timestamp: 2024-01-21T22:51:50+00:00

from __future__ import annotations

from pydantic import BaseModel, Field


class VirusTotalObject(BaseModel):
    harmless: int
    type_unsupported: int = Field(..., alias='type-unsupported')
    suspicious: int
    confirmed_timeout: int = Field(..., alias='confirmed-timeout')
    timeout: int
    failure: int
    malicious: int
    undetected: int
