from pydantic import BaseModel
from typing import Optional, List, Literal


class NVDParamsSchema(BaseModel):
    startIndex: int = 0
    resultsPerPage: int = 200
    lastModStartDate: Optional[str] = None
    lastModEndDate: Optional[str] = None
    pubStartDate: Optional[str] = None
    pubEndDate: Optional[str] = None
    cpeName: Optional[str] = None
    cveIds: Optional[List[str]] = None
    cveTag: Optional[str] = None
    cvssV3Severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None
    keywordSearch: Optional[str] = None