import re
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from typing import Optional, List, Literal
from dataclasses import dataclass, field
from datetime import datetime

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NVDParamsSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


@dataclass
class CVEHit:
    cve_id: str
    description: str | None
    cvss_score: float | None
    published_date: datetime | None
    similarity: float
    exact_match: bool = False
    cwe: str | None = None
    cvss_vector: str | None = None
    modified_date: datetime | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class NewsHit:
    id: int
    url: str
    title: str | None
    source_domain: str | None
    content: str | None
    published_at: datetime | None
    similarity: float
    exact_match: bool = False


@dataclass
class RAGAnswer:
    question: str
    text: str
    sources: List[str]
    cited: List[str]
    uncited: List[str]
    invalid_citations: List[str]
    latency: float
    prompt_tokens: int
    completion_tokens: int
