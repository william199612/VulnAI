import os
import re
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
MAX_STEPS = 6

CITE_RE = re.compile(r"\[((?:CVE-\d{4}-\d{4,})|(?:news:\d+))\]", re.I)
ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|news:\d+)$", re.I)
BRACKET_RE = re.compile(r"\[([^\]\n]+)\](?!\()")


@dataclass
class AgentResult:
    question: str
    text: str
    steps: list[dict] = field(default_factory=list)  # the tool-call trace
    sources: dict[str, str] = field(default_factory=dict)  # id -> url
    cited: list[str] = field(default_factory=list)
    invalid_citations: list[str] = field(default_factory=list)
    uncited: list[str] = field(default_factory=list)
    stopped_reason: str = "answer"  # answer | max_steps
    latency_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
