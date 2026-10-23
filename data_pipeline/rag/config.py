import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
EMBEDDING_MODEL = "text-embedding-3-small"
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

MAX_RETRIES = 5
TIMEOUT = 60

BATCH_SIZE = 100
MAX_CONSECUTIVE_FAILURES = 3
MAX_EMBEDDING_CHARS = 1500

TOP_K_DEFAULT = 5
NEWS_SNIPPET_CHARS = 1000

TEMPERATURE = 0.0
MAX_TURNS = 4
