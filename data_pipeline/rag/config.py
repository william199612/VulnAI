import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
EMBEDDING_MODEL = "text-embedding-3-small"

MAX_RETRIES = 5
TIMEOUT = 60

BATCH_SIZE = 100
MAX_CONSECUTIVE_FAILURES = 3
MAX_EMBEDDING_CHARS = 1500

TOP_K_DEFAULT = 5
