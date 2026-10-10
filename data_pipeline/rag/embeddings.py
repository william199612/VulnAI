from openai import OpenAI
from dotenv import load_dotenv

from .config import OPENAI_API_KEY, EMBEDDING_MODEL, MAX_RETRIES, TIMEOUT

load_dotenv()
_client = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        # the SDK retries 429s and connection errors with backoff on its own;
        # raise the default (2) so brief rate limits don't fail a whole batch
        _client = OpenAI(
            api_key=OPENAI_API_KEY,
            max_retries=MAX_RETRIES,
            timeout=TIMEOUT,
        )
    return _client


def embed_texts(texts: list[str], model: str = EMBEDDING_MODEL) -> list[list[float]]:
    response = get_client().embeddings.create(input=texts, model=model)
    return [item.embedding for item in response.data]
