from openai import OpenAI
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

from .config import OPENAI_API_KEY

_client = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=OPENAI_API_KEY)
    return _client


def embed_texts(
    texts: list[str], model: str = "text-embedding-3-small"
) -> list[list[float]]:
    response = get_client().embeddings.create(input=texts, model=model)
    return [item.embedding for item in response.data]
