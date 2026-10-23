import re

from data_pipeline.rag.answer import answer_question, LLM_MODEL
from data_pipeline.rag.embeddings import get_client
from data_pipeline.shared.logging import get_logger
from data_pipeline.rag.prompt import REWRITE_PROMPT
from data_pipeline.rag.config import MAX_TURNS

logger = get_logger("rag", "rag_answer.log")


def _resolve_tags(text, sources):
    ref = {
        s["tag"]: (s["id"] if s["type"] == "cve" else f"news: {s['id'][:60]}")
        for s in sources
    }
    return re.sub(r"\[(S\d+)\]", lambda m: f"[{ref.get(m.group(1), m.group(1))}]", text)


class Conversation:
    def __init__(self, days=None):
        self.history = []  # list of (question, answer-with-resolved-tags)
        self.days = days

    def _rewrite(self, question):
        if not self.history:
            return question
        convo = "\n".join(f"User: {q}\nAssistant: {a}" for q, a in self.history)
        resp = get_client().chat.completions.create(
            model=LLM_MODEL,
            temperature=0,
            messages=[
                {"role": "system", "content": REWRITE_PROMPT},
                {"role": "user", "content": f"{convo}\n\nLatest message: {question}"},
            ],
        )
        return (resp.choices[0].message.content or question).strip()

    def ask(self, question):
        search_query = self._rewrite(question)
        logger.info(f"rewrite: {question!r} -> {search_query!r}")
        ans = answer_question(
            question, history=self.history, search_query=search_query, days=self.days
        )
        self.history.append((question, _resolve_tags(ans.text, ans.sources)))
        self.history = self.history[-MAX_TURNS:]
        return ans, search_query

    def reset(self):
        self.history = []
