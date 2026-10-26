"""Agent loop: the model decides which tools to call, we execute them, repeat.

Flow
  1. send system prompt + question + TOOL_SPECS to the model
  2. if the model requests tool calls -> run them, append the results, go to 1
  3. if it answers in plain text -> that is the final answer
  Guards: max steps (the last step forces an answer with tools disabled),
          duplicate-call detection, tools never raise (see tools.run_tool),
          citation validity + coverage checks on the final answer.

Citations: the answer cites real IDs in brackets, e.g. [CVE-2026-93546] or
[news:12]. "Valid" means the ID was actually returned by a tool in this run.

Run:
    uv run python -m agent.agent "Should we patch CVE-2026-93546 immediately?"
"""

from __future__ import annotations

import json
import logging
import sys
import time
from openai import OpenAI

from agent.tools import TOOL_SPECS, run_tool
from agent.prompt import AGENT_PROMPT_VERSION, SYSTEM_PROMPT
from agent.constants import (
    DEFAULT_MODEL,
    MAX_STEPS,
    CITE_RE,
    ID_RE,
    BRACKET_RE,
    AgentResult,
)

logger = logging.getLogger("agent")


def _collect_sources(result: object, out: dict[str, str]) -> None:
    """Collect every item id (and url) a tool returned. Error payloads are skipped."""
    if isinstance(result, dict):
        if result.get("error"):
            return
        item_id = result.get("id")
        if isinstance(item_id, str) and ID_RE.match(item_id):
            if item_id.upper().startswith("CVE-"):
                out.setdefault(
                    item_id.upper(),
                    f"https://nvd.nist.gov/vuln/detail/{item_id.upper()}",
                )
            else:
                out.setdefault(item_id.lower(), result.get("url", ""))
        for v in result.values():
            _collect_sources(v, out)
    elif isinstance(result, list):
        for v in result:
            _collect_sources(v, out)


def _norm(tag: str) -> str:
    return tag.upper() if tag.upper().startswith("CVE-") else tag.lower()


def _find_uncited(text: str) -> list[str]:
    """Lines that state something (>= 40 chars, not a heading or lead-in) with no [ID]."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        low = s.lower()
        if (
            len(s) < 40
            or s.startswith("#")
            or s.endswith(":")
            or low.startswith(("not verified", "the sources do not contain"))
        ):
            continue
        if not CITE_RE.search(s):
            out.append(s)
    return out


def _summarize(result_json: str) -> tuple[int | None, str | None]:
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        return None, "unparseable"
    if isinstance(data, dict):
        if data.get("error"):
            return None, data["error"]
        return data.get("count", 1 if data.get("id") else None), None
    return None, None


# --------------------------------------------------------------------------
def run_agent(
    question: str,
    *,
    history: list[dict] | None = None,
    max_steps: int = MAX_STEPS,
    model: str | None = None,
) -> AgentResult:
    client = OpenAI()
    model = model or DEFAULT_MODEL
    t0 = time.perf_counter()

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += history or []
    messages.append({"role": "user", "content": question})

    res = AgentResult(question=question, text="")
    seen_calls: set[tuple[str, str]] = set()
    final_text = ""

    for step in range(1, max_steps + 1):
        last = step == max_steps
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOL_SPECS,
            tool_choice="none" if last else "auto",  # last step must answer
            temperature=0,
        )
        res.prompt_tokens += resp.usage.prompt_tokens
        res.completion_tokens += resp.usage.completion_tokens
        msg = resp.choices[0].message

        if not msg.tool_calls:
            final_text = msg.content or ""
            res.stopped_reason = "max_steps" if last and res.steps else "answer"
            break

        messages.append(
            {
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {
                            "name": c.function.name,
                            "arguments": c.function.arguments,
                        },
                    }
                    for c in msg.tool_calls
                ],
            }
        )

        for call in msg.tool_calls:
            name, raw_args = call.function.name, call.function.arguments or "{}"
            key = (name, raw_args)
            t1 = time.perf_counter()
            if key in seen_calls:  # guard: repeated identical call
                result_json = json.dumps(
                    {
                        "error": "duplicate_call",
                        "message": "You already made this exact call. Use its earlier "
                        "result, or call with different arguments, or answer.",
                    }
                )
            else:
                seen_calls.add(key)
                result_json = run_tool(name, raw_args)

            n_results, err = _summarize(result_json)
            try:
                _collect_sources(json.loads(result_json), res.sources)
            except json.JSONDecodeError:
                pass
            res.steps.append(
                {
                    "step": step,
                    "tool": name,
                    "args": raw_args,
                    "results": n_results,
                    "error": err,
                    "chars": len(result_json),
                    "latency_s": round(time.perf_counter() - t1, 2),
                }
            )
            messages.append(
                {"role": "tool", "tool_call_id": call.id, "content": result_json}
            )

    res.text = final_text
    cited = {_norm(m) for m in CITE_RE.findall(final_text)}
    res.cited = sorted(cited)
    res.invalid_citations = sorted(cited - set(res.sources))
    res.uncited = _find_uncited(final_text) if res.sources else []
    res.latency_s = time.perf_counter() - t0
    cited_raw = BRACKET_RE.findall(final_text)
    bad = {t for t in cited_raw if not ID_RE.match(t.strip())}
    res.invalid_citations = sorted((cited - set(res.sources)) | bad)

    logger.info(
        f"prompt_version={AGENT_PROMPT_VERSION} q={question!r} steps={len(res.steps)} "
        f"tools={[s['tool'] for s in res.steps]} stop={res.stopped_reason} "
        f"cited={len(cited)} invalid={res.invalid_citations} uncited={len(res.uncited)} "
        f"latency={res.latency_s:.1f}s tokens={res.prompt_tokens}+{res.completion_tokens}"
    )
    return res


# --------------------------------------------------------------------------
def print_result(r: AgentResult) -> None:
    print("\n--- trace ---")
    for s in r.steps:
        status = f"error={s['error']}" if s["error"] else f"results={s['results']}"
        print(f"  {s['step']}. {s['tool']}({s['args']})  {status}  {s['latency_s']}s")
    print("\n--- answer ---\n")
    print(r.text)
    print()
    for sid, url in r.sources.items():
        print(f" {'*' if sid in r.cited else ' '} [{sid}] {url}")
    if r.invalid_citations:
        print(
            f"WARNING: invalid citations (not returned by any tool): {r.invalid_citations}"
        )
    if r.uncited:
        print(f"WARNING: {len(r.uncited)} item(s) without a citation:")
        for b in r.uncited:
            print(f"  - {b[:100]}")
    if r.stopped_reason == "max_steps":
        print("NOTE: step limit reached; the answer was forced with tools disabled.")
    print(
        f"\n{r.latency_s:.1f}s, {r.prompt_tokens}+{r.completion_tokens} tokens (* = cited)"
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    if len(sys.argv) < 2:
        sys.exit('usage: python -m agent.agent "your question"')
    print_result(run_agent(" ".join(sys.argv[1:])))
