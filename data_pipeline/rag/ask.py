import argparse

from data_pipeline.rag.answer import answer_question


def main():
    p = argparse.ArgumentParser()
    p.add_argument("question")
    p.add_argument(
        "--days", type=int, default=None, help="only sources from the last N days"
    )
    p.add_argument("--model", default=None)
    args = p.parse_args()

    a = answer_question(args.question, days=args.days, model=args.model)

    print(f"\n{a.text}\n")
    print("Sources:")
    for s in a.sources:
        mark = "*" if s["tag"] in a.cited else " "
        print(f" {mark} [{s['tag']}] {s['type']:4} {s['id'][:70]}  {s['url']}")
    if a.invalid_citations:
        print(f"WARNING: invalid tags: {a.invalid_citations}")
    if a.uncited:
        print(f"WARNING: {len(a.uncited)} item(s) without a citation:")
        for b in a.uncited:
            print(f"  - {b[:100]}")
    print(
        f"\n{a.latency:.1f}s, {a.prompt_tokens}+{a.completion_tokens} tokens (* = cited)"
    )


if __name__ == "__main__":
    main()
