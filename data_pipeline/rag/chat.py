import argparse

from data_pipeline.rag.conversation import Conversation


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=None)
    args = p.parse_args()

    convo = Conversation(days=args.days)
    print("Type a question. /reset starts over, /quit exits.")

    while True:
        q = input("\n> ").strip()
        if q in ("/quit", "/exit"):
            break
        if q == "/reset":
            convo.reset()
            continue
        if not q:
            continue
        ans, search_query = convo.ask(q)
        if search_query != q:
            print(f"  (searched for: {search_query})")
        print(f"\n{ans.text}\n")
        for s in ans.sources:
            mark = "*" if s["tag"] in ans.cited else " "
            print(f" {mark} [{s['tag']}] {s['type']:4} {s['id'][:60]}  {s['url']}")
        if ans.invalid_citations:
            print(f"WARNING: invalid tags {ans.invalid_citations}")


if __name__ == "__main__":
    main()
