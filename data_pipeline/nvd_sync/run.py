import argparse

from data_pipeline.nvd_sync.sync import run_full_sync, run_incremental_sync, run_seed_sync


def main():
    parser = argparse.ArgumentParser(description="Run NVD CVE sync")
    parser.add_argument(
        "mode",
        choices=["seed", "full", "incremental"],
        help="Which sync to run: seed (bounded initial load), full (entire NVD history), incremental (since last checkpoint)",
    )
    parser.add_argument(
        "--years-back",
        type=int,
        default=1,
        help="For 'seed' mode: how many years of history to pull (default: 1)",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=200,
        help="Page size for NVD API requests (default: 200)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="For 'full' mode: cap the number of pages fetched (useful for testing)",
    )

    args = parser.parse_args()

    if args.mode == "seed":
        run_seed_sync(years_back=args.years_back, results_per_page=args.results_per_page)
    elif args.mode == "full":
        run_full_sync(results_per_page=args.results_per_page, max_pages=args.max_pages)
    elif args.mode == "incremental":
        run_incremental_sync()


if __name__ == "__main__":
    main()