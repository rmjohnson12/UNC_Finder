"""Command-line entrypoint.

    python3 -m cti_tracker.cli run          # collect + persist + summarize
    python3 -m cti_tracker.cli run --dry-run
    python3 -m cti_tracker.cli show --limit 15
    python3 -m cti_tracker.cli actors
"""
from __future__ import annotations

import argparse

from .config import ACTORS
from .orchestrator import Orchestrator
from .store import DEFAULT_DB, Store

# Optional: load a local .env if python-dotenv is installed. Not required.
try:  # pragma: no cover
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass


def cmd_run(args: argparse.Namespace) -> None:
    store = Store(args.db)
    config: dict = {}
    if args.cisa_feed:
        config["cisa_feed_url"] = args.cisa_feed
    orch = Orchestrator(store, config=config)
    results = orch.run(dry_run=args.dry_run)
    for r in results:
        print(f"[{r.agent}] new={r.new_count} seen={r.seen_count} errors={len(r.errors)}")
        for n in r.notes:
            print(f"    note: {n}")
        for e in r.errors:
            print(f"    ERROR: {e}")
    print("\nStore summary:", store.counts_by_type())
    store.close()


def cmd_show(args: argparse.Namespace) -> None:
    store = Store(args.db)
    rows = store.recent(args.limit)
    if not rows:
        print("(store is empty — run `python3 -m cti_tracker.cli run` first)")
    for d in rows:
        label = d.get("name") or d.get("value") or d.get("id")
        seen = d.get("_times_seen", 1)
        print(f"- [{d['type']}] {label}  (seen x{seen}, last {d.get('_last_seen','')[:19]})")
        if d.get("labels"):
            print(f"    actors: {', '.join(d['labels'])}")
    store.close()


def cmd_actors(_: argparse.Namespace) -> None:
    for a in ACTORS:
        aliases = f" (aka {', '.join(a.aliases)})" if a.aliases else ""
        print(f"{a.primary}{aliases}\n    {a.note}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cti-tracker", description="UNC5792/UNC4221 CTI tracker")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite path (default: %(default)s)")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run all collectors once")
    run.add_argument("--dry-run", action="store_true", help="collect but don't persist")
    run.add_argument("--cisa-feed", default=None, help="override CISA feed URL")
    run.set_defaults(func=cmd_run)

    show = sub.add_parser("show", help="show recent objects")
    show.add_argument("--limit", type=int, default=20)
    show.set_defaults(func=cmd_show)

    actors = sub.add_parser("actors", help="list tracked actors")
    actors.set_defaults(func=cmd_actors)
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
