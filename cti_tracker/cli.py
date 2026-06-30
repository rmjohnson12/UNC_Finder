"""Command-line entrypoint.

    python3 -m cti_tracker.cli run          # collect + persist + summarize
    python3 -m cti_tracker.cli run --dry-run
    python3 -m cti_tracker.cli show --limit 15
    python3 -m cti_tracker.cli digest --since 2026-06-01T00:00:00Z
    python3 -m cti_tracker.cli export-stix --output unc-finder-bundle.json --pretty
    python3 -m cti_tracker.cli actors
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .config import ACTORS, Actor, load_actors
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
    config: dict = {"actors": configured_actors(args)}
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


def configured_actors(args: argparse.Namespace) -> tuple[Actor, ...]:
    return load_actors(args.actor_config) if args.actor_config else ACTORS


def cmd_actors(args: argparse.Namespace) -> None:
    for a in configured_actors(args):
        aliases = f" (aka {', '.join(a.aliases)})" if a.aliases else ""
        print(f"{a.primary}{aliases}\n    {a.note}")


def parse_since(value: str) -> str:
    """Validate and normalize an ISO-8601 timestamp for SQLite comparisons."""
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "expected an ISO-8601 timestamp, e.g. 2026-06-01T00:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def cmd_digest(args: argparse.Namespace) -> None:
    store = Store(args.db)
    rows = store.changed_since(args.since, args.limit)
    new_count, reseen_count = store.change_counts_since(args.since)
    print(f"Changes since {args.since}: {new_count} new, {reseen_count} re-seen")
    if not rows:
        print("(no changes)")
    for item in rows:
        label = item.get("name") or item.get("value") or item.get("id")
        actors = ", ".join(item.get("labels", [])) or "untagged"
        print(f"- [{item['_change']}] [{item['type']}] {label}")
        print(f"    actors: {actors}; seen x{item['_times_seen']}")
    if new_count + reseen_count > len(rows):
        print(f"(showing {len(rows)} of {new_count + reseen_count} changes)")
    store.close()


def cmd_serve(args: argparse.Namespace) -> None:
    from .web import serve_dashboard

    serve_dashboard(args.db, args.host, args.port)


def cmd_export_stix(args: argparse.Namespace) -> None:
    from .stix_export import write_bundle

    store = Store(args.db)
    try:
        count = write_bundle(store, args.output, args.pretty)
    finally:
        store.close()
    destination = "stdout" if args.output == "-" else args.output
    print(f"Exported {count} STIX 2.1 object(s) to {destination}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cti-tracker", description="Configurable passive CTI tracker"
    )
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite path (default: %(default)s)")
    p.add_argument(
        "--actor-config",
        help="JSON actor profile (defaults to the built-in UNC5792/UNC4221 catalog)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run all collectors once")
    run.add_argument("--dry-run", action="store_true", help="collect but don't persist")
    run.add_argument("--cisa-feed", default=None, help="override CISA feed URL")
    run.set_defaults(func=cmd_run)

    show = sub.add_parser("show", help="show recent objects")
    show.add_argument("--limit", type=int, default=20)
    show.set_defaults(func=cmd_show)

    digest = sub.add_parser("digest", help="show objects changed since a timestamp")
    digest.add_argument("--since", required=True, type=parse_since, help="ISO-8601 timestamp")
    digest.add_argument("--limit", type=int, default=100)
    digest.set_defaults(func=cmd_digest)

    actors = sub.add_parser("actors", help="list tracked actors")
    actors.set_defaults(func=cmd_actors)

    serve = sub.add_parser("serve", help="serve the local read-only dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8080, type=int)
    serve.set_defaults(func=cmd_serve)

    export_stix = sub.add_parser("export-stix", help="export a validated STIX 2.1 bundle")
    export_stix.add_argument("--output", "-o", default="unc-finder-bundle.json")
    export_stix.add_argument("--pretty", action="store_true", help="indent and sort JSON output")
    export_stix.set_defaults(func=cmd_export_stix)
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
