"""Small read-only local dashboard for the CTI store."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from .store import Store


def render_dashboard(store: Store) -> str:
    counts = store.counts_by_type()
    objects = store.recent(100)
    cards = "".join(
        f'<div class="card"><strong>{count}</strong><span>{html.escape(kind)}</span></div>'
        for kind, count in counts.items()
    ) or '<div class="card"><strong>0</strong><span>objects</span></div>'

    rows: list[str] = []
    for item in objects:
        label = str(item.get("name") or item.get("value") or item.get("id"))
        url = str(item.get("url", ""))
        safe_label = html.escape(label)
        if url.startswith(("https://", "http://")):
            safe_label = (
                f'<a href="{html.escape(url, quote=True)}" target="_blank" '
                f'rel="noreferrer">{safe_label}</a>'
            )
        actors = ", ".join(str(value) for value in item.get("labels", [])) or "—"
        rows.append(
            "<tr>"
            f"<td><span class=\"pill\">{html.escape(str(item['type']))}</span></td>"
            f"<td>{safe_label}</td>"
            f"<td>{html.escape(actors)}</td>"
            f"<td>{item.get('_times_seen', 1)}</td>"
            f"<td>{html.escape(str(item.get('_last_seen', ''))[:19])}</td>"
            "</tr>"
        )
    table_rows = "".join(rows) or '<tr><td colspan="5">No intelligence collected yet.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="30">
  <title>UNC Finder CTI Dashboard</title>
  <style>
    :root {{ color-scheme: dark; --ink:#e8edf2; --muted:#93a4b8; --panel:#14202b;
      --line:#263849; --accent:#56d6b3; --bg:#091016; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(circle at top right,#163345,var(--bg) 42%);
      color:var(--ink); font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }}
    main {{ width:min(1180px,92vw); margin:48px auto; }}
    header {{ display:flex; justify-content:space-between; align-items:end; gap:24px; margin-bottom:28px; }}
    h1 {{ margin:0; font-size:clamp(28px,5vw,52px); letter-spacing:-.06em; }}
    header p {{ color:var(--muted); max-width:580px; margin:8px 0 0; }}
    .status {{ color:var(--accent); white-space:nowrap; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:24px 0; }}
    .card {{ background:color-mix(in srgb,var(--panel) 88%,transparent); border:1px solid var(--line);
      border-radius:14px; padding:18px; display:flex; flex-direction:column; box-shadow:0 12px 34px #0005; }}
    .card strong {{ color:var(--accent); font-size:30px; }} .card span {{ color:var(--muted); }}
    .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:14px; background:var(--panel); }}
    table {{ border-collapse:collapse; width:100%; min-width:760px; }}
    th,td {{ padding:13px 15px; border-bottom:1px solid var(--line); text-align:left; }}
    th {{ color:var(--muted); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }}
    tr:last-child td {{ border-bottom:0; }} a {{ color:var(--accent); }}
    .pill {{ border:1px solid #3d6170; border-radius:999px; padding:3px 8px; font-size:12px; }}
    footer {{ color:var(--muted); margin-top:16px; font-size:12px; }}
    @media (max-width:700px) {{ header {{ align-items:start; flex-direction:column; }} }}
  </style>
</head>
<body><main>
  <header><div><h1>UNC Finder</h1><p>Passive, source-backed threat intelligence. Reports,
    indicators, and relationships from the local SQLite store.</p></div>
    <div class="status">● read-only dashboard</div></header>
  <section class="cards">{cards}</section>
  <section class="table-wrap"><table>
    <thead><tr><th>Type</th><th>Object</th><th>Actors</th><th>Seen</th><th>Last observed</th></tr></thead>
    <tbody>{table_rows}</tbody>
  </table></section>
  <footer>Refreshes every 30 seconds · No active infrastructure access</footer>
</main></body></html>"""


def make_handler(db_path: str) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/", "/api/summary", "/api/objects"}:
                self.send_error(404)
                return
            store = Store(db_path)
            try:
                if self.path == "/":
                    body = render_dashboard(store).encode("utf-8")
                    content_type = "text/html; charset=utf-8"
                elif self.path == "/api/summary":
                    body = json.dumps(store.counts_by_type()).encode("utf-8")
                    content_type = "application/json"
                else:
                    body = json.dumps(store.recent(100)).encode("utf-8")
                    content_type = "application/json"
            finally:
                store.close()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return DashboardHandler


def serve_dashboard(db_path: str, host: str, port: int) -> None:
    server = HTTPServer((host, port), make_handler(db_path))
    print(f"Dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
