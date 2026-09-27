"""Background worker: re-checks verified domains on schedule and emails new problems.

Run continuously:   python -m siteguard.monitor
Run once (cron):    python -m siteguard.monitor --once
"""
import argparse
import json
import logging
import time

from . import checks, config, db, mailer

log = logging.getLogger("siteguard.monitor")


def due_domains(conn, interval_hours):
    return conn.execute(
        """SELECT d.*, u.email FROM domains d JOIN users u ON u.id = d.user_id
           WHERE d.verified_at IS NOT NULL
             AND (d.last_checked_at IS NULL
                  OR d.last_checked_at <= datetime('now', ?))""",
        (f"-{interval_hours} hours",),
    ).fetchall()


def previous_ids(conn, domain_id):
    row = conn.execute("SELECT findings FROM reports WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
                       (domain_id,)).fetchone()
    return {f["id"] for f in json.loads(row["findings"])} if row else set()


def check_domain(conn, domain, run=checks.run_all, send=mailer.send):
    before = previous_ids(conn, domain["id"])
    first_run = domain["last_checked_at"] is None
    try:
        score, findings = run(domain["name"])
    except checks.UnsafeTarget as e:
        log.warning("skipping %s: %s", domain["name"], e)
        conn.execute("UPDATE domains SET last_checked_at = datetime('now') WHERE id = ?", (domain["id"],))
        return None
    conn.execute("INSERT INTO reports (domain_id, score, findings) VALUES (?, ?, ?)",
                 (domain["id"], score, json.dumps(findings, ensure_ascii=False)))
    conn.execute("UPDATE domains SET last_checked_at = datetime('now'), last_score = ? WHERE id = ?",
                 (score, domain["id"]))

    new = [f for f in findings if f["id"] not in before]
    if new and (first_run or any(f["severity"] in ("high", "medium") for f in new)):
        lines = [f"- [{f['severity']}] {f['title']}\n  الحل: {f['fix']}" for f in new]
        send(domain["email"],
             f"SiteGuard: {len(new)} مشكلة جديدة في {domain['name']} (التقييم {score}/100)",
             "\n".join(lines) + f"\n\nالتقرير الكامل: {config.BASE_URL}/domains/{domain['id']}")
    return score


def run_once(path=None, run=checks.run_all, send=mailer.send):
    with db.session(path) as conn:
        for d in due_domains(conn, config.CHECK_INTERVAL_HOURS):
            try:
                check_domain(conn, d, run=run, send=send)
            except Exception:
                log.exception("check failed for %s", d["name"])
            conn.commit()


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    db.init()
    while True:
        run_once()
        if args.once:
            return
        time.sleep(600)


if __name__ == "__main__":
    main()
