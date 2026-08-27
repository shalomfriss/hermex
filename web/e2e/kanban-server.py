"""Production dashboard fixture with a representative Kanban board."""
from __future__ import annotations

import argparse
import contextlib
import os
import time

os.environ.setdefault("HERMES_NO_BANNER", "1")
os.environ.setdefault("HERMES_DASHBOARD_EMBEDDED_CHAT", "1")
# Kanban workers pin the shared board in their process environment. This
# fixture must always use its temporary HERMES_HOME instead of inheriting that
# production board capability.
os.environ.pop("HERMES_KANBAN_DB", None)
os.environ.pop("HERMES_KANBAN_BOARD", None)
os.environ.pop("HERMES_KANBAN_HOME", None)
os.environ.pop("HERMES_DELEGATED_CHILD_CONTEXT", None)


def seed_board() -> None:
    from hermes_cli import kanban_db

    kanban_db.init_db(board="default")
    with contextlib.closing(kanban_db.connect(board="default")) as conn:
        task_ids: list[str] = []
        statuses = ["triage", "todo", "ready", "running", "blocked", "review", "done"]
        for index in range(14):
            task_id = kanban_db.create_task(
                conn,
                title=f"Accessible task card {index + 1}",
                body="Keyboard and pointer behavior must remain available.",
                assignee="coder" if index % 2 == 0 else "reviewer",
                tenant="alpha" if index % 2 == 0 else "beta",
                priority=index % 3,
                initial_status="running",
                board="default",
            )
            conn.execute(
                "UPDATE tasks SET status = ?, current_run_id = NULL WHERE id = ?",
                (statuses[index % len(statuses)], task_id),
            )
            task_ids.append(task_id)

        now = int(time.time())
        for attempt in range(4):
            conn.execute(
                """
                INSERT INTO task_runs (
                    task_id, profile, status, outcome, summary, metadata,
                    started_at, ended_at
                ) VALUES (?, ?, 'done', 'success', ?, ?, ?, ?)
                """,
                (
                    task_ids[0],
                    "coder",
                    f"Verified keyboard behavior, attempt {attempt + 1}",
                    '{"checks":["keyboard","axe"]}',
                    now - (attempt + 2) * 90,
                    now - (attempt + 1) * 60,
                ),
            )
        conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9131)
    args = parser.parse_args()

    seed_board()

    from hermes_cli import web_server
    import uvicorn

    web_server.app.state.auth_required = False
    web_server.app.state.bound_host = "127.0.0.1"
    web_server.app.state.bound_port = args.port
    uvicorn.run(
        web_server.app,
        host="127.0.0.1",
        port=args.port,
        server_header=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
