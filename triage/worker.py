"""One scheduled POSIX job: collect, publish reports, and record operational health."""

import argparse
from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import uuid

from .core import Store, timestamp, utcnow
from .reporting import write_reports
from .sources import aws_findings, read_file, read_owners


class JobBusy(Exception):
    pass


def emit(event, **fields):
    print(json.dumps({"timestamp": utcnow().isoformat(), "event": event, **fields}), flush=True)


def load_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"mode", "state_dir", "fixture_path", "owners_path", "region", "profile"}
    if not isinstance(config, dict) or set(config) - allowed:
        raise ValueError("configuration must be an object containing only documented keys")
    if config.get("mode") not in ("fixture", "aws"):
        raise ValueError("mode must be fixture or aws")
    for name in ("state_dir", "fixture_path", "owners_path"):
        value = config.get(name)
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(name + " must be a nonempty path")
            config[name] = str((path.parent / value).resolve())
    if not config.get("state_dir"):
        raise ValueError("state_dir is required")
    if config["mode"] == "fixture" and not config.get("fixture_path"):
        raise ValueError("fixture mode requires fixture_path")
    if config["mode"] == "aws" and not config.get("region"):
        raise ValueError("AWS mode requires region")
    for name in ("region", "profile"):
        if config.get(name) is not None and (not isinstance(config[name], str) or not config[name].strip()):
            raise ValueError(name + " must be a nonempty string")
    return config


def atomic_json(path, data):
    """Same-filesystem replacement avoids partial health/status JSON reads."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


@contextmanager
def job_lock(state_dir):
    """The kernel releases the lock on exit, including a killed worker."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state_dir / "worker.lock").open("a", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise JobBusy("another scheduled worker is already running") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_once(config, now=None):
    """Exit successfully only after collection AND a complete report publication."""
    fixed_time = now
    now = now or utcnow()
    previous_umask = os.umask(0o077)
    store = None
    try:
        with job_lock(config["state_dir"]):
            mode = config["mode"]
            mode_dir = Path(config["state_dir"]) / mode
            mode_dir.mkdir(exist_ok=True, mode=0o700)
            started = {"mode": mode, "started_at": timestamp(now.isoformat()), "outcome": "running"}
            atomic_json(mode_dir / "last-attempt.json", started)
            emit("job_started", mode=mode)
            phase = "collection"
            try:
                owners = read_owners(config.get("owners_path"))
                if mode == "fixture":
                    findings = read_file(config["fixture_path"])
                    source = "file:" + config["fixture_path"]
                else:
                    findings = aws_findings(config["region"], config.get("profile"))
                    source = "aws:" + config["region"] + ":" + (config.get("profile") or "default-credentials")
                store = Store(mode_dir / "triage.db")
                stats = store.ingest(findings, owners, source, now)
                run_id = store.latest_run()["id"]
                emit("collection_succeeded", mode=mode, run_id=run_id, **stats)
                phase = "reporting"
                reports = mode_dir / "reports"
                reports.mkdir(exist_ok=True, mode=0o700)
                bundle = Path(tempfile.mkdtemp(prefix="run-%d-" % run_id, dir=reports))
                write_reports(store, bundle, now)
                phase = "publication"
                pending_link = reports / (".latest-" + uuid.uuid4().hex)
                try:
                    pending_link.symlink_to(bundle.name, target_is_directory=True)
                    os.replace(str(pending_link), str(reports / "latest"))
                finally:
                    if pending_link.is_symlink():
                        pending_link.unlink()
                completed = timestamp((fixed_time or utcnow()).isoformat())
                success = {**started, "outcome": "success", "completed_at": completed,
                           "run_id": run_id, "report_dir": str(bundle), "stats": stats}
                atomic_json(mode_dir / "last-success.json", success)
                atomic_json(mode_dir / "last-attempt.json", success)
                emit("job_succeeded", mode=mode, run_id=run_id, report_dir=str(bundle))
                return success
            except Exception as exc:
                # Do not log raw finding payloads or exception text that might contain credentials.
                failure = {**started, "outcome": "failure", "phase": phase,
                           "error_type": type(exc).__name__, "failed_at": utcnow().isoformat()}
                try:
                    atomic_json(mode_dir / "last-attempt.json", failure)
                except OSError:
                    emit("status_write_failed", mode=mode)
                emit("job_failed", mode=mode, phase=phase, error_type=type(exc).__name__)
                raise
    finally:
        if store is not None:
            store.close()
        os.umask(previous_umask)


def health(config, max_age_hours=26, now=None):
    if not math.isfinite(max_age_hours) or max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive and finite")
    now = now or utcnow()
    mode_dir = Path(config["state_dir"]) / config["mode"]
    reasons = []
    success = {}
    age_hours = None
    try:
        attempt = json.loads((mode_dir / "last-attempt.json").read_text(encoding="utf-8"))
        if attempt.get("outcome") != "success":
            reasons.append("latest attempt is " + str(attempt.get("outcome", "unknown")))
        success = json.loads((mode_dir / "last-success.json").read_text(encoding="utf-8"))
        completed = datetime.fromisoformat(timestamp(success["completed_at"]))
        age_hours = (now - completed).total_seconds() / 3600
        if age_hours < 0:
            reasons.append("success timestamp is in the future; check the clock")
        elif age_hours > max_age_hours:
            reasons.append("last successful collection/report is stale")
        bundle = Path(success["report_dir"])
        latest = mode_dir / "reports/latest"
        if not latest.is_symlink() or latest.resolve() != bundle.resolve():
            reasons.append("latest report pointer does not match the success record")
        if not all((bundle / name).is_file() for name in ("report.md", "findings.csv")):
            reasons.append("a published report file is missing")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        reasons.append("success/status evidence is missing or invalid")
    return {"healthy": not reasons, "mode": config["mode"], "reasons": reasons,
            "age_hours": round(age_hours, 3) if age_hours is not None else None,
            "run_id": success.get("run_id") if isinstance(success, dict) else None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="JSON configuration; relative paths resolve beside it")
    parser.add_argument("--health", action="store_true", help="Check published report freshness without collecting")
    parser.add_argument("--max-age-hours", type=float, default=26)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.health:
            result = health(config, args.max_age_hours)
            emit("health_check", **result)
            return 0 if result["healthy"] else 1
        run_once(config)
        return 0
    except JobBusy:
        emit("job_busy", message="Another worker holds the job lock")
        return 75
    except Exception as exc:
        emit("worker_error", error_type=type(exc).__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
