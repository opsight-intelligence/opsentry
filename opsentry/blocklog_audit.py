#!/usr/bin/env python3
"""
Block log pattern analyzer for OpSentry.
Parses ~/.claude/guardrail-blocks.log (JSON-lines) and runs pattern detectors
that look for repeat-offender, rapid-burst, multi-hook coverage, exfiltration
cluster, and self-modification attempt signatures so patrol.sh can flag
suspicious activity beyond simple block counts. Each detector emits a
structured finding (info/warn/fail) consumed by patrol.sh in the same format
as baseline.py for visual consistency.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

# Repeat offender: same hook firing N+ times in the last hour.
REPEAT_OFFENDER_WARN = 5
REPEAT_OFFENDER_FAIL = 20

# Rapid burst: any 30-second window with N+ blocks.
RAPID_BURST_WINDOW_SECONDS = 30
RAPID_BURST_WARN = 5

# Multi-hook coverage: distinct hooks fired in the last hour.
MULTI_HOOK_WARN = 3
MULTI_HOOK_FAIL = 5

# Exfiltration cluster: sensitive-files + data-exfiltration within 5 minutes.
EXFIL_CLUSTER_WINDOW_SECONDS = 300

# Self-modification attempts (Attack 3 — guardrail self-destruction).
SELF_MOD_WARN = 1
SELF_MOD_FAIL = 3

DEFAULT_WINDOW_HOURS = 24


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------


@dataclass
class LogEntry:
    """One parsed line from guardrail-blocks.log."""

    timestamp: datetime.datetime
    hook: str
    reason: str
    detail: str
    user: str
    raw: dict = field(default_factory=dict)


def _parse_timestamp(value: str) -> datetime.datetime | None:
    """Parse an ISO-8601 UTC timestamp like 2026-04-11T14:30:00Z."""
    if not value:
        return None
    try:
        # Python 3.10's fromisoformat doesn't accept the trailing Z; strip it.
        cleaned = value.rstrip("Z")
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def parse_log(log_path: Path) -> list[LogEntry]:
    """
    Read a JSON-lines guardrail block log and return parsed entries.

    Lines that are empty, not valid JSON, or missing a parseable timestamp
    are silently skipped — the goal is best-effort analysis, not strict
    validation.
    """
    entries: list[LogEntry] = []
    if not log_path.is_file():
        return entries

    try:
        raw = log_path.read_text(errors="ignore")
    except OSError:
        return entries

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        ts = _parse_timestamp(obj.get("timestamp", ""))
        if ts is None:
            continue
        entries.append(
            LogEntry(
                timestamp=ts,
                hook=str(obj.get("hook", "")),
                reason=str(obj.get("reason", "")),
                detail=str(obj.get("detail", "")),
                user=str(obj.get("user", "")),
                raw=obj,
            )
        )
    entries.sort(key=lambda e: e.timestamp)
    return entries


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _within_window(
    entries: list[LogEntry], now: datetime.datetime, window_seconds: int
) -> list[LogEntry]:
    """Return entries whose timestamp is within `window_seconds` of `now`."""
    cutoff = now - datetime.timedelta(seconds=window_seconds)
    return [e for e in entries if e.timestamp >= cutoff]


def detect_total_stats(
    entries: list[LogEntry], now: datetime.datetime, window_hours: int
) -> dict:
    """INFO finding with total count and last-window count."""
    last_window = _within_window(entries, now, window_hours * 3600)
    return {
        "status": "info",
        "check": "total_blocks",
        "message": (
            f"{len(entries)} total blocks logged "
            f"({len(last_window)} in last {window_hours}h)"
        ),
        "details": {
            "total": len(entries),
            "last_window": len(last_window),
            "window_hours": window_hours,
        },
    }


def detect_repeat_offender(
    entries: list[LogEntry], now: datetime.datetime
) -> list[dict]:
    """Same hook firing N+ times in the last hour."""
    findings: list[dict] = []
    last_hour = _within_window(entries, now, 3600)
    if not last_hour:
        return findings

    counts: dict[str, int] = {}
    for entry in last_hour:
        counts[entry.hook] = counts.get(entry.hook, 0) + 1

    flagged = False
    for hook, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        if count >= REPEAT_OFFENDER_FAIL:
            findings.append(
                {
                    "status": "fail",
                    "check": "repeat_offender",
                    "message": (
                        f"hook '{hook}' fired {count} times in last 1h "
                        f"(>= {REPEAT_OFFENDER_FAIL} = sustained attack signature)"
                    ),
                    "details": {"hook": hook, "count": count},
                }
            )
            flagged = True
        elif count >= REPEAT_OFFENDER_WARN:
            findings.append(
                {
                    "status": "warn",
                    "check": "repeat_offender",
                    "message": (
                        f"hook '{hook}' fired {count} times in last 1h "
                        f"(>= {REPEAT_OFFENDER_WARN} = repeated bypass attempts)"
                    ),
                    "details": {"hook": hook, "count": count},
                }
            )
            flagged = True

    if not flagged:
        findings.append(
            {
                "status": "pass",
                "check": "repeat_offender",
                "message": f"no hook fired more than {REPEAT_OFFENDER_WARN} times in last 1h",
            }
        )
    return findings


def detect_rapid_burst(
    entries: list[LogEntry], now: datetime.datetime, window_hours: int
) -> list[dict]:
    """Sliding 30-second window with N+ blocks in the recent window."""
    findings: list[dict] = []
    entries = _within_window(entries, now, window_hours * 3600)
    if len(entries) < RAPID_BURST_WARN:
        findings.append(
            {
                "status": "pass",
                "check": "rapid_burst",
                "message": f"no {RAPID_BURST_WINDOW_SECONDS}s burst of {RAPID_BURST_WARN}+ blocks detected",
            }
        )
        return findings

    # Sliding window over sorted entries (parse_log sorts by timestamp).
    left = 0
    max_burst = 0
    burst_start: datetime.datetime | None = None
    burst_end: datetime.datetime | None = None
    for right in range(len(entries)):
        while (
            entries[right].timestamp - entries[left].timestamp
        ).total_seconds() > RAPID_BURST_WINDOW_SECONDS:
            left += 1
        window_size = right - left + 1
        if window_size > max_burst:
            max_burst = window_size
            burst_start = entries[left].timestamp
            burst_end = entries[right].timestamp

    if max_burst >= RAPID_BURST_WARN and burst_start is not None and burst_end is not None:
        delta = (burst_end - burst_start).total_seconds()
        findings.append(
            {
                "status": "warn",
                "check": "rapid_burst",
                "message": (
                    f"{max_burst} blocks within {delta:.1f}s "
                    f"(>= {RAPID_BURST_WARN} in {RAPID_BURST_WINDOW_SECONDS}s = automated bypass attempt)"
                ),
                "details": {
                    "burst_size": max_burst,
                    "window_seconds": delta,
                    "first": burst_start.isoformat(),
                    "last": burst_end.isoformat(),
                },
            }
        )
    else:
        findings.append(
            {
                "status": "pass",
                "check": "rapid_burst",
                "message": f"no {RAPID_BURST_WINDOW_SECONDS}s burst of {RAPID_BURST_WARN}+ blocks detected",
            }
        )
    return findings


def detect_multi_hook_coverage(
    entries: list[LogEntry], now: datetime.datetime
) -> list[dict]:
    """Number of distinct hooks fired in the last hour."""
    findings: list[dict] = []
    last_hour = _within_window(entries, now, 3600)
    distinct = sorted({e.hook for e in last_hour if e.hook})
    count = len(distinct)

    if count >= MULTI_HOOK_FAIL:
        findings.append(
            {
                "status": "fail",
                "check": "multi_hook_coverage",
                "message": (
                    f"{count} distinct hooks fired in last 1h "
                    f"(>= {MULTI_HOOK_FAIL} = systematic exploration): {', '.join(distinct)}"
                ),
                "details": {"hooks": distinct, "count": count},
            }
        )
    elif count >= MULTI_HOOK_WARN:
        findings.append(
            {
                "status": "warn",
                "check": "multi_hook_coverage",
                "message": (
                    f"{count} distinct hooks fired in last 1h "
                    f"(>= {MULTI_HOOK_WARN} = unusual breadth): {', '.join(distinct)}"
                ),
                "details": {"hooks": distinct, "count": count},
            }
        )
    else:
        findings.append(
            {
                "status": "pass",
                "check": "multi_hook_coverage",
                "message": f"{count} distinct hook(s) in last 1h (below threshold)",
            }
        )
    return findings


def detect_exfil_cluster(
    entries: list[LogEntry], now: datetime.datetime, window_hours: int
) -> list[dict]:
    """sensitive-files + data-exfiltration within 5 minutes = exfil primitive."""
    findings: list[dict] = []
    recent = _within_window(entries, now, window_hours * 3600)
    sensitive = [e for e in recent if "sensitive-files" in e.hook]
    exfil = [e for e in recent if "data-exfiltration" in e.hook]

    if not sensitive or not exfil:
        findings.append(
            {
                "status": "pass",
                "check": "exfil_cluster",
                "message": "no sensitive-files + data-exfiltration cluster detected",
            }
        )
        return findings

    # O(n*m) but n,m are bounded by log size; for huge logs we'd switch to a
    # merge-walk on the sorted streams. Acceptable v1.
    for s in sensitive:
        for x in exfil:
            delta = abs((s.timestamp - x.timestamp).total_seconds())
            if delta <= EXFIL_CLUSTER_WINDOW_SECONDS:
                findings.append(
                    {
                        "status": "fail",
                        "check": "exfil_cluster",
                        "message": (
                            f"sensitive-files ({s.timestamp.isoformat()}) + "
                            f"data-exfiltration ({x.timestamp.isoformat()}) within "
                            f"{delta:.0f}s (canonical exfil primitive)"
                        ),
                        "details": {
                            "sensitive_at": s.timestamp.isoformat(),
                            "exfil_at": x.timestamp.isoformat(),
                            "delta_seconds": delta,
                        },
                    }
                )
                return findings  # one finding is enough; don't spam

    findings.append(
        {
            "status": "pass",
            "check": "exfil_cluster",
            "message": "sensitive-files and data-exfiltration both seen but never within 5 minutes",
        }
    )
    return findings


def detect_self_mod_attempts(
    entries: list[LogEntry], now: datetime.datetime, window_hours: int
) -> list[dict]:
    """block-scope-escape blocks tagged with Self-modification (Attack 3)."""
    findings: list[dict] = []
    recent = _within_window(entries, now, window_hours * 3600)
    matches = [
        e
        for e in recent
        if "scope-escape" in e.hook and "self-modification" in e.reason.lower()
    ]
    count = len(matches)

    if count >= SELF_MOD_FAIL:
        findings.append(
            {
                "status": "fail",
                "check": "self_mod_attempts",
                "message": (
                    f"{count} block-scope-escape self-modification attempts logged "
                    f"(>= {SELF_MOD_FAIL} = active Attack 3 — guardrail self-destruction)"
                ),
                "details": {"count": count},
            }
        )
    elif count >= SELF_MOD_WARN:
        findings.append(
            {
                "status": "warn",
                "check": "self_mod_attempts",
                "message": (
                    f"{count} block-scope-escape self-modification attempt(s) logged — "
                    "review the agent's recent actions"
                ),
                "details": {"count": count},
            }
        )
    else:
        findings.append(
            {
                "status": "pass",
                "check": "self_mod_attempts",
                "message": "no guardrail self-modification attempts logged",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Top-level analyze
# ---------------------------------------------------------------------------


def analyze(
    entries: list[LogEntry],
    now: datetime.datetime | None = None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> tuple[bool, list[dict]]:
    """
    Run all detectors against `entries` and return (any_fail, findings).

    `now` defaults to the latest entry's timestamp (or wall-clock UTC if the
    log is empty), so the analyzer is deterministic for replayed logs and
    test fixtures.
    """
    if now is None:
        if entries:
            now = entries[-1].timestamp
        else:
            now = datetime.datetime.now(datetime.timezone.utc)

    findings: list[dict] = [detect_total_stats(entries, now, window_hours)]
    findings.extend(detect_repeat_offender(entries, now))
    findings.extend(detect_rapid_burst(entries, now, window_hours))
    findings.extend(detect_multi_hook_coverage(entries, now))
    findings.extend(detect_exfil_cluster(entries, now, window_hours))
    findings.extend(detect_self_mod_attempts(entries, now, window_hours))

    any_fail = any(f["status"] == "fail" for f in findings)
    return any_fail, findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_findings(findings: list[dict], verbose: bool = False) -> None:
    for f in findings:
        status = f["status"]
        if not verbose and status == "pass":
            continue
        check = f["check"]
        message = f["message"]
        print(f"  {status.upper()}  {check} — {message}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OpSentry block log pattern analyzer.",
    )
    parser.add_argument(
        "command",
        choices=["analyze"],
        help="The only supported command for now.",
    )
    parser.add_argument(
        "--log-file",
        required=True,
        type=Path,
        help="Path to guardrail-blocks.log (JSON-lines).",
    )
    parser.add_argument(
        "--window-hours",
        type=int,
        default=DEFAULT_WINDOW_HOURS,
        help=f"Recent-window size for stats (default {DEFAULT_WINDOW_HOURS}).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide PASS findings; only show INFO/WARN/FAIL.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all findings including PASS.",
    )
    args = parser.parse_args()

    entries = parse_log(args.log_file)
    any_fail, findings = analyze(entries, window_hours=args.window_hours)

    # Default behavior: hide PASS, show others. --verbose forces PASS too.
    _print_findings(findings, verbose=args.verbose)
    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
