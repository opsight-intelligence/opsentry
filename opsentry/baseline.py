#!/usr/bin/env python3
"""
Configuration baseline integrity helper for OpSentry.
Computes SHA-256 hashes over the guardrail-controlled subset of CLAUDE.md
(content between guardrail markers) and settings.json (intersection of
installed deny rules with source deny rules + OpSentry hook entries
identified by command path) so install.sh can write a baseline manifest at
install time and patrol.sh can detect tampering against that manifest later.
The subset approach is required because both files are merge-installed:
employees may add their own deny rules and CLAUDE.md content that must not
break the integrity check.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

SCHEMA_VERSION = 1
BASELINE_FILENAME = ".opsentry-baseline.json"

GUARDRAILS_START = "<!-- GUARDRAILS START — DO NOT EDIT THIS SECTION -->"
GUARDRAILS_END = "<!-- GUARDRAILS END -->"

GUARDRAIL_HOOK_PREFIX = "block-"
GUARDRAIL_HOOK_SUFFIX = ".sh"
GUARDRAIL_MATCHERS = ("Read", "Write", "Edit", "Bash")


# ---------------------------------------------------------------------------
# Subset extraction
# ---------------------------------------------------------------------------


def extract_claude_md_section(claude_md_path: Path) -> bytes | None:
    """
    Return the guardrail section of CLAUDE.md as bytes (markers included).

    Returns None when the file is missing or markers cannot be found, so
    callers can distinguish "not installed" from "installed but tampered".
    """
    if not claude_md_path.is_file():
        return None
    content = claude_md_path.read_bytes()
    start = content.find(GUARDRAILS_START.encode())
    end = content.find(GUARDRAILS_END.encode())
    if start < 0 or end < 0:
        return None
    return content[start : end + len(GUARDRAILS_END.encode())]


def _is_guardrail_hook_command(command: str) -> bool:
    """A hook command path is ours iff its basename is block-*.sh."""
    if not command:
        return False
    basename = command.rsplit("/", 1)[-1]
    return basename.startswith(GUARDRAIL_HOOK_PREFIX) and basename.endswith(
        GUARDRAIL_HOOK_SUFFIX
    )


def extract_settings_subset(
    settings_path: Path, source_settings_path: Path
) -> dict | None:
    """
    Return the guardrail-controlled subset of an installed settings.json.

    The subset is:
        - The installed deny rules that are also present in the source
          guardrail settings (so user-added denies don't poison the hash,
          but a missing or mutated guardrail deny does).
        - The PreToolUse entries for OpSentry's matchers (Read/Write/Edit/
          Bash), with non-guardrail hook commands stripped out so user-added
          custom hooks for the same matcher don't poison the hash.

    Within each matcher the guardrail hooks are kept in *installed order* so
    that an attacker who reorders the hook list (placing a custom one first
    to bypass enforcement) is detected by the hash mismatch.

    Returns None when either file is missing.
    """
    if not settings_path.is_file() or not source_settings_path.is_file():
        return None

    installed = json.loads(settings_path.read_text())
    source = json.loads(source_settings_path.read_text())

    source_deny = set(source.get("permissions", {}).get("deny", []))
    installed_deny = installed.get("permissions", {}).get("deny", [])
    relevant_deny = sorted(rule for rule in installed_deny if rule in source_deny)

    pre_tool_use = installed.get("hooks", {}).get("PreToolUse", [])
    matcher_to_guardrail_hooks: dict[str, list[str]] = {}
    for entry in pre_tool_use:
        matcher = entry.get("matcher", "")
        if matcher not in GUARDRAIL_MATCHERS:
            continue
        guardrail_cmds: list[str] = []
        for hook in entry.get("hooks", []):
            cmd = hook.get("command", "")
            if _is_guardrail_hook_command(cmd):
                # Normalize: drop the absolute install dir prefix so hashes
                # are stable across machines with different $HOME paths.
                guardrail_cmds.append(cmd.rsplit("/", 1)[-1])
        if guardrail_cmds:
            matcher_to_guardrail_hooks[matcher] = guardrail_cmds

    return {
        "deny": relevant_deny,
        "pre_tool_use": [
            {"matcher": m, "hooks": matcher_to_guardrail_hooks[m]}
            for m in GUARDRAIL_MATCHERS
            if m in matcher_to_guardrail_hooks
        ],
    }


def hash_settings_subset(subset: dict) -> str:
    """Hash a settings subset dict via canonical JSON."""
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hash_bytes(path.read_bytes())


# ---------------------------------------------------------------------------
# Baseline write / verify
# ---------------------------------------------------------------------------


def compute_baseline(
    claude_home: Path, source_dir: Path, version: str | None = None
) -> dict:
    """
    Compute a baseline manifest dict for the freshly-installed claude_home.

    `source_dir` is the guardrail source directory (the one that contains
    `CLAUDE.md`, `settings.json`, and `hooks/`). `version` is the OpSentry
    version string written into the manifest for traceability.
    """
    settings_path = claude_home / "settings.json"
    source_settings_path = source_dir / "settings.json"
    claude_md_path = claude_home / "CLAUDE.md"

    section = extract_claude_md_section(claude_md_path)
    settings_subset = extract_settings_subset(settings_path, source_settings_path)

    hooks_block: dict[str, str] = {}
    hooks_dir = claude_home / "hooks"
    if hooks_dir.is_dir():
        for hook_path in sorted(hooks_dir.glob("block-*.sh")):
            digest = hash_file(hook_path)
            if digest is not None:
                hooks_block[hook_path.name] = digest

    return {
        "schema": SCHEMA_VERSION,
        "version": version or "unknown",
        "installed_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "claude_md": {
            "section_sha256": hash_bytes(section) if section is not None else None,
            "markers_present": section is not None,
        },
        "settings": {
            "guardrail_subset_sha256": (
                hash_settings_subset(settings_subset) if settings_subset is not None else None
            ),
            "subset_present": settings_subset is not None,
        },
        "hooks": hooks_block,
    }


def write_baseline(
    claude_home: Path,
    source_dir: Path,
    version: str | None = None,
) -> Path:
    """Compute and write the baseline manifest to claude_home / .opsentry-baseline.json."""
    manifest = compute_baseline(claude_home, source_dir, version=version)
    manifest_path = claude_home / BASELINE_FILENAME
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest_path


def verify_baseline(
    claude_home: Path,
    source_dir: Path,
) -> tuple[bool, list[dict]]:
    """
    Compare the current installed state against the stored baseline manifest.

    Returns (overall_ok, findings) where findings is a list of dicts with
    keys: status ('pass'|'fail'|'warn'), check, expected, actual, message.
    """
    manifest_path = claude_home / BASELINE_FILENAME
    findings: list[dict] = []

    if not manifest_path.is_file():
        findings.append(
            {
                "status": "warn",
                "check": "manifest",
                "expected": str(manifest_path),
                "actual": None,
                "message": (
                    f"Baseline manifest missing at {manifest_path}. Run install.sh "
                    "to generate one. Skipping baseline integrity check."
                ),
            }
        )
        return True, findings

    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError) as exc:
        findings.append(
            {
                "status": "fail",
                "check": "manifest",
                "expected": "valid JSON",
                "actual": str(exc),
                "message": f"Baseline manifest at {manifest_path} could not be parsed.",
            }
        )
        return False, findings

    schema = manifest.get("schema")
    if schema != SCHEMA_VERSION:
        findings.append(
            {
                "status": "warn",
                "check": "schema",
                "expected": SCHEMA_VERSION,
                "actual": schema,
                "message": (
                    f"Baseline schema is {schema}, expected {SCHEMA_VERSION}. "
                    "Re-run install.sh to refresh the baseline."
                ),
            }
        )

    current = compute_baseline(claude_home, source_dir, version=manifest.get("version"))
    overall_ok = True

    # CLAUDE.md guardrail section
    expected_md = manifest.get("claude_md", {}).get("section_sha256")
    actual_md = current["claude_md"]["section_sha256"]
    if expected_md is None and actual_md is None:
        findings.append(
            {
                "status": "warn",
                "check": "claude_md.section_sha256",
                "expected": None,
                "actual": None,
                "message": "Neither baseline nor current CLAUDE.md has guardrail markers.",
            }
        )
    elif expected_md == actual_md:
        findings.append(
            {
                "status": "pass",
                "check": "claude_md.section_sha256",
                "expected": expected_md,
                "actual": actual_md,
                "message": "CLAUDE.md guardrail section matches baseline.",
            }
        )
    else:
        overall_ok = False
        findings.append(
            {
                "status": "fail",
                "check": "claude_md.section_sha256",
                "expected": expected_md,
                "actual": actual_md,
                "message": (
                    "CLAUDE.md guardrail section has been MODIFIED since install. "
                    "Re-run install.sh to restore."
                ),
            }
        )

    # settings.json guardrail subset
    expected_settings = manifest.get("settings", {}).get("guardrail_subset_sha256")
    actual_settings = current["settings"]["guardrail_subset_sha256"]
    if expected_settings is None and actual_settings is None:
        findings.append(
            {
                "status": "warn",
                "check": "settings.guardrail_subset_sha256",
                "expected": None,
                "actual": None,
                "message": "Neither baseline nor current settings.json has a guardrail subset.",
            }
        )
    elif expected_settings == actual_settings:
        findings.append(
            {
                "status": "pass",
                "check": "settings.guardrail_subset_sha256",
                "expected": expected_settings,
                "actual": actual_settings,
                "message": "settings.json guardrail subset matches baseline.",
            }
        )
    else:
        overall_ok = False
        findings.append(
            {
                "status": "fail",
                "check": "settings.guardrail_subset_sha256",
                "expected": expected_settings,
                "actual": actual_settings,
                "message": (
                    "settings.json guardrail subset has been MODIFIED since install "
                    "(deny rule removed/mutated, or hook registration tampered). "
                    "Re-run install.sh to restore."
                ),
            }
        )

    # Hook hashes (each hook independently)
    expected_hooks = manifest.get("hooks", {}) or {}
    actual_hooks = current.get("hooks", {}) or {}
    for hook_name, expected_hash in expected_hooks.items():
        actual_hash = actual_hooks.get(hook_name)
        if actual_hash is None:
            overall_ok = False
            findings.append(
                {
                    "status": "fail",
                    "check": f"hooks.{hook_name}",
                    "expected": expected_hash,
                    "actual": None,
                    "message": f"Hook {hook_name} is MISSING since install.",
                }
            )
        elif actual_hash != expected_hash:
            overall_ok = False
            findings.append(
                {
                    "status": "fail",
                    "check": f"hooks.{hook_name}",
                    "expected": expected_hash,
                    "actual": actual_hash,
                    "message": f"Hook {hook_name} has been MODIFIED since install.",
                }
            )
        else:
            findings.append(
                {
                    "status": "pass",
                    "check": f"hooks.{hook_name}",
                    "expected": expected_hash,
                    "actual": actual_hash,
                    "message": f"Hook {hook_name} matches baseline.",
                }
            )

    return overall_ok, findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_findings(findings: list[dict]) -> None:
    for f in findings:
        status = f["status"].upper()
        check = f["check"]
        message = f["message"]
        print(f"  {status}  {check} — {message}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OpSentry baseline integrity helper.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    write_p = sub.add_parser("write", help="Write the baseline manifest.")
    write_p.add_argument("--claude-home", required=True, type=Path)
    write_p.add_argument(
        "--source-dir",
        required=True,
        type=Path,
        help="Path to the guardrail source dir (the one with CLAUDE.md, settings.json, hooks/).",
    )
    write_p.add_argument("--version", default=None)

    verify_p = sub.add_parser(
        "verify", help="Verify the installed state against the baseline manifest."
    )
    verify_p.add_argument("--claude-home", required=True, type=Path)
    verify_p.add_argument(
        "--source-dir",
        required=True,
        type=Path,
        help="Path to the guardrail source dir (used to extract the canonical deny rule set).",
    )
    verify_p.add_argument(
        "--quiet", action="store_true", help="Only print findings on failure."
    )

    args = parser.parse_args()

    if args.command == "write":
        manifest_path = write_baseline(
            args.claude_home, args.source_dir, version=args.version
        )
        print(f"  Baseline written to {manifest_path}")
        return 0

    if args.command == "verify":
        ok, findings = verify_baseline(args.claude_home, args.source_dir)
        if not args.quiet or not ok:
            _print_findings(findings)
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
