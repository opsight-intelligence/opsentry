# redteam-loop

Review-gated red-team / blue-team hardening loop for the opsentry hooks.

## What it does

1. **Attacker** (headless Claude) generates 10 novel PreToolUse payloads per
   round, avoiding duplicates from earlier rounds.
2. Split 80/20 into training and held-out sets. The **defender never sees**
   the held-out attacks — they exist to detect regex overfit.
3. Run each attack through every hook in a **workdir copy**. Count how many
   bypass.
4. **Defender** (headless Claude) receives hook sources + bypassing training
   attacks and returns a unified diff plus new `run_test` lines.
5. Apply the diff to the workdir, re-run the existing `test.sh` (must stay
   green) plus training and held-out attacks. Log results.
6. Stop after 3 rounds or when two consecutive rounds produce zero bypasses.

## Safety properties

- **Never modifies** `opsentry/claude/hooks/` — all edits land in
  `redteam-loop/workdir/claude/hooks/`.
- **Never runs git** — no commits, branches, or PRs. You review and apply.
- **Never runs `test.sh` against the real hooks** — the workdir copy is
  isolated.

## Requirements

- `claude` CLI on PATH (headless `-p` mode)
- `jq`, `python3`, `patch`

## Run

```
bash run_loop.sh
```

Each invocation creates a fresh `rounds/<timestamp>/` directory.

## Outputs

```
rounds/<session>/
├── SUMMARY.md                   # top-level table
└── round-N/
    ├── attacks.json             # full batch from attacker
    ├── training.json            # 80% the defender sees
    ├── heldout.json             # 20% held out (overfit check)
    ├── train_pre.json           # which attacks blocked before defender
    ├── train_post.json          # which blocked after patch applied
    ├── heldout_pre.json
    ├── heldout_post.json
    ├── patch.diff               # defender's proposed diff
    ├── new_tests.sh              # proposed run_test lines
    ├── tests.txt                # existing test.sh output on patched hooks
    ├── attacker_raw.txt
    └── defender_raw.txt
```

## Review & apply a round

```
cd ~/Desktop/repos/agentguard/opsentry/claude/hooks
patch -p0 < ~/Desktop/repos/agentguard/redteam-loop/rounds/<session>/round-N/patch.diff
# then eyeball new_tests.sh and append lines you want to opsentry/test.sh
bash ~/Desktop/repos/agentguard/opsentry/test.sh
```

## How to read the summary

- `heldout_blocked` substantially lower than `training_blocked` = regex
  overfit. Reject the patch or widen the approach.
- `existing tests P/F` must match baseline (currently 169 / 0). Any
  regression means the patch broke an allow case.
- Monotonic decrease in `unblocked pre` across rounds = real hardening;
  plateau near zero = attacker exhausted.
