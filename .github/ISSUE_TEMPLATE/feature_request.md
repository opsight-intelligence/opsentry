---
name: Feature Request
about: Suggest a new pattern to block or a new hook
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

**What pattern should OpSentry block?**
Describe the dangerous command, file access, or code pattern.

**Why is this dangerous?**
What could go wrong if this pattern is not blocked?

**Which hook should handle it?**
Existing hook to extend, or a new hook?

- [ ] block-sensitive-files.sh
- [ ] block-dangerous-commands.sh
- [ ] block-git-commands.sh
- [ ] block-data-exfiltration.sh
- [ ] block-package-install.sh
- [ ] block-scope-escape.sh
- [ ] block-environment-escape.sh
- [ ] block-pii-leakage.sh
- [ ] New hook needed

**Example**
Show the command or pattern that should be caught:
```bash
# This should be blocked:
example-dangerous-command
```

**Additional context**
Any compliance framework, regulation, or real-world incident that motivates this?
