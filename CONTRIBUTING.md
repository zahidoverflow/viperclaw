# Contributing to ViperClaw

Contributions that add deep, verified offensive methodologies, new language taint patterns, or improved HTTP/WAF differential heuristics are welcome!

## Guidelines
1. **Clean-Room & MIT Licensed:** All code and `SKILL.md` playbooks must be original work compatible with the MIT License.
2. **Zero Bloated Wrappers:** Do not submit generic wrappers around random CLI scanners. Every analyzer or skill must encode a specific, high-signal methodology or verification oracle.
3. **Tests Required:** Run `pytest -v` before opening a Pull Request.
