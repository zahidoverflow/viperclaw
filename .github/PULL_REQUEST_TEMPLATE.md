## Summary
- Briefly describe the new analyzer rule, security audit skill (`skills/viper-*/SKILL.md`), or bug fix.

## Verification Checklist
- [ ] Pure Python 3.10+ standard library only (`0` external runtime dependencies added to `pyproject.toml`)
- [ ] `pytest -v` passes all regression suites
- [ ] If adding a new skill, `SKILL.md` includes YAML frontmatter (`name`, `description`), discovery patterns, a 5-point audit checklist, and a vulnerable vs. hardened code example.
