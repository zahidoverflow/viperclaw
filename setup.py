"""Minimal setuptools shim to dynamically bundle all skills/*/SKILL.md into wheels."""

from pathlib import Path
from setuptools import setup

skill_data_files = [
    (f"share/viperclaw/skills/{p.parent.name}", [p.as_posix()])
    for p in sorted(Path("skills").glob("*/SKILL.md"))
]

setup(data_files=skill_data_files)
