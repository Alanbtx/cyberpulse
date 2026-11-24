"""O prompt copiável (frontend/src/prompt.ts) deve pedir o mesmo formato do prompt da plataforma."""
from pathlib import Path

from app.ai import REQUIRED_SECTIONS, build_prompt
from app.models import Vulnerability

FRONT_PROMPT = Path(__file__).resolve().parents[2] / "frontend" / "src" / "prompt.ts"


def test_copyable_prompt_has_same_sections_as_platform():
    ts = FRONT_PROMPT.read_text(encoding="utf-8")
    platform = build_prompt(Vulnerability(cve_id="CVE-2024-3094", title="t", source="x"))
    for section in REQUIRED_SECTIONS:
        assert f"'{section}'" in ts, f"Seção ausente no prompt copiável: {section}"
        assert f"**{section}**" in platform


def test_copyable_prompt_keeps_key_rules():
    ts = FRONT_PROMPT.read_text(encoding="utf-8")
    for rule in ("Português do Brasil", "Get-HotFix", "não foi confirmado", "Sendo explorada ativamente"):
        assert rule in ts
