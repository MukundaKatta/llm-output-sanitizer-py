"""Core sanitizer for llm-output-sanitizer.

Mirrors the JS sibling 1:1: each kind in ``PATTERNS`` (``html``, ``sql``,
``shell``) has a regex; matched spans are replaced with ``[removed:<kind>]``.
After the regex pass, when ``sink="html"``, remaining ``<``, ``>`` and ``&``
characters are entity-encoded to neutralize stray markup.

The ``sink`` parameter accepts ``"markdown"`` (default), ``"html"``, ``"sql"``,
or ``"shell"``. Only ``"html"`` triggers the entity-encode step in the JS
source; the other sinks rely on the pattern pass alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

# Patterns in order. Mirrors the JS ``PATTERNS`` object exactly.
PATTERNS: dict[str, Pattern[str]] = {
    "html": re.compile(
        r"<\/?(script|iframe|object|embed|form|meta|link)[^>]*>",
        re.IGNORECASE,
    ),
    "sql": re.compile(
        r"\b(drop|truncate|alter|delete\s+from|insert\s+into)\b",
        re.IGNORECASE,
    ),
    "shell": re.compile(
        r"\b(rm\s+-rf|curl\s+[^|]+\||wget\s+[^|]+\||chmod\s+777|sudo\s+)\b",
        re.IGNORECASE,
    ),
}

_HTML_ENTITY_MAP = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}
_VALID_SINKS = frozenset({"markdown", "html", "sql", "shell"})


@dataclass(frozen=True)
class Finding:
    """A single dangerous-pattern hit.

    Attributes:
        kind: which pattern category fired (``html`` / ``sql`` / ``shell``).
        match: the literal substring that was replaced.
    """

    kind: str
    match: str


@dataclass(frozen=True)
class SanitizeResult:
    """Result of a sanitize pass.

    Attributes:
        safe: ``True`` iff no patterns matched.
        text: the post-sanitize text (with ``[removed:<kind>]`` substitutions
            and, for ``sink="html"``, entity-encoded ``<``, ``>``, ``&``).
        findings: per-pattern hits, in the order patterns are evaluated.
        sink: the sink the caller targeted; useful for logging/debug.
    """

    safe: bool
    text: str
    findings: list[Finding] = field(default_factory=list)
    sink: str = "markdown"


class UnsafeOutputError(ValueError):
    """Raised by ``assert_safe`` when the sanitizer flags any pattern.

    The original ``Finding`` list is attached as ``.findings`` so callers can
    log the reason without re-running the pass.
    """

    def __init__(self, findings: list[Finding]) -> None:
        super().__init__("Unsafe LLM output")
        self.findings = findings


def sanitize(text: object, sink: str = "markdown") -> SanitizeResult:
    """Run every pattern over ``text`` and replace matches inline.

    ``text`` is coerced to ``str`` (treats ``None`` as ``""`` to match the JS
    ``text ?? ""`` step). ``sink`` selects the post-processing pass:

      * ``"html"``  -- after the pattern pass, entity-encodes ``<``, ``>``, ``&``.
      * ``"sql"`` / ``"shell"`` / ``"markdown"`` -- pattern pass only.

    Returns a ``SanitizeResult``. ``safe`` is ``True`` only when no pattern fired.
    """
    if sink not in _VALID_SINKS:
        raise ValueError(
            f"unknown sink {sink!r}; expected one of {sorted(_VALID_SINKS)}"
        )

    value = "" if text is None else str(text)
    findings: list[Finding] = []

    # Apply patterns in declaration order. Each matched span becomes
    # ``[removed:<kind>]`` and is logged as a Finding.
    for kind, regex in PATTERNS.items():
        def _sub(match: re.Match[str], _kind: str = kind) -> str:
            findings.append(Finding(kind=_kind, match=match.group(0)))
            return f"[removed:{_kind}]"

        value = regex.sub(_sub, value)

    # HTML sink: entity-encode any leftover markup characters. The JS source
    # only does this for ``sink="html"``; we keep that contract.
    if sink == "html":
        value = re.sub(
            r"[<>&]",
            lambda m: _HTML_ENTITY_MAP[m.group(0)],
            value,
        )

    return SanitizeResult(
        safe=not findings,
        text=value,
        findings=findings,
        sink=sink,
    )


def assert_safe(text: object, sink: str = "markdown") -> str:
    """Sanitize ``text``; raise ``UnsafeOutputError`` if any pattern fired.

    Returns the cleaned text on success. Use this on the boundary right before
    handing model output to a sensitive sink.
    """
    result = sanitize(text, sink=sink)
    if not result.safe:
        raise UnsafeOutputError(result.findings)
    return result.text


# JS-style aliases for callers porting from ``@mukundakatta/llm-output-sanitizer``.
sanitize_output = sanitize
assert_safe_output = assert_safe
