"""llm-output-sanitizer -- neutralize dangerous patterns in LLM output.

Public surface (mirrors the JS sibling ``@mukundakatta/llm-output-sanitizer``):

    from llm_output_sanitizer import sanitize, assert_safe, SanitizeResult, Finding, UnsafeOutputError

* ``sanitize(text, sink="markdown")`` -> ``SanitizeResult`` -- replace dangerous spans, optionally HTML-encode.
* ``assert_safe(text, sink=...)`` -> ``str`` -- raise ``UnsafeOutputError`` if anything was flagged; else return the cleaned text.
* ``Finding`` / ``SanitizeResult`` -- dataclasses with the per-pattern hits.
* ``UnsafeOutputError`` -- raised by ``assert_safe`` when ``safe=False``; carries ``findings``.

Pure-stdlib (``re`` only). Designed as a last-mile guard for HTML / SQL /
shell / markdown sinks; not a substitute for parameterised queries or proper
output encoders, but a useful tripwire when an agent's output goes anywhere
risky.
"""

from .core import (
    PATTERNS,
    Finding,
    SanitizeResult,
    UnsafeOutputError,
    assert_safe,
    assert_safe_output,
    sanitize,
    sanitize_output,
)

__version__ = "0.1.0"
VERSION = __version__

__all__ = [
    "PATTERNS",
    "VERSION",
    "Finding",
    "SanitizeResult",
    "UnsafeOutputError",
    "assert_safe",
    "assert_safe_output",
    "sanitize",
    "sanitize_output",
]
