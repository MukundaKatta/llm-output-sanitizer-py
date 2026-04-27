# llm-output-sanitizer-py

[![PyPI](https://img.shields.io/pypi/v/llm-output-sanitizer-py.svg)](https://pypi.org/project/llm-output-sanitizer-py/)
[![Python](https://img.shields.io/pypi/pyversions/llm-output-sanitizer-py.svg)](https://pypi.org/project/llm-output-sanitizer-py/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Sanitize LLM outputs before HTML, SQL, shell, or markdown sinks.** Zero runtime dependencies.

Python port of [@mukundakatta/llm-output-sanitizer](https://github.com/MukundaKatta/llm-output-sanitizer). The JS sibling has the full design notes; this README sticks to the Python API.

## Install

```bash
pip install llm-output-sanitizer-py
```

## Usage

```python
from llm_output_sanitizer import sanitize, assert_safe, UnsafeOutputError

text = '<script>alert("pwned")</script> Drop table users; rm -rf /'

result = sanitize(text, sink="markdown")
result.safe        # False
result.text        # '[removed:html]alert("pwned")[removed:html] [removed:sql] table users; [removed:shell]/'
result.findings    # [Finding(kind='html', match='<script>'), ...]

# Tripwire pattern: raise on any flagged content right before sending to the sink.
try:
    safe_text = assert_safe(text, sink="html")
except UnsafeOutputError as exc:
    log.warning("blocked unsafe LLM output: %s", exc.findings)
```

### Sinks

| Sink | Behavior |
|---|---|
| `markdown` (default) | Pattern pass only. |
| `html` | Pattern pass + entity-encode `<`, `>`, `&` in whatever is left. |
| `sql` | Pattern pass only. |
| `shell` | Pattern pass only. |

### Bundled patterns

| Kind | Catches |
|---|---|
| `html` | `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<meta>`, `<link>` (open or close tags) |
| `sql` | `drop`, `truncate`, `alter`, `delete from`, `insert into` |
| `shell` | `rm -rf`, `curl ... \|`, `wget ... \|`, `chmod 777`, `sudo ` |

## API differences from the JS sibling

* `sanitize()` returns a `SanitizeResult` dataclass; findings are frozen `Finding` dataclasses.
* `assert_safe()` raises `UnsafeOutputError` (a `ValueError` subclass) instead of a plain `Error` with attached `findings`.
* `sink` is a Python keyword arg, not an `options` object.

See the JS sibling's [README](https://github.com/MukundaKatta/llm-output-sanitizer) for the full design notes.

## License

MIT
