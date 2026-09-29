"""Vercel entrypoint.

Vercel detects a Python project and loads `app` from a default location; `app.py`
at the project root is one of those locations. All the code lives in
`evm_audit/vercel.py` so the same module is importable and testable locally.
"""

from evm_audit.vercel import app  # noqa: F401
