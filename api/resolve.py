"""Vercel function: GET /api/resolve (proxy resolution). See evm_audit/vercel.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.vercel import make_app, resolve_handler  # noqa: E402

app = make_app(resolve_handler, methods=("GET",))
