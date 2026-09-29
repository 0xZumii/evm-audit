"""Vercel function: GET /api/health. See evm_audit/vercel.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.vercel import health_handler, make_app  # noqa: E402

app = make_app(health_handler, methods=("GET",))
