"""Vercel function: GET /api/address (Sourcify source). See evm_audit/vercel.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.vercel import address_handler, make_app  # noqa: E402

app = make_app(address_handler, methods=("GET",))
