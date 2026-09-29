"""Vercel function: POST /api/calldata (decode layer). See evm_audit/vercel.py."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.server import calldata_payload  # noqa: E402
from evm_audit.vercel import make_app  # noqa: E402

app = make_app(calldata_payload)
