"""Vercel function: POST /api/allowances.

Deliberately answers 501: the scan needs hundreds of eth_getLogs calls and does
not fit a serverless timeout. See evm_audit/vercel.py.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.vercel import allowances_disabled, make_app  # noqa: E402

app = make_app(allowances_disabled)
