"""Vercel function for POST /api/typed-data (EIP-712 decode). See evm_audit/vercel.py.

The route keeps its hyphen via a rewrite in vercel.json; the file cannot use one
because a Vercel Python entrypoint is imported as a module.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evm_audit.server import typed_data_payload  # noqa: E402
from evm_audit.vercel import make_app  # noqa: E402

app = make_app(typed_data_payload)
