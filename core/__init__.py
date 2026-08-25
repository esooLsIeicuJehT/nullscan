"""NULLSCAN analysis core — framework-free by contract.

Nothing in this package may import from `service`. CI enforces it (see
tests/test_boundaries.py). Breaking that line is how a clean engine turns into
a web app you can never ship on-prem.
"""

from .analyzer import ENGINE_VERSION, SCHEMA_VERSION, analyze_path
from .diff import diff_reports

__all__ = ["analyze_path", "diff_reports", "ENGINE_VERSION", "SCHEMA_VERSION"]
