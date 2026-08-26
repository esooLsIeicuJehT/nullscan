"""NULLSCAN analysis core — framework-free by contract.

Nothing in this package may import from `service`. CI enforces it (see
tests/test_boundaries.py). Breaking that line is how a clean engine turns into
a web app you can never ship on-prem.
"""

from .analyzer import ENGINE_VERSION, SCHEMA_VERSION, analyze_path
from .diff import diff_reports
from .policy import DEFAULT_POLICY_TOML, Policy, PolicyError
from .sbom import build_sbom
from .sbom import to_json as sbom_json

__all__ = [
    "DEFAULT_POLICY_TOML",
    "ENGINE_VERSION",
    "SCHEMA_VERSION",
    "Policy",
    "PolicyError",
    "analyze_path",
    "build_sbom",
    "diff_reports",
    "sbom_json",
]
