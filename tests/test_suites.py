"""
tests.test_suites — makes the standalone suites discoverable.

THE BUG THIS FIXES
    `python -m unittest discover` reported "Ran 0 tests / NO TESTS RAN" and
    exited 0. So did pytest. Both suites work when run directly, but neither
    exposes TestCase classes, so a normal CI pipeline would have gone green
    while executing nothing at all — the worst possible failure for a test
    suite, because it is indistinguishable from success.

WHY SUBPROCESS RATHER THAN REWRITING 145 CHECKS
    Rewriting every check into a TestCase method is a large mechanical diff
    across working tests, and it would change what runs. Shelling out runs
    EXACTLY what a human runs, so the discovered result and the direct result
    can never disagree.

WHY THE COUNT FLOOR
    Asserting "0 failures" is not enough: a suite that collects nothing also
    has 0 failures. Each case pins a minimum count, so silently losing tests —
    an import error swallowed, a section deleted, a file renamed — fails the
    build instead of quietly shrinking coverage.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULT = re.compile(r"(\d+)\s+passed,\s+(\d+)\s+failed")

# Raise these when you add tests; never lower them to make a build pass.
MIN_ENGINE_TESTS = 71
MIN_SERVICE_TESTS = 95


def _run(script: str, timeout: int) -> tuple[int, int, str]:
    """Returns (passed, failed, output). Raises on non-zero exit."""
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests", script)],
        capture_output=True, text=True, timeout=timeout, cwd=ROOT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    out = proc.stdout + proc.stderr
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    m = None
    for m in RESULT.finditer(clean):
        pass
    if m is None:
        raise AssertionError(
            f"{script} produced no result line — it likely crashed on import.\n"
            f"exit={proc.returncode}\n{clean[-2500:]}"
        )
    return int(m.group(1)), int(m.group(2)), clean


class EngineSuite(unittest.TestCase):
    """core/ — parsers, pipeline, diff, container hardening. No dependencies."""

    def test_engine_suite_passes(self) -> None:
        passed, failed, out = _run("test_engine.py", timeout=600)
        self.assertEqual(failed, 0, f"{failed} engine test(s) failed\n{out[-3000:]}")
        self.assertGreaterEqual(
            passed, MIN_ENGINE_TESTS,
            f"engine suite ran {passed} tests, expected at least "
            f"{MIN_ENGINE_TESTS}. Tests went missing — do not lower the floor "
            f"to make this pass.",
        )


class ServiceSuite(unittest.TestCase):
    """service/ — HTTP contract, quota, billing, key delivery. Needs FastAPI."""

    def setUp(self) -> None:
        try:
            import fastapi  # noqa: F401
        except ImportError:
            self.skipTest("fastapi not installed (expected on Termux)")

    def test_service_suite_passes(self) -> None:
        passed, failed, out = _run("test_service.py", timeout=900)
        self.assertEqual(failed, 0, f"{failed} service test(s) failed\n{out[-3000:]}")
        self.assertGreaterEqual(
            passed, MIN_SERVICE_TESTS,
            f"service suite ran {passed} tests, expected at least "
            f"{MIN_SERVICE_TESTS}.",
        )


class Boundaries(unittest.TestCase):
    """The architectural invariant, checked independently of the suites.

    core/ importing a web framework is not a style issue: it would end the
    ability to ship the engine as a CLI, a CI binary, or an on-prem wheel. It
    gets its own discoverable test so it fails even if everything else is
    skipped.
    """

    def test_core_imports_no_third_party(self) -> None:
        import ast

        stdlib = set(sys.stdlib_module_names)
        local = {"core", "service", "tests", "tools", "cli", "fixtures"}
        offenders: list[str] = []

        for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "core")):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                path = os.path.join(dirpath, fname)
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), path)
                for node in ast.walk(tree):
                    mods: list[str] = []
                    if isinstance(node, ast.Import):
                        mods = [a.name.split(".")[0] for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                        mods = [node.module.split(".")[0]]
                    for mod in mods:
                        if mod not in stdlib and mod not in local:
                            offenders.append(f"{fname}: {mod}")

        self.assertEqual(offenders, [], f"core/ gained dependencies: {offenders}")

    def test_cli_does_not_import_service(self) -> None:
        with open(os.path.join(ROOT, "cli.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("from service", src)
        self.assertNotIn("import service", src)


class StaticGates(unittest.TestCase):
    """Lint findings that were hand-fixed and must not creep back."""

    def test_no_bare_assert_in_request_path(self) -> None:
        # `python -O` strips asserts. An assert guarding a real precondition
        # becomes a confusing AttributeError three frames away in production.
        with open(os.path.join(ROOT, "service", "jobs.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("assert self._pool", src)

    def test_outbound_urls_are_https_only(self) -> None:
        from service.billing import StripeError, _require_https

        for bad in ("http://api.stripe.com/v1", "file:///etc/passwd", "ftp://x"):
            with self.assertRaises(StripeError, msg=f"{bad} was accepted"):
                _require_https(bad)
        _require_https("https://api.stripe.com/v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
