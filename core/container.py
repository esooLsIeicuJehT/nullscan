"""
core.container — hardened APK (zip) access.

FLOW POSITION: the trust boundary. Everything past this module treats bytes as
already-validated. An APK is an attacker-supplied zip; your original handler
piped it straight into a parser.

Threats handled here:
  * zip bomb        — compression ratio and total-uncompressed ceilings
  * entry flooding  — entry count ceiling
  * path traversal  — never write to disk; entries are read by exact name only
  * oversized entry — per-entry read cap
  * nested archives — not recursed into
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass

# Raised from 30_000 after a corpus run: com.m4coding.ide ships 32,461 entries
# and got rejected as hostile. An IDE bundling toolchains, fonts and templates
# is normal, not an attack. Rejecting a real customer's APK is a worse failure
# than accepting a large one — the other three ceilings still bound the work.
MAX_ENTRIES = 120_000
MAX_TOTAL_UNCOMPRESSED = 1_500 * 1024 * 1024      # 1.5 GB
MAX_ENTRY_BYTES = 300 * 1024 * 1024               # 300 MB (big DEX/obb-ish)
MAX_COMPRESSION_RATIO = 250


class ContainerError(ValueError):
    pass


@dataclass(slots=True)
class ApkContainer:
    sha256: str
    size_bytes: int
    _zf: zipfile.ZipFile

    def read(self, name: str) -> bytes:
        info = self._zf.getinfo(name)
        if info.file_size > MAX_ENTRY_BYTES:
            raise ContainerError(f"{name}: entry exceeds {MAX_ENTRY_BYTES} bytes")
        with self._zf.open(info, "r") as fh:
            return fh.read(MAX_ENTRY_BYTES + 1)[:MAX_ENTRY_BYTES]

    def names(self) -> list[str]:
        return self._zf.namelist()

    def dex_names(self) -> list[str]:
        """classes.dex, classes2.dex ... in load order."""
        def order(n: str) -> int:
            stem = n[len("classes"):-len(".dex")]
            return int(stem) if stem.isdigit() else 1

        found = [
            n for n in self._zf.namelist()
            if n.startswith("classes") and n.endswith(".dex") and "/" not in n
        ]
        return sorted(found, key=order)

    def native_libs(self) -> list[tuple[str, str, int]]:
        """(path, abi, uncompressed_size) for every lib/<abi>/*.so"""
        out = []
        for info in self._zf.infolist():
            parts = info.filename.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                out.append((info.filename, parts[1], info.file_size))
        return out

    def close(self) -> None:
        self._zf.close()

    def __enter__(self) -> "ApkContainer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_apk(path: str) -> ApkContainer:
    """Open and validate. Raises ContainerError on anything suspicious."""
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
            total += len(chunk)

    try:
        zf = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise ContainerError(f"not a valid zip/APK: {exc}") from exc

    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        zf.close()
        raise ContainerError(f"entry count {len(infos)} exceeds {MAX_ENTRIES}")

    uncompressed = sum(i.file_size for i in infos)
    if uncompressed > MAX_TOTAL_UNCOMPRESSED:
        zf.close()
        raise ContainerError(f"uncompressed size {uncompressed} exceeds ceiling")

    compressed = sum(i.compress_size for i in infos) or 1
    if uncompressed / compressed > MAX_COMPRESSION_RATIO:
        zf.close()
        raise ContainerError(
            f"compression ratio {uncompressed / compressed:.0f}:1 looks like a zip bomb"
        )

    if "AndroidManifest.xml" not in zf.namelist():
        zf.close()
        raise ContainerError("no AndroidManifest.xml — not an APK")

    return ApkContainer(sha256=digest.hexdigest(), size_bytes=total, _zf=zf)
