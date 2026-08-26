"""
core.signing — APK signature schemes and signer identity.

FLOW POSITION: apk bytes -> SigningFacts -> findings + diff signal.

WHY THIS IS A SEPARATE LANE FROM COMPLIANCE
    Everything else in the engine answers "what does this app collect". This
    answers "is this the publisher you think it is". A build can be perfectly
    compliant and signed by the wrong key — that is a supply-chain question,
    and it is the one that matters after a CI system is compromised.

WHY NO CRYPTOGRAPHY LIBRARY
    We need three things: which schemes are present, the SHA-256 of the signing
    certificate, and whether it is the well-known Android debug certificate.
    All three are byte-level facts. Verifying the signature mathematically
    would need a crypto library and would duplicate what `apksigner` already
    does well — and `core/` is stdlib-only by contract.

    So this module is explicit about its limit: it reports WHO signed, not
    whether the signature is valid. A tampered APK with an intact certificate
    would be reported accurately by this code and caught by apksigner. Saying
    that plainly is better than implying verification we do not perform.

FORMAT (Android APK Signing Block, before the ZIP central directory)
    uint64  size_of_block (excluding this field)
    repeated: uint64 len | uint32 id | value
    uint64  size_of_block (again)
    char[16] "APK Sig Block 42"
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
EOCD_SIG = b"PK\x05\x06"

SCHEME_IDS = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v4",          # v4 stores its data out-of-band in an .idsig
    0x2146444E: "v3.1",
}

# The debug certificate every Android SDK install generates. Identical on every
# machine, private key shipped with the SDK — so a release signed with it can
# be re-signed by literally anyone.
DEBUG_CN = "Android Debug"
DEBUG_SUBJECT_HINTS = (b"Android Debug", b"AndroidDebugKey")

_CN_OID = b"\x06\x03\x55\x04\x03"   # 2.5.4.3 commonName
_O_OID = b"\x06\x03\x55\x04\x0a"    # 2.5.4.10 organizationName


@dataclass(frozen=True, slots=True)
class Signer:
    sha256: str
    subject_cn: str
    organization: str
    is_debug: bool
    der_bytes: int


@dataclass(frozen=True, slots=True)
class SigningFacts:
    schemes: tuple[str, ...]
    signers: tuple[Signer, ...]
    v1_only: bool
    unsigned: bool
    note: str = ""


def _find_eocd(data: bytes) -> int | None:
    """Scan backwards for the End of Central Directory record."""
    # The comment field can be up to 65535 bytes, so bound the search.
    tail = data[-(65_557 + 22):] if len(data) > 65_579 else data
    idx = tail.rfind(EOCD_SIG)
    return (len(data) - len(tail) + idx) if idx != -1 else None


def _read_ascii_after_oid(der: bytes, oid: bytes) -> str:
    """Pull the printable string that follows an X.509 attribute OID.

    A deliberately shallow read rather than a full ASN.1 parser: we need a
    human-readable label for a report, not a validated structure. A malformed
    value yields an empty string instead of an exception, because a weird
    certificate must not take down a scan of an otherwise fine APK.
    """
    pos = der.find(oid)
    if pos == -1:
        return ""
    p = pos + len(oid)
    if p + 2 > len(der):
        return ""
    tag, length = der[p], der[p + 1]
    if tag not in (0x0C, 0x13, 0x16, 0x14):   # UTF8 / Printable / IA5 / Teletex
        return ""
    if length & 0x80:                          # long form: not worth chasing
        return ""
    raw = der[p + 2: p + 2 + length]
    try:
        text = raw.decode("utf-8", "replace").strip()
    except Exception:
        return ""
    return text if re.fullmatch(r"[\x20-\x7e]*", text) else ""


def _certificate(der: bytes) -> Signer:
    cn = _read_ascii_after_oid(der, _CN_OID)
    org = _read_ascii_after_oid(der, _O_OID)
    is_debug = (cn == DEBUG_CN) or any(h in der for h in DEBUG_SUBJECT_HINTS)
    return Signer(
        sha256=hashlib.sha256(der).hexdigest(),
        subject_cn=cn, organization=org,
        is_debug=is_debug, der_bytes=len(der),
    )


def _lp_sequence(buf: bytes) -> list[bytes]:
    """Split a uint32-length-prefixed sequence. Tolerates truncation."""
    out: list[bytes] = []
    p = 0
    while p + 4 <= len(buf):
        (n,) = struct.unpack_from("<I", buf, p)
        p += 4
        if n == 0 or p + n > len(buf):
            break
        out.append(buf[p:p + n])
        p += n
    return out


def _certs_from_v2_block(value: bytes) -> list[bytes]:
    """signers -> signer -> signed_data -> certificates -> DER."""
    certs: list[bytes] = []
    for signers_blob in _lp_sequence(value):
        for signer in _lp_sequence(signers_blob):
            parts = _lp_sequence(signer)
            if not parts:
                continue
            signed_data = parts[0]
            inner = _lp_sequence(signed_data)
            # inner = [digests, certificates, additional_attributes]
            if len(inner) >= 2:
                certs.extend(_lp_sequence(inner[1]))
    return certs


def analyze_signing(data: bytes, v1_present: bool) -> SigningFacts:
    """`data` is the whole APK; `v1_present` comes from META-INF inspection."""
    eocd = _find_eocd(data)
    if eocd is None:
        return SigningFacts((), (), v1_only=v1_present, unsigned=not v1_present,
                            note="no zip end-of-central-directory record")

    try:
        (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
    except struct.error:
        cd_offset = 0

    schemes: list[str] = []
    certs: list[bytes] = []

    if cd_offset > 24:
        footer = data[cd_offset - 24: cd_offset]
        if footer[8:] == APK_SIG_BLOCK_MAGIC:
            (block_size,) = struct.unpack_from("<Q", footer, 0)
            start = cd_offset - block_size - 8
            if 0 <= start < cd_offset:
                block = data[start + 8: cd_offset - 24]
                p = 0
                while p + 12 <= len(block):
                    (pair_len,) = struct.unpack_from("<Q", block, p)
                    if pair_len < 4 or p + 8 + pair_len > len(block) + 8:
                        break
                    (pair_id,) = struct.unpack_from("<I", block, p + 8)
                    value = block[p + 12: p + 8 + pair_len]
                    name = SCHEME_IDS.get(pair_id)
                    if name:
                        schemes.append(name)
                        if name in ("v2", "v3", "v3.1"):
                            certs.extend(_certs_from_v2_block(value))
                    p += 8 + pair_len

    if v1_present:
        schemes.insert(0, "v1")

    seen: set[str] = set()
    signers: list[Signer] = []
    for der in certs:
        s = _certificate(der)
        if s.sha256 not in seen:
            seen.add(s.sha256)
            signers.append(s)

    return SigningFacts(
        schemes=tuple(dict.fromkeys(schemes)),
        signers=tuple(signers),
        v1_only=bool(v1_present) and not any(s != "v1" for s in schemes),
        unsigned=not schemes,
        note="certificate identity only — signature validity is not verified here",
    )
