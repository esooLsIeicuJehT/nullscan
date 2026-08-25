"""
core.dex — Dalvik executable table parser.

FLOW POSITION: bytes -> DexTables -> consumed by signatures.py.

DELIBERATE SCOPE LIMIT: we parse the *reference tables* (strings, types,
methods, fields), not the bytecode of every method body. For compliance
scanning that is the correct trade. A method reference to
`Landroid/telephony/TelephonyManager;->getImei` is proof the API is linked
into the app; walking the instruction stream to confirm it is *reachable*
costs ~40x the CPU and changes the answer for a tiny minority of apps.

If reachability ever matters (it will, for the "dead code" false-positive
complaint), that becomes a separate opt-in pass behind the same interface —
the boundary is already drawn here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

DEX_MAGICS = {b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
              b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00"}

HEADER_FMT_OFFSETS = {
    "string_ids_size": 56, "string_ids_off": 60,
    "type_ids_size": 64, "type_ids_off": 68,
    "proto_ids_size": 72, "proto_ids_off": 76,
    "field_ids_size": 80, "field_ids_off": 84,
    "method_ids_size": 88, "method_ids_off": 92,
    "class_defs_size": 96, "class_defs_off": 100,
}


class DexError(ValueError):
    pass


@dataclass(slots=True)
class DexTables:
    name: str
    strings: list[str]
    types: list[str]                     # descriptors, e.g. "Lcom/foo/Bar;"
    method_refs: list[str]               # "Lcom/foo/Bar;->method"
    field_refs: list[str]                # "Lcom/foo/Bar;->field"
    defined_classes: list[str]

    @property
    def type_set(self) -> set[str]:
        return set(self.types)


def _uleb128(buf: bytes, p: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return p, result
        shift += 7
        if shift > 35:
            raise DexError("uleb128 overflow")


def _mutf8(buf: bytes, p: int) -> str:
    """Read a null-terminated MUTF-8 string. Tolerates encoder quirks."""
    end = buf.index(b"\x00", p)
    return buf[p:end].decode("utf-8", "replace")


def _cap(count: int, off: int, item_bytes: int, buflen: int, hard: int) -> int:
    """Clamp a header-declared table size to what the buffer can physically hold.

    A truncated or hostile DEX declares string_ids_size = 0xFFFFFFFF. Trusting it
    means `range(4_294_967_295)` — the worker pegs a core until the job timeout
    fires. Cheapest possible denial of service against a scanning service, and
    it costs three lines to close.
    """
    if off <= 0 or off >= buflen or count <= 0:
        return 0
    return min(count, hard, (buflen - off) // item_bytes)


def parse_dex(buf: bytes, name: str = "classes.dex", *, max_strings: int = 400_000) -> DexTables:
    if len(buf) < 112 or buf[:8] not in DEX_MAGICS:
        raise DexError(f"{name}: bad DEX magic")

    blen = len(buf)

    def u32(off: int) -> int:
        return struct.unpack_from("<I", buf, off)[0]

    h = {k: u32(v) for k, v in HEADER_FMT_OFFSETS.items()}

    for key, item, hard in (
        ("string_ids", 4, max_strings),
        ("type_ids", 4, 200_000),
        ("proto_ids", 12, 200_000),
        ("field_ids", 8, 400_000),
        ("method_ids", 8, 400_000),
        ("class_defs", 32, 100_000),
    ):
        declared = h[f"{key}_size"]
        h[f"{key}_size"] = _cap(declared, h[f"{key}_off"], item, blen, hard)
        if declared and not h[f"{key}_size"]:
            # header points outside the file — record it rather than pretending
            h.setdefault("_truncated", 0)

    if not any(h[f"{k}_size"] for k in
               ("string_ids", "type_ids", "method_ids", "class_defs")):
        raise DexError(f"{name}: header tables all point outside the file")

    # --- strings -------------------------------------------------------------
    n_strings = h["string_ids_size"]
    strings: list[str] = []
    so = h["string_ids_off"]
    for i in range(n_strings):
        try:
            data_off = u32(so + i * 4)
            p, _utf16_len = _uleb128(buf, data_off)
            strings.append(_mutf8(buf, p))
        except (struct.error, IndexError, ValueError):
            strings.append("")

    def s(idx: int) -> str:
        return strings[idx] if 0 <= idx < len(strings) else ""

    # --- types ---------------------------------------------------------------
    types: list[str] = []
    to = h["type_ids_off"]
    for i in range(h["type_ids_size"]):
        try:
            types.append(s(u32(to + i * 4)))
        except struct.error:
            types.append("")

    def t(idx: int) -> str:
        return types[idx] if 0 <= idx < len(types) else ""

    # --- methods -------------------------------------------------------------
    method_refs: list[str] = []
    mo = h["method_ids_off"]
    for i in range(h["method_ids_size"]):
        try:
            class_idx, _proto_idx, name_idx = struct.unpack_from("<HHI", buf, mo + i * 8)
            method_refs.append(f"{t(class_idx)}->{s(name_idx)}")
        except struct.error:
            break

    # --- fields --------------------------------------------------------------
    field_refs: list[str] = []
    fo = h["field_ids_off"]
    for i in range(h["field_ids_size"]):
        try:
            class_idx, _type_idx, name_idx = struct.unpack_from("<HHI", buf, fo + i * 8)
            field_refs.append(f"{t(class_idx)}->{s(name_idx)}")
        except struct.error:
            break

    # --- defined classes (vs merely referenced) ------------------------------
    defined: list[str] = []
    co = h["class_defs_off"]
    for i in range(h["class_defs_size"]):
        try:
            (class_idx,) = struct.unpack_from("<I", buf, co + i * 32)
            defined.append(t(class_idx))
        except struct.error:
            break

    return DexTables(
        name=name,
        strings=strings,
        types=types,
        method_refs=method_refs,
        field_refs=field_refs,
        defined_classes=defined,
    )
