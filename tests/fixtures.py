"""
tests.fixtures — build real AXML / DEX / APK bytes from scratch.

A binary parser you have never run against a byte stream you constructed
yourself is a guess. This module encodes the formats a second time, from the
spec, in the opposite direction. When the encoder and decoder agree, the offset
arithmetic in core/axml.py and core/dex.py is proven, not asserted.
"""

from __future__ import annotations

import struct
import zipfile

from core.axml import ANDROID_NS

# ============================== AXML ENCODER =================================
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_EL = 0x0102
RES_XML_END_EL = 0x0103

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12


class _Pool:
    def __init__(self) -> None:
        self.items: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]

    def build(self) -> bytes:
        data = bytearray()
        offsets: list[int] = []
        for s in self.items:
            offsets.append(len(data))
            enc = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"

        header_size = 28
        strings_start = header_size + len(offsets) * 4
        size = strings_start + len(data)
        out = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL, header_size, size,
            len(self.items), 0, 0, strings_start, 0,
        )
        out += b"".join(struct.pack("<I", o) for o in offsets)
        return out + bytes(data)


class AxmlBuilder:
    """Emits a byte-accurate binary AndroidManifest.xml."""

    def __init__(self) -> None:
        self.pool = _Pool()
        self._body = bytearray()
        self._ns_uri = self.pool.add(ANDROID_NS)
        self._ns_prefix = self.pool.add("android")

    def _start_ns(self) -> None:
        self._body += struct.pack(
            "<HHIIIII", RES_XML_START_NS, 16, 24, 1, 0xFFFFFFFF,
            self._ns_prefix, self._ns_uri,
        )

    def _end_ns(self) -> None:
        self._body += struct.pack(
            "<HHIIIII", RES_XML_END_NS, 16, 24, 1, 0xFFFFFFFF,
            self._ns_prefix, self._ns_uri,
        )

    def start(self, tag: str, attrs: dict[str, object] | None = None) -> AxmlBuilder:
        attrs = attrs or {}
        name_idx = self.pool.add(tag)
        packed = bytearray()
        for k, v in attrs.items():
            if k.startswith("android:"):
                ns_idx, attr_name = self._ns_uri, k.split(":", 1)[1]
            else:
                ns_idx, attr_name = 0xFFFFFFFF, k
            n_idx = self.pool.add(attr_name)

            if isinstance(v, bool):
                raw, dtype, data = 0xFFFFFFFF, TYPE_INT_BOOLEAN, (0xFFFFFFFF if v else 0)
            elif isinstance(v, int):
                raw, dtype, data = 0xFFFFFFFF, TYPE_INT_DEC, v
            else:
                s_idx = self.pool.add(str(v))
                raw, dtype, data = s_idx, TYPE_STRING, s_idx
            packed += struct.pack("<III", ns_idx, n_idx, raw)
            packed += struct.pack("<HBBI", 8, 0, dtype, data)

        size = 16 + 20 + len(packed)
        self._body += struct.pack("<HHII", RES_XML_START_EL, 16, size, 1)
        self._body += struct.pack("<I", 0xFFFFFFFF)                 # comment
        self._body += struct.pack("<II", 0xFFFFFFFF, name_idx)      # ns, name
        # attributeStart is relative to attrExt (20 == immediately after it)
        self._body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        self._body += packed
        return self

    def end(self, tag: str) -> AxmlBuilder:
        name_idx = self.pool.add(tag)
        self._body += struct.pack(
            "<HHIIIII", RES_XML_END_EL, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx
        )
        return self

    def element(self, tag: str, attrs: dict[str, object] | None = None) -> AxmlBuilder:
        return self.start(tag, attrs).end(tag)

    def build(self) -> bytes:
        pool = self.pool.build()
        body = bytes(self._body)
        # namespace chunks must precede the root element
        ns_open = struct.pack(
            "<HHIIIII", RES_XML_START_NS, 16, 24, 1, 0xFFFFFFFF,
            self._ns_prefix, self._ns_uri,
        )
        ns_close = struct.pack(
            "<HHIIIII", RES_XML_END_NS, 16, 24, 1, 0xFFFFFFFF,
            self._ns_prefix, self._ns_uri,
        )
        total = 8 + len(pool) + len(ns_open) + len(body) + len(ns_close)
        return struct.pack("<HHI", RES_XML, 8, total) + pool + ns_open + body + ns_close


# ============================== DEX ENCODER ==================================
def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex(
    *,
    class_descriptors: list[str],
    methods: list[tuple[str, str]],     # (class descriptor, method name)
    extra_strings: list[str] | None = None,
) -> bytes:
    """Emit a structurally valid DEX with populated string/type/method tables."""
    extra_strings = extra_strings or []

    strings: list[str] = []
    sidx: dict[str, int] = {}

    def s(v: str) -> int:
        if v not in sidx:
            sidx[v] = len(strings)
            strings.append(v)
        return sidx[v]

    all_types = list(dict.fromkeys(class_descriptors + [m[0] for m in methods]))
    for t in all_types:
        s(t)
    for _, mname in methods:
        s(mname)
    for e in extra_strings:
        s(e)
    s("V")  # shorty for the single proto

    type_ids = [s(t) for t in all_types]
    tidx = {t: i for i, t in enumerate(all_types)}

    header_size = 112
    string_ids_off = header_size
    string_ids_size = len(strings)
    type_ids_off = string_ids_off + string_ids_size * 4
    type_ids_size = len(type_ids)
    proto_ids_off = type_ids_off + type_ids_size * 4
    proto_ids_size = 1
    field_ids_off = proto_ids_off + proto_ids_size * 12
    field_ids_size = 0
    method_ids_off = field_ids_off + field_ids_size * 8
    method_ids_size = len(methods)
    class_defs_off = method_ids_off + method_ids_size * 8
    class_defs_size = len(class_descriptors)
    data_off = class_defs_off + class_defs_size * 32

    # string data blob
    blob = bytearray()
    data_offsets: list[int] = []
    for v in strings:
        data_offsets.append(data_off + len(blob))
        enc = v.encode("utf-8")
        blob += _uleb(len(v)) + enc + b"\x00"

    out = bytearray()
    out += b"dex\n035\x00"
    out += b"\x00" * 4                       # checksum (unverified by our parser)
    out += b"\x00" * 20                      # signature
    out += struct.pack("<I", data_off + len(blob))   # file_size
    out += struct.pack("<I", header_size)
    out += struct.pack("<I", 0x12345678)     # endian tag
    out += struct.pack("<II", 0, 0)          # link
    out += struct.pack("<I", 0)              # map_off
    out += struct.pack("<II", string_ids_size, string_ids_off)
    out += struct.pack("<II", type_ids_size, type_ids_off)
    out += struct.pack("<II", proto_ids_size, proto_ids_off)
    out += struct.pack("<II", field_ids_size, field_ids_off)
    out += struct.pack("<II", method_ids_size, method_ids_off)
    out += struct.pack("<II", class_defs_size, class_defs_off)
    out += struct.pack("<II", len(blob), data_off)
    assert len(out) == header_size, len(out)

    for off in data_offsets:
        out += struct.pack("<I", off)
    for t in type_ids:
        out += struct.pack("<I", t)
    out += struct.pack("<III", s("V"), tidx[all_types[0]], 0)   # one proto
    for cls, mname in methods:
        out += struct.pack("<HHI", tidx[cls], 0, s(mname))
    for cd in class_descriptors:
        out += struct.pack("<I", tidx[cd]) + b"\x00" * 28
    out += blob
    return bytes(out)


# ============================== APK ASSEMBLY =================================
def build_apk(
    path: str,
    manifest: bytes,
    dexes: dict[str, bytes],
    native: dict[str, int] | None = None,
) -> str:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        for name, blob in dexes.items():
            zf.writestr(name, blob)
        for lib, size in (native or {}).items():
            zf.writestr(lib, b"\x7fELF" + b"\x00" * max(0, size - 4))
        zf.writestr("resources.arsc", b"\x00" * 64)
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
    return path
