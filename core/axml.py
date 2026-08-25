"""
core.axml — binary AndroidManifest.xml (AXML) decoder.

FLOW POSITION: bytes -> structured element tree -> ManifestFacts.
No aapt2, no apktool, no subprocess. Pure stdlib so the whole engine can run
in a locked-down container and be shipped as an on-prem wheel.

Format reference (AOSP ResourceTypes.h):
  ResChunk_header { u16 type; u16 headerSize; u32 size; }
  Chunks appear sequentially; unknown chunk types are skipped by `size`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# --- chunk types -------------------------------------------------------------
RES_NULL = 0x0000
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

# --- typed value data types --------------------------------------------------
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 1 << 8

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Fallback attribute-name resolution. Modern AAPT2 and several obfuscators emit
# an EMPTY string-pool entry for attribute names and rely on the resource-map
# chunk instead. Without this table you silently read every attribute as "".
# Extend as needed; unresolved IDs fall through to "attr_0x...".
ATTR_RES_IDS: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010004: "manageSpaceActivity",
    0x01010005: "allowClearUserData",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000A: "permissionGroup",
    0x0101000B: "sharedUserId",
    0x0101000C: "hasCode",
    0x0101000D: "persistent",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010012: "taskAffinity",
    0x01010013: "multiprocess",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010527: "networkSecurityConfig",
    0x01010604: "usesCleartextTraffic",
}


class AxmlError(ValueError):
    """Raised when the byte stream is not decodable AXML."""


@dataclass(slots=True)
class XmlNode:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list["XmlNode"] = field(default_factory=list)

    def find_all(self, tag: str) -> list["XmlNode"]:
        out: list[XmlNode] = []
        stack = [self]
        while stack:
            node = stack.pop()
            if node.tag == tag:
                out.append(node)
            stack.extend(node.children)
        return out

    def get(self, name: str, default: str | None = None) -> str | None:
        """Attribute lookup that ignores the android: prefix."""
        if name in self.attrs:
            return self.attrs[name]
        return self.attrs.get(f"android:{name}", default)


class _StringPool:
    __slots__ = ("strings",)

    def __init__(self, strings: list[str]) -> None:
        self.strings = strings

    def at(self, idx: int) -> str:
        if idx < 0 or idx >= len(self.strings):
            return ""
        return self.strings[idx]


def _read_string_pool(buf: bytes, off: int) -> tuple[_StringPool, int]:
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", buf, off)
    if chunk_type != RES_STRING_POOL:
        raise AxmlError(f"expected string pool at {off:#x}, got {chunk_type:#x}")

    string_count, style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", buf, off + 8
    )
    is_utf8 = bool(flags & UTF8_FLAG)

    offsets_base = off + header_size
    data_base = off + strings_start
    strings: list[str] = []

    for i in range(string_count):
        (rel,) = struct.unpack_from("<I", buf, offsets_base + i * 4)
        p = data_base + rel
        try:
            if is_utf8:
                # two length fields: utf16 char count, then byte count.
                p, _ = _decode_len8(buf, p)
                p, nbytes = _decode_len8(buf, p)
                strings.append(buf[p : p + nbytes].decode("utf-8", "replace"))
            else:
                p, nchars = _decode_len16(buf, p)
                strings.append(buf[p : p + nchars * 2].decode("utf-16-le", "replace"))
        except (struct.error, IndexError):
            strings.append("")

    return _StringPool(strings), off + chunk_size


def _decode_len8(buf: bytes, p: int) -> tuple[int, int]:
    """UTF-8 pool length: high bit set means two bytes."""
    v = buf[p]
    if v & 0x80:
        return p + 2, ((v & 0x7F) << 8) | buf[p + 1]
    return p + 1, v


def _decode_len16(buf: bytes, p: int) -> tuple[int, int]:
    """UTF-16 pool length: high bit set means two u16s."""
    (v,) = struct.unpack_from("<H", buf, p)
    if v & 0x8000:
        (v2,) = struct.unpack_from("<H", buf, p + 2)
        return p + 4, ((v & 0x7FFF) << 16) | v2
    return p + 2, v


def _format_value(pool: _StringPool, raw_idx: int, dtype: int, data: int) -> str:
    if raw_idx != 0xFFFFFFFF:
        s = pool.at(raw_idx)
        if s:
            return s
    if dtype == TYPE_STRING:
        return pool.at(data)
    if dtype == TYPE_INT_BOOLEAN:
        return "true" if data != 0 else "false"
    if dtype == TYPE_INT_HEX:
        return f"{data:#x}"
    if dtype == TYPE_REFERENCE:
        return f"@{data:#010x}"
    if dtype == TYPE_ATTRIBUTE:
        return f"?{data:#010x}"
    if dtype == TYPE_NULL:
        return ""
    if dtype == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data))[0])
    # TYPE_INT_DEC and anything else numeric
    return str(struct.unpack("<i", struct.pack("<I", data))[0])


def parse_axml(buf: bytes) -> XmlNode:
    """Decode AXML bytes into a node tree. Raises AxmlError on malformed input."""
    if len(buf) < 8:
        raise AxmlError("buffer too small")

    chunk_type, header_size, total = struct.unpack_from("<HHI", buf, 0)
    if chunk_type != RES_XML:
        raise AxmlError(f"not an AXML file (magic {chunk_type:#x})")
    if total > len(buf):
        total = len(buf)  # tolerate truncation rather than dying

    pos = header_size
    pool: _StringPool | None = None
    res_map: list[int] = []

    root = XmlNode(tag="#root")
    stack: list[XmlNode] = [root]

    while pos + 8 <= total:
        ctype, chdr, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8:
            break  # corrupt; refuse to spin

        if ctype == RES_STRING_POOL:
            pool, _ = _read_string_pool(buf, pos)

        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - chdr) // 4
            res_map = list(struct.unpack_from(f"<{n}I", buf, pos + chdr))

        elif ctype == RES_XML_START_ELEMENT and pool is not None:
            node = _read_start_element(buf, pos, chdr, pool, res_map)
            stack[-1].children.append(node)
            stack.append(node)

        elif ctype == RES_XML_END_ELEMENT:
            if len(stack) > 1:
                stack.pop()

        pos += csize

    if not root.children:
        raise AxmlError("no elements decoded")
    return root.children[0]


def _read_start_element(
    buf: bytes, pos: int, chdr: int, pool: _StringPool, res_map: list[int]
) -> XmlNode:
    _ns_idx, name_idx = struct.unpack_from("<II", buf, pos + 8 + 8)
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", buf, pos + 8 + 16)

    node = XmlNode(tag=pool.at(name_idx))
    # attributeStart is relative to the START OF ResXMLTree_attrExt, which begins
    # at pos + headerSize (16) — not to the start of the chunk. Off-by-16 here
    # reads garbage that still parses, which is the worst kind of bug.
    base = pos + chdr + attr_start
    stride = attr_size or 20

    for i in range(attr_count):
        a = base + i * stride
        if a + 20 > len(buf):
            break
        # attribute = { u32 ns; u32 name; u32 rawValue;
        #               Res_value { u16 size; u8 res0; u8 dataType; u32 data } }
        a_ns, a_name, a_raw = struct.unpack_from("<III", buf, a)
        _vsize, _res0, a_type, a_data = struct.unpack_from("<HBBI", buf, a + 12)

        name = pool.at(a_name)
        if not name:
            # The resource map is a PARALLEL ARRAY TO THE STRING POOL, not to the
            # attribute list. Indexing it by attribute position is the classic bug
            # here and produces plausible-but-wrong attribute names.
            rid = res_map[a_name] if a_name < len(res_map) else 0
            name = ATTR_RES_IDS.get(rid, f"attr_{rid:#010x}")

        if pool.at(a_ns) == ANDROID_NS:
            name = f"android:{name}"

        node.attrs[name] = _format_value(pool, a_raw, a_type, a_data)

    return node
