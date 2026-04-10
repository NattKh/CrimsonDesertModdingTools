#!/usr/bin/env python3
"""
Parser for Crimson Desert iteminfo_decompressed.pabgb binary format.
Parses all 5988 items with full byte preservation for roundtrip writes.

Usage:
    python iteminfo_parser.py [binary_path] [--json output.json]

See iteminfo_struct.h for the binary format specification.
"""

import struct
import json
import sys
from dataclasses import dataclass
from typing import List, Optional
from collections import Counter

FILEPATH = "iteminfo_decompressed.pabgb"
CONST_HASH = 0x9D7C0DD0


# ---------------------------------------------------------------------------
# Binary reader / writer helpers
# ---------------------------------------------------------------------------

class BinaryReader:
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.off = offset

    def u8(self):
        v = self.data[self.off]
        self.off += 1
        return v

    def u16(self):
        v, = struct.unpack_from('<H', self.data, self.off)
        self.off += 2
        return v

    def u32(self):
        v, = struct.unpack_from('<I', self.data, self.off)
        self.off += 4
        return v

    def f32(self):
        v, = struct.unpack_from('<f', self.data, self.off)
        self.off += 4
        return v

    def raw(self, n: int) -> bytes:
        v = self.data[self.off:self.off + n]
        self.off += n
        return v

    def skip(self, n: int):
        self.off += n

    def ascii(self, n: int) -> str:
        return self.raw(n).decode('ascii', errors='replace')

    def utf8(self, n: int) -> str:
        return self.raw(n).decode('utf-8', errors='replace')


class BinaryWriter:
    def __init__(self):
        self.buf = bytearray()

    def u8(self, v: int):
        self.buf.append(v & 0xFF)

    def u16(self, v: int):
        self.buf += struct.pack('<H', v)

    def u32(self, v: int):
        self.buf += struct.pack('<I', v)

    def raw(self, data: bytes):
        self.buf += data

    def ascii(self, s: str):
        self.buf += s.encode('ascii')

    def utf8(self, s: str):
        self.buf += s.encode('utf-8')

    def bytes(self) -> bytes:
        return bytes(self.buf)


# ---------------------------------------------------------------------------
# Data structures -- every byte is accounted for
# ---------------------------------------------------------------------------

@dataclass
class ItemRecord:
    # Header
    item_id: int
    name: str
    stack_size: int
    header_unk1: int

    # Sub-record 0x70
    sub70_id: int
    sub70_str: str

    # Between sub70 and sub71 (variable length)
    between_pad4: bytes         # 4 bytes (null padding after sub70 str)
    between_val1: int           # u16
    between_raw: bytes          # everything from after val1 to the 0x07 0x71 marker

    # Sub-record 0x71
    sub71_id: int
    sub71_str: str

    # Post-71 header: 17 zeros + value_a(4) + pad3(3) + extra_blocks + field_bool1(4) + pad2(2)
    post71_zeros: bytes         # 17 bytes (always zeros)
    value_a: int                # u32
    post71_pad3: bytes          # 3 bytes
    extra_blocks: bytes         # N*8 bytes (variable, between pad3 and field_bool1)
    field_bool1: int            # u32
    post71_pad2: bytes          # 2 bytes

    # Description section
    description: str            # UTF-8 text (can be empty)
    desc_null_pad: bytes        # 4 bytes: null(1) + pad(3) after description
    ref_id: int                 # u32
    postdesc_field1: int        # u32
    item_category: int          # u32

    # Between category and hash anchor
    pre_hash_pad: bytes         # typically 26 zero bytes, can be longer

    # Hash anchor section (None if no hash)
    hash_marker: Optional[int]  # u8: 0x00 or 0x01
    constant_hash: Optional[int]  # u32: 0x9D7C0DD0
    hash_pad14: Optional[bytes]   # 14 bytes
    ref_array: List[int]        # u32 array

    # Post-refs transition (None if no hash)
    flag_1: Optional[int]       # u8
    flag_2: Optional[int]       # u8
    postrefs_pad3: Optional[bytes]  # 3 bytes
    flag_3: Optional[int]       # u8

    # Everything from post-refs (or post-category for no-hash) to end of item
    tail_raw: bytes


def serialize_item(item: ItemRecord) -> bytes:
    """Serialize an ItemRecord back to binary. Exact byte-for-byte roundtrip."""
    w = BinaryWriter()

    # Header
    w.u32(item.item_id)
    w.u32(len(item.name))
    w.ascii(item.name)
    w.u8(0)  # null
    w.u32(item.stack_size)
    w.u32(item.header_unk1)

    # Sub-record 0x70
    w.u8(0x07)
    w.u32(0x70)
    w.u32(item.sub70_id)
    w.u32(len(item.sub70_str))
    w.ascii(item.sub70_str)

    # Between
    w.raw(item.between_pad4)
    w.u16(item.between_val1)
    w.raw(item.between_raw)

    # Sub-record 0x71
    w.u8(0x07)
    w.u32(0x71)
    w.u32(item.sub71_id)
    w.u32(len(item.sub71_str))
    w.ascii(item.sub71_str)

    # Post-71 header
    w.raw(item.post71_zeros)
    w.u32(item.value_a)
    w.raw(item.post71_pad3)
    w.raw(item.extra_blocks)
    w.u32(item.field_bool1)
    w.raw(item.post71_pad2)

    # Description
    desc_bytes = item.description.encode('utf-8')
    w.u32(len(desc_bytes))
    if len(desc_bytes) > 0:
        w.raw(desc_bytes)
    w.raw(item.desc_null_pad)
    w.u32(item.ref_id)
    w.u32(item.postdesc_field1)
    w.u32(item.item_category)

    # Pre-hash padding
    w.raw(item.pre_hash_pad)

    # Hash anchor + refs
    if item.hash_marker is not None:
        w.u8(item.hash_marker)
        w.u32(item.constant_hash)
        w.raw(item.hash_pad14)
        w.u32(len(item.ref_array))
        for ref in item.ref_array:
            w.u32(ref)
        w.u8(item.flag_1)
        w.u8(item.flag_2)
        w.raw(item.postrefs_pad3)
        w.u8(item.flag_3)

    # Tail
    w.raw(item.tail_raw)

    return w.bytes()


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def find_all_items(data: bytes) -> List[tuple]:
    """Scan the file for item start positions."""
    items = []
    off = 0
    end = len(data) - 16
    while off < end:
        item_id = struct.unpack_from('<I', data, off)[0]
        name_len = struct.unpack_from('<I', data, off + 4)[0]
        if 2 <= name_len <= 100 and off + 8 + name_len < len(data):
            try:
                name = data[off + 8:off + 8 + name_len].decode('ascii')
                if (all(c.isalnum() or c == '_' for c in name)
                        and data[off + 8 + name_len] == 0):
                    marker_off = off + 8 + name_len + 1 + 8
                    if (marker_off + 9 < len(data)
                            and data[marker_off] == 0x07
                            and struct.unpack_from('<I', data, marker_off + 1)[0] == 0x70
                            and struct.unpack_from('<I', data, marker_off + 5)[0] == item_id):
                        items.append((off, item_id, name))
                        off = marker_off + 20
                        continue
            except (UnicodeDecodeError, IndexError):
                pass
        off += 1
    return items


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _find_hash(data: bytes, start: int, end: int):
    """Find hash anchor. Returns (position, marker_byte) or (None, 0)."""
    for off in range(start, min(start + 500, end - 5)):
        if data[off] in (0x00, 0x01):
            if struct.unpack_from('<I', data, off + 1)[0] == CONST_HASH:
                return off, data[off]
    return None, 0


def _try_desc_at(data, dl_off, limit, hash_pos):
    """Try parsing desc at dl_off. Returns (text, len, ref, field1, cat, gap) or None."""
    if dl_off + 4 >= limit:
        return None
    desc_len = struct.unpack_from('<I', data, dl_off)[0]
    if desc_len > 500:
        return None
    text_end = dl_off + 4 + desc_len
    if text_end + 16 > limit:
        return None
    cat_off = text_end + 1 + 3 + 4 + 4
    if cat_off + 4 > limit:
        return None
    category = struct.unpack_from('<I', data, cat_off)[0]
    if category > 10:
        return None
    if desc_len > 0:
        if data[text_end] != 0:
            return None
        try:
            text = data[dl_off + 4:text_end].decode('utf-8')
        except UnicodeDecodeError:
            return None
    else:
        text = ""
    gap = (hash_pos - (cat_off + 4)) if hash_pos else -1
    ref_id = struct.unpack_from('<I', data, text_end + 4)[0]
    field1 = struct.unpack_from('<I', data, text_end + 8)[0]
    return text, desc_len, ref_id, field1, category, gap


def parse_item(data: bytes, item_off: int, next_off: int) -> Optional[ItemRecord]:
    """Parse a single item, preserving every byte for roundtrip."""
    r = BinaryReader(data, item_off)

    try:
        # -- Header --
        item_id = r.u32()
        name_len = r.u32()
        name = r.ascii(name_len)
        r.skip(1)  # null
        stack_size = r.u32()
        header_unk1 = r.u32()

        # -- Sub-record 0x70 --
        assert r.u8() == 0x07
        assert r.u32() == 0x70
        sub70_id = r.u32()
        s70_len = r.u32()
        sub70_str = r.ascii(s70_len)

        # -- Between section --
        between_pad4 = r.raw(4)
        between_val1 = r.u16()
        # Scan forward for 0x07 + u32(0x71)
        pos71 = r.off
        while pos71 < r.off + 500:
            if data[pos71] == 0x07 and struct.unpack_from('<I', data, pos71 + 1)[0] == 0x71:
                break
            pos71 += 1
        between_raw = r.raw(pos71 - r.off)

        # -- Sub-record 0x71 --
        assert r.u8() == 0x07
        assert r.u32() == 0x71
        sub71_id = r.u32()
        s71_len = r.u32()
        sub71_str = r.ascii(s71_len)

        post71 = r.off

        # -- Find hash anchor --
        hash_pos, hash_marker_byte = _find_hash(data, post71, next_off)
        search_limit = hash_pos if hash_pos else next_off

        # -- Find description offset (post71 + 38 + 8*k) --
        desc_k = None
        desc_result = None

        # Pass 1: strict (gap == 26)
        for k in range(8):
            res = _try_desc_at(data, post71 + 38 + 8 * k, search_limit, hash_pos)
            if res and res[5] == 26:
                desc_k, desc_result = k, res
                break

        # Pass 2: relaxed (any valid category)
        if desc_result is None:
            for k in range(8):
                res = _try_desc_at(data, post71 + 38 + 8 * k, search_limit, hash_pos)
                if res is not None:
                    desc_k, desc_result = k, res
                    break

        if desc_result is None:
            return None

        description, desc_len, ref_id, postdesc_field1, item_category, _ = desc_result
        desc_off = post71 + 38 + 8 * desc_k

        # -- Read post-71 header fields byte-for-byte --
        r.off = post71
        post71_zeros = r.raw(17)
        value_a = r.u32()
        post71_pad3 = r.raw(3)

        # extra_blocks: bytes between pad3 and field_bool1
        # field_bool1 is at desc_off - 6, pad2 at desc_off - 2
        fb1_off = desc_off - 6
        extra_blocks = r.raw(fb1_off - r.off)
        field_bool1 = r.u32()
        post71_pad2 = r.raw(2)

        # -- Description section --
        assert r.off == desc_off
        r.skip(4)  # desc_len (already parsed)
        if desc_len > 0:
            r.skip(desc_len)  # desc text
        desc_null_pad = r.raw(4)  # null(1) + pad(3)
        assert r.u32() == ref_id
        r.skip(4)  # postdesc_field1 (already in desc_result)
        r.off -= 4
        postdesc_field1_check = r.u32()
        assert r.u32() == item_category

        # -- Pre-hash padding / hash / refs --
        if hash_pos is not None:
            pre_hash_pad = r.raw(hash_pos - r.off)

            hash_marker = r.u8()
            constant_hash = r.u32()
            hash_pad14 = r.raw(14)
            ref_count = r.u32()
            if ref_count > 100:
                return None
            ref_array = [r.u32() for _ in range(ref_count)]

            flag_1 = r.u8()
            flag_2 = r.u8()
            postrefs_pad3 = r.raw(3)
            flag_3 = r.u8()
        else:
            pre_hash_pad = b''
            hash_marker = None
            constant_hash = None
            hash_pad14 = None
            ref_array = []
            flag_1 = None
            flag_2 = None
            postrefs_pad3 = None
            flag_3 = None

        # -- Tail: everything remaining --
        tail_raw = r.raw(next_off - r.off)

        return ItemRecord(
            item_id=item_id,
            name=name,
            stack_size=stack_size,
            header_unk1=header_unk1,
            sub70_id=sub70_id,
            sub70_str=sub70_str,
            between_pad4=between_pad4,
            between_val1=between_val1,
            between_raw=between_raw,
            sub71_id=sub71_id,
            sub71_str=sub71_str,
            post71_zeros=post71_zeros,
            value_a=value_a,
            post71_pad3=post71_pad3,
            extra_blocks=extra_blocks,
            field_bool1=field_bool1,
            post71_pad2=post71_pad2,
            description=description,
            desc_null_pad=desc_null_pad,
            ref_id=ref_id,
            postdesc_field1=postdesc_field1_check,
            item_category=item_category,
            pre_hash_pad=pre_hash_pad,
            hash_marker=hash_marker,
            constant_hash=constant_hash,
            hash_pad14=hash_pad14,
            ref_array=ref_array,
            flag_1=flag_1,
            flag_2=flag_2,
            postrefs_pad3=postrefs_pad3,
            flag_3=flag_3,
            tail_raw=tail_raw,
        )

    except Exception:
        return None


# ---------------------------------------------------------------------------
# Bulk parse / export
# ---------------------------------------------------------------------------

def parse_all_items(filepath: str) -> List[ItemRecord]:
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data):,} bytes")
    item_offsets = find_all_items(data)
    print(f"Found {len(item_offsets)} items")

    records = []
    failed = []
    for idx in range(len(item_offsets)):
        off, item_id, name = item_offsets[idx]
        next_off = item_offsets[idx + 1][0] if idx + 1 < len(item_offsets) else len(data)
        record = parse_item(data, off, next_off)
        if record:
            records.append(record)
        else:
            failed.append(name)

    print(f"Parsed: {len(records)}/{len(item_offsets)}")
    if failed:
        print(f"Failed ({len(failed)}): {', '.join(failed)}")
    return records, data, item_offsets


def item_to_dict(item: ItemRecord) -> dict:
    return {
        "item_id": item.item_id,
        "name": item.name,
        "stack_size": item.stack_size,
        "header_unk1": item.header_unk1,
        "sub70_str": item.sub70_str,
        "sub71_str": item.sub71_str,
        "value_a": item.value_a,
        "field_bool1": item.field_bool1,
        "description": item.description,
        "ref_id": item.ref_id,
        "postdesc_field1": item.postdesc_field1,
        "item_category": item.item_category,
        "ref_array": item.ref_array,
        "ref_count": len(item.ref_array),
        "flags": [item.flag_1, item.flag_2, item.flag_3],
        "icon_str": "",  # could scan tail_raw if needed
        "raw_size": (len(item.tail_raw) + len(item.name) + 100),  # approximate
    }


def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else FILEPATH
    records, data, item_offsets = parse_all_items(filepath)

    # JSON export
    output_path = "iteminfo_parsed.json"
    for i, arg in enumerate(sys.argv):
        if arg == "--json" and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]

    output = [item_to_dict(r) for r in records]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"Exported to {output_path}")

    # Roundtrip verification
    print(f"\nRoundtrip verification:")
    ok = 0
    bad = 0
    for idx, record in enumerate(records):
        off = item_offsets[idx][0]
        next_off = item_offsets[idx + 1][0] if idx + 1 < len(item_offsets) else len(data)
        original = data[off:next_off]
        rebuilt = serialize_item(record)
        if original == rebuilt:
            ok += 1
        else:
            bad += 1
            if bad <= 5:
                # Find first mismatch
                for i in range(min(len(original), len(rebuilt))):
                    if original[i] != rebuilt[i]:
                        print(f"  MISMATCH {record.name}: byte {i}/{len(original)} "
                              f"(orig=0x{original[i]:02X} got=0x{rebuilt[i]:02X})")
                        break
                else:
                    print(f"  MISMATCH {record.name}: len orig={len(original)} got={len(rebuilt)}")
    print(f"  {ok}/{ok + bad} items roundtrip OK")

    # Summary
    cats = Counter(r.item_category for r in records)
    print(f"\nTotal: {len(records)} items")
    print(f"Categories: {dict(cats.most_common())}")


if __name__ == "__main__":
    main()
