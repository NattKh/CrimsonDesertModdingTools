#!/usr/bin/env python3
"""
CharacterInfo PABGB Parser — finds _terrainRegionAutoSpawnInfo and
_terrainRegionSpawnPerCount for every entry in characterinfo.pabgb.

Strategy
--------
Parsing every field sequentially from the decompiled deserializer
(sub_141037900) is impractical because many "complex" reader functions
(sub_14105FXXX, sub_1410765F0, etc.) consume variable numbers of bytes
and their exact format is not fully reverse-engineered.

Instead we use an empirical **anchor-based** approach:

1.  Every characterinfo entry contains the value 100000 (0x000186A0)
    one or more times.  The *last* occurrence sits at a fixed position
    relative to the two target fields.
2.  _terrainRegionAutoSpawnInfo (u32) is at anchor + 36.
3.  _terrainRegionSpawnPerCount (u32) is at anchor + 40.

This was validated against all 6 872 entries in the 2026-04-06 game data.

Binary layout (44 bytes from the anchor):
    +0   u32  100000          (the anchor value)
    +4   u32  0               (9 consecutive zero u32s — other fields
    +8   u32  0                that are typically unused)
    ...
    +32  u32  0
    +36  u32  _terrainRegionAutoSpawnInfo   (terrain region key, usually 0)
    +40  u32  _terrainRegionSpawnPerCount   (spawn count per region, 0-50)

Usage
-----
    from characterinfo_parser import find_spawn_fields

    pabgb = open("characterinfo.pabgb", "rb").read()
    pabgh = open("characterinfo.pabgh", "rb").read()
    result = find_spawn_fields(pabgb, pabgh)
    # result: {char_key: (spawn_count_offset, spawn_count_value,
    #                     terrain_key_offset, terrain_key_value)}
"""

from __future__ import annotations

import os
import struct
import sys
from typing import Dict, Tuple

# ---------------------------------------------------------------------------
# PABGH index parser
# ---------------------------------------------------------------------------

def parse_pabgh_index(pabgh_data: bytes) -> Dict[int, int]:
    """Parse characterinfo.pabgh.  Returns {entry_key: byte_offset}."""
    # characterinfo is NOT in the UINT_COUNT_TABLES set -> u16 count
    count = struct.unpack_from('<H', pabgh_data, 0)[0]

    # Derive key size from file geometry
    total_key_bytes = len(pabgh_data) - 2 - count * 4
    key_size = total_key_bytes // count
    assert key_size * count == total_key_bytes, (
        f"key_size calc: {total_key_bytes} / {count} = {total_key_bytes / count}"
    )

    offsets: Dict[int, int] = {}
    pos = 2  # after u16 count
    for _ in range(count):
        key = int.from_bytes(pabgh_data[pos:pos + key_size], 'little')
        offset = struct.unpack_from('<I', pabgh_data, pos + key_size)[0]
        offsets[key] = offset
        pos += key_size + 4

    return offsets


def compute_entry_sizes(offsets: Dict[int, int],
                        pabgb_size: int) -> Dict[int, int]:
    """Compute each entry's byte length from the sorted offset list."""
    sorted_items = sorted(offsets.items(), key=lambda kv: kv[1])
    sizes: Dict[int, int] = {}
    for i, (key, off) in enumerate(sorted_items):
        if i + 1 < len(sorted_items):
            sizes[key] = sorted_items[i + 1][1] - off
        else:
            sizes[key] = pabgb_size - off
    return sizes


# ---------------------------------------------------------------------------
# Entry header parser
# ---------------------------------------------------------------------------

def parse_entry_header(data: bytes, offset: int) -> Tuple[int, str, int]:
    """Parse the entry header at *offset*.

    Returns (entry_key, entry_name, payload_start_offset).
    """
    entry_key = struct.unpack_from('<I', data, offset)[0]
    name_len = struct.unpack_from('<I', data, offset + 4)[0]
    name_start = offset + 8
    name = data[name_start:name_start + name_len].decode('utf-8', errors='replace')
    # +1 for the null terminator
    payload_start = name_start + name_len + 1
    return entry_key, name, payload_start


# ---------------------------------------------------------------------------
# Anchor-based spawn field finder
# ---------------------------------------------------------------------------

_ANCHOR = b'\xa0\x86\x01\x00'   # 100000 as u32 LE
_ANCHOR_TO_TERRAIN = 36          # bytes from anchor to terrain key field
_ANCHOR_TO_SPAWN   = 40          # bytes from anchor to spawn count field


def _find_last_anchor(entry_bytes: bytes) -> int:
    """Return the offset of the LAST 0x000186A0 u32 in *entry_bytes*,
    or -1 if not found."""
    pos = 0
    last = -1
    while True:
        idx = entry_bytes.find(_ANCHOR, pos)
        if idx == -1:
            return last
        last = idx
        pos = idx + 1


def find_spawn_fields(
    pabgb_data: bytes,
    pabgh_data: bytes,
) -> Dict[int, Tuple[int, int, int, int]]:
    """Locate _terrainRegionSpawnPerCount and _terrainRegionAutoSpawnInfo
    for every entry in characterinfo.pabgb.

    Parameters
    ----------
    pabgb_data : bytes
        Raw contents of characterinfo.pabgb.
    pabgh_data : bytes
        Raw contents of characterinfo.pabgh.

    Returns
    -------
    dict
        ``{char_key: (spawn_count_offset, spawn_count_value,
                      terrain_key_offset, terrain_key_value)}``

        *spawn_count_offset* and *terrain_key_offset* are **absolute**
        byte offsets within *pabgb_data*.
    """
    offsets = parse_pabgh_index(pabgh_data)
    sizes = compute_entry_sizes(offsets, len(pabgb_data))

    result: Dict[int, Tuple[int, int, int, int]] = {}

    for char_key, entry_offset in offsets.items():
        entry_size = sizes[char_key]
        entry = pabgb_data[entry_offset:entry_offset + entry_size]

        anchor_pos = _find_last_anchor(entry)
        if anchor_pos < 0:
            # Should never happen for valid characterinfo data
            continue

        # Terrain region key (field 122 in the decompile)
        terrain_rel = anchor_pos + _ANCHOR_TO_TERRAIN
        if terrain_rel + 4 > entry_size:
            continue
        terrain_key_abs = entry_offset + terrain_rel
        terrain_key_val = struct.unpack_from('<I', pabgb_data, terrain_key_abs)[0]

        # Spawn per count (field 123 in the decompile)
        spawn_rel = anchor_pos + _ANCHOR_TO_SPAWN
        if spawn_rel + 4 > entry_size:
            continue
        spawn_count_abs = entry_offset + spawn_rel
        spawn_count_val = struct.unpack_from('<I', pabgb_data, spawn_count_abs)[0]

        result[char_key] = (
            spawn_count_abs,   # absolute offset of _terrainRegionSpawnPerCount
            spawn_count_val,   # value of _terrainRegionSpawnPerCount
            terrain_key_abs,   # absolute offset of _terrainRegionAutoSpawnInfo
            terrain_key_val,   # value of _terrainRegionAutoSpawnInfo
        )

    return result


# ---------------------------------------------------------------------------
# CLI diagnostics
# ---------------------------------------------------------------------------

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    paz_dir = os.path.normpath(os.path.join(base, '..', 'extractedpaz', '0008_full'))

    pabgb_path = os.path.join(paz_dir, 'characterinfo.pabgb')
    pabgh_path = os.path.join(paz_dir, 'characterinfo.pabgh')

    if not os.path.isfile(pabgb_path) or not os.path.isfile(pabgh_path):
        print(f"ERROR: characterinfo files not found in {paz_dir}")
        sys.exit(1)

    pabgb = open(pabgb_path, 'rb').read()
    pabgh = open(pabgh_path, 'rb').read()

    print(f"characterinfo.pabgb : {len(pabgb):,} bytes")
    print(f"characterinfo.pabgh : {len(pabgh):,} bytes")
    print()

    result = find_spawn_fields(pabgb, pabgh)
    print(f"Entries parsed: {len(result)}")

    # --- Collect entry names for diagnostics ---
    offsets = parse_pabgh_index(pabgh)
    entry_names: Dict[int, str] = {}
    for char_key, off in offsets.items():
        _, name, _ = parse_entry_header(pabgb, off)
        entry_names[char_key] = name

    # --- Distribution ---
    spawn_dist: Dict[int, int] = {}
    terrain_dist: Dict[int, int] = {}
    for char_key, (sc_off, sc_val, tk_off, tk_val) in result.items():
        spawn_dist[sc_val] = spawn_dist.get(sc_val, 0) + 1
        terrain_dist[tk_val] = terrain_dist.get(tk_val, 0) + 1

    print()
    print("_terrainRegionSpawnPerCount distribution:")
    for val, cnt in sorted(spawn_dist.items()):
        pct = cnt * 100.0 / len(result)
        print(f"  {val:5d}: {cnt:5d} entries ({pct:5.1f}%)")

    print()
    print("_terrainRegionAutoSpawnInfo distribution:")
    for val, cnt in sorted(terrain_dist.items()):
        pct = cnt * 100.0 / len(result)
        print(f"  {val:5d}: {cnt:5d} entries ({pct:5.1f}%)")

    # --- Verification with specific entries ---
    print()
    print("=== Verification: specific entries ===")
    check_keys = {
        1:        "Kliff (main character)",
        4:        "Damian",
        6:        "Oongka",
        100:      "key 100",
        3002:     "NHM_Citizen_Dyer (town NPC)",
        30030:    "Animal_Wild_Boar_Wild",
        1003537:  "WorldObserver (system)",
    }
    for ck, label in check_keys.items():
        if ck not in result:
            print(f"  {label} (key={ck}): NOT FOUND")
            continue
        sc_off, sc_val, tk_off, tk_val = result[ck]
        name = entry_names.get(ck, "???")
        print(f"  {name} (key={ck}):")
        print(f"    _terrainRegionAutoSpawnInfo  @ 0x{tk_off:08X} = {tk_val}")
        print(f"    _terrainRegionSpawnPerCount  @ 0x{sc_off:08X} = {sc_val}")

    # --- Cross-check: values should be in range ---
    print()
    print("=== Cross-check: value ranges ===")
    bad_spawn = [k for k, (_, v, _, _) in result.items() if v > 50]
    bad_terrain = [k for k, (_, _, _, v) in result.items()
                   if v != 0 and v > 100000]
    print(f"  Spawn count > 50:    {len(bad_spawn)} entries")
    print(f"  Terrain key > 100K:  {len(bad_terrain)} entries")
    if bad_spawn:
        for k in bad_spawn[:5]:
            print(f"    key={k}: spawn={result[k][1]}")
    if bad_terrain:
        for k in bad_terrain[:5]:
            print(f"    key={k}: terrain={result[k][3]}")

    # --- Show entries grouped by spawn count for each unique value ---
    print()
    print("=== Sample entries per spawn value ===")
    by_spawn: Dict[int, list] = {}
    for ck, (_, sv, _, _) in result.items():
        by_spawn.setdefault(sv, []).append(ck)
    for sv in sorted(by_spawn):
        keys = by_spawn[sv]
        samples = keys[:3]
        names = [entry_names.get(k, f"key={k}") for k in samples]
        extra = f" (+{len(keys)-3} more)" if len(keys) > 3 else ""
        print(f"  spawn={sv:2d}: {', '.join(names)}{extra}")

    print()
    print("Done.")


if __name__ == '__main__':
    main()
