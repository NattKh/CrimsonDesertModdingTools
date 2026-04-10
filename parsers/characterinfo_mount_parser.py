#!/usr/bin/env python3
"""CharacterInfo mount/vehicle field parser — extracts ride duration, cooldown,
and vehicle type from characterinfo.pabgb using the IDA-decoded reader order
(sub_141037900).

Only parses the header + early scalar fields needed for mount editing.
Skips the complex arrays/stats in the tail of each entry.
"""

import struct
import json
import os
import sys
import logging

log = logging.getLogger(__name__)

# ── PABGH index ──────────────────────────────────────────────────────────

def parse_pabgh_index(pabgh_data):
    """Parse characterinfo.pabgh: u16 count, then count * (u32 key + u32 offset)."""
    count = struct.unpack_from('<H', pabgh_data, 0)[0]
    entries = {}
    pos = 2
    for _ in range(count):
        key = struct.unpack_from('<I', pabgh_data, pos)[0]
        offset = struct.unpack_from('<I', pabgh_data, pos + 4)[0]
        entries[key] = offset
        pos += 8
    return entries


# ── Entry header parser ──────────────────────────────────────────────────

def _read_cstring(data, p):
    """Read u32-length-prefixed string, return (string, new_pos)."""
    slen = struct.unpack_from('<I', data, p)[0]
    p += 4
    if slen > 100000:
        return None, p
    s = data[p:p + slen].decode('utf-8', errors='replace')
    return s, p + slen


def _read_locstr(data, p):
    """Read LocalizableString: u8 flag + u64 hash + CString. Return new_pos."""
    p += 1  # flag
    p += 8  # hash
    slen = struct.unpack_from('<I', data, p)[0]
    p += 4 + slen
    return p


def _read_enum4_hash(data, p):
    """Read u32 from stream (sub_1408F5560_0_1335 pattern: reads 4B, stores u16)."""
    return p + 4


def parse_mount_fields(data, offset, end):
    """Parse one CharacterInfo entry and extract mount-relevant fields.

    Returns dict with mount fields + byte offsets for in-place editing, or None on failure.
    """
    p = offset
    result = {}

    try:
        # H0: entry_id (u32, 4B) — stream.read(a2[0], 4)
        result['entry_key'] = struct.unpack_from('<I', data, p)[0]; p += 4

        # H1: entry_name (CString via sub_14100FE80)
        name, p = _read_cstring(data, p)
        if name is None:
            return None
        result['name'] = name

        # H2: _isBlocked (u8, 1B) — stream.read(a2+16, 1)
        result['_isBlocked'] = data[p]; p += 1

        # L0: _stringKey1 (LocStr via sub_140ED6040)
        p = _read_locstr(data, p)

        # L1: _stringKey2 (LocStr via sub_140ED6040)
        p = _read_locstr(data, p)

        # F00: enum4 hash (sub_1408F5560_0_1335) — reads 4B from stream
        p = _read_enum4_hash(data, p)  # a2+88

        # F01: enum4 hash
        p = _read_enum4_hash(data, p)  # a2+90

        # F02: CString (sub_14100FE80) — description
        _, p = _read_cstring(data, p)  # a2+96

        # F03: _spawnFixType (u8, 1B) — a2+104
        p += 1

        # F04: _isRemoteCatchable (u8, 1B) — a2+105
        p += 1

        # F05: key lookup (reads 4B, hash→u16 stored at a2+106)
        p += 4

        # F06: key lookup (reads 4B, hash→u16 stored at a2+108)
        p += 4

        # F07: _vehicleInfo (sub_14105F770, reads 2B stream → u16 at a2+110)
        result['_vehicleInfo_offset'] = p
        result['_vehicleInfo'] = struct.unpack_from('<H', data, p)[0]
        p += 2

        # F08: _callMercenaryCoolTime (u64, 8B) — a2+112
        result['_callMercenaryCoolTime_offset'] = p
        result['_callMercenaryCoolTime'] = struct.unpack_from('<Q', data, p)[0]
        p += 8

        # F09: _callMercenarySpawnDuration (u64, 8B) — a2+120 — RIDE DURATION
        result['_callMercenarySpawnDuration_offset'] = p
        result['_callMercenarySpawnDuration'] = struct.unpack_from('<Q', data, p)[0]
        p += 8

        # F10: _mercenaryCoolTimeType (u8, 1B) — a2+128
        result['_mercenaryCoolTimeType'] = data[p]; p += 1

        result['_parsed_bytes'] = p - offset
        result['_entry_size'] = end - offset

    except (struct.error, IndexError) as e:
        log.debug("Parse error at offset %d: %s", p, e)
        return None

    return result


# ── Convenience: parse all mounts ────────────────────────────────────────

MOUNT_VEHICLE_TYPES = {
    16960: 'Horse',
    16966: 'Wolf',
    16978: 'Camel',
    16984: 'Dragon',
    16988: 'WarMachine/ATAG',
    16994: 'Domestic',
    17003: 'Wagon',
}


def parse_all_entries(pabgb_data, pabgh_data):
    """Parse all CharacterInfo entries, return list of mount-field dicts."""
    idx = parse_pabgh_index(pabgh_data)
    sorted_entries = sorted(idx.items(), key=lambda x: x[1])

    results = []
    for i, (key, eoff) in enumerate(sorted_entries):
        if i + 1 < len(sorted_entries):
            end = sorted_entries[i + 1][1]
        else:
            end = len(pabgb_data)
        r = parse_mount_fields(pabgb_data, eoff, end)
        if r:
            results.append(r)

    return results


def parse_mounts_only(pabgb_data, pabgh_data):
    """Parse all entries and return only those with a vehicle type (mounts)."""
    all_entries = parse_all_entries(pabgb_data, pabgh_data)
    mounts = []
    for r in all_entries:
        vtype = r.get('_vehicleInfo', 0)
        if vtype in MOUNT_VEHICLE_TYPES:
            r['_vehicleTypeName'] = MOUNT_VEHICLE_TYPES[vtype]
            mounts.append(r)
        elif vtype != 0 and r.get('name', '').startswith('Riding_'):
            r['_vehicleTypeName'] = f'Unknown({vtype})'
            mounts.append(r)
    return mounts


# ── CLI validation ───────────────────────────────────────────────────────

def main():
    base = os.environ.get('EXTRACTED_PAZ', os.environ.get('EXTRACTED_PAZ', './extracted/0008_full'))
    with open(os.path.join(base, 'characterinfo.pabgb'), 'rb') as f:
        pabgb = f.read()
    with open(os.path.join(base, 'characterinfo.pabgh'), 'rb') as f:
        pabgh = f.read()

    all_entries = parse_all_entries(pabgb, pabgh)
    print(f"Parsed {len(all_entries)} / {struct.unpack_from('<H', pabgh, 0)[0]} entries")

    mounts = [e for e in all_entries if e.get('_vehicleInfo', 0) != 0
              or e.get('name', '').startswith('Riding_')]
    print(f"\nMounts/vehicles with _vehicleInfo != 0: {len(mounts)}")

    # Show timed mounts
    timed = [m for m in mounts if m.get('_callMercenarySpawnDuration', 0) > 0]
    print(f"Timed mounts (duration > 0): {len(timed)}")
    print(f"\n{'Name':<45} {'Type':<8} {'Duration':<12} {'Cooldown':<12} {'CoolType'}")
    print("-" * 100)
    for m in sorted(timed, key=lambda x: x['name']):
        dur = m['_callMercenarySpawnDuration']
        cool = m['_callMercenaryCoolTime']
        vtype = MOUNT_VEHICLE_TYPES.get(m['_vehicleInfo'], str(m['_vehicleInfo']))
        print(f"{m['name']:<45} {vtype:<8} {dur:>8}s    {cool:>8}s    {m['_mercenaryCoolTimeType']}")

    # Show all vehicle types
    vtypes = {}
    for m in mounts:
        vt = m['_vehicleInfo']
        vtypes[vt] = vtypes.get(vt, 0) + 1
    print(f"\nVehicle type distribution: {dict(sorted(vtypes.items()))}")


if __name__ == '__main__':
    main()
