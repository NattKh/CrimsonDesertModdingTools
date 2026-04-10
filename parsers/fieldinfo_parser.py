"""
FieldInfo parser — parses fieldinfo.pabgb entries.

Schema from IDA decompile of sub_1410403F0.
Target field: _alwaysCallVehicle_dev (u8 bool, last field of each entry).

Stream field order:
  1.  _key:                    4B (u32)
  2.  _stringKey:              CString (4+len)
  3.  _unknownBool:            1B (u8)
  4.  _fieldType1:             4B (enum _1335)
  5.  _fieldType2:             4B (enum _1335)
  6.  _unknownKey:             4B (u32)
  7.  _flag1:                  1B (u8)
  8.  _flag2:                  1B (u8)
  9.  _flag3:                  1B (u8)
  10. _flag4:                  1B (u8)
  11. _fieldType3:             4B (enum _1335)
  12. _position:               12B (3*f32)
  13. _value1:                 8B (u64)
  14. _value2:                 8B (u64)
  15. _bounds1:                4B (u32)
  16. _bounds2:                4B (u32)
  17. _bounds3:                4B (u32)
  18. _bounds4:                4B (u32)
  19. _zoneType:               2B (enum _1344 — the rare 2B reader!)
  20. _canCallVehicle:         1B (u8) — normal vehicle call flag?
  21. _unknownFlag:            1B (u8)
  22. _complexData:            variable (sub_141A7CA00)
  23. _regionKey1:             4B (enum4B lookup)
  24. _regionKey2:             4B (enum4B lookup)
  25. _regionKey3:             4B (enum4B lookup)
  26. _alwaysCallVehicle_dev:  1B (u8 bool) ← TARGET
"""
import struct
import sys
import os


def _u8(D, p):
    return D[p], p + 1

def _u16(D, p):
    return struct.unpack_from('<H', D, p)[0], p + 2

def _u32(D, p):
    return struct.unpack_from('<I', D, p)[0], p + 4

def _cstring(D, p):
    slen, p = _u32(D, p)
    if slen > 10000:
        return None, -1
    s = D[p:p + slen].decode('utf-8', errors='replace')
    return s, p + slen

def _skip_cstring(D, p):
    slen, p = _u32(D, p)
    if slen > 10000:
        return -1
    return p + slen


def parse_pabgh_index(G):
    c16 = struct.unpack_from('<H', G, 0)[0]
    if 2 + c16 * 8 == len(G):
        idx_start, count = 2, c16
    else:
        count = struct.unpack_from('<I', G, 0)[0]
        idx_start = 4
    idx = {}
    for i in range(count):
        pos = idx_start + i * 8
        if pos + 8 > len(G):
            break
        idx[struct.unpack_from('<I', G, pos)[0]] = struct.unpack_from('<I', G, pos + 4)[0]
    return idx


def parse_entry(D, eoff, end):
    """Parse a single FieldInfo entry.

    Returns dict with key fields and the _alwaysCallVehicle_dev offset, or None.
    """
    p = eoff
    entry = {}

    try:
        # 1. _key (4B)
        entry['key'], p = _u32(D, p)

        # 2. _stringKey (CString)
        entry['name'], p = _cstring(D, p)
        if p < 0:
            return None

        # 3. _unknownBool (1B)
        _, p = _u8(D, p)

        # 4-5. Two enum4B (_1335)
        entry['field_type1'], p = _u32(D, p)
        entry['field_type2'], p = _u32(D, p)

        # 6. _unknownKey (4B)
        _, p = _u32(D, p)

        # 7-10. Four u8 flags
        entry['flag1'], p = _u8(D, p)
        entry['flag2'], p = _u8(D, p)
        entry['flag3'], p = _u8(D, p)
        entry['flag4'], p = _u8(D, p)

        # 11. _fieldType3 enum4B (_1335)
        _, p = _u32(D, p)

        # 12. _position 12B (3*f32)
        x = struct.unpack_from('<f', D, p)[0]; p += 4
        y = struct.unpack_from('<f', D, p)[0]; p += 4
        z = struct.unpack_from('<f', D, p)[0]; p += 4
        entry['position'] = (round(x, 2), round(y, 2), round(z, 2))

        # 13-14. Two u64 values
        p += 8  # value1
        p += 8  # value2

        # 15-18. Four u32 values (bounds/dimensions)
        p += 4 * 4

        # 19. _zoneType enum 2B (_1344 — rare 2B reader)
        entry['zone_type'], p = _u16(D, p)

        # 20. _canCallVehicle (1B) — normal flag
        entry['can_call_vehicle'], p = _u8(D, p)
        entry['can_call_vehicle_offset'] = p - 1

        # 21. _unknownFlag (1B)
        _, p = _u8(D, p)

        # 22. _complexData (sub_141A7CA00) — variable size
        # This is a complex sub-struct. We need to skip it to reach the final fields.
        # sub_141A7CA00 reads: u32 count + count * elements
        # Each element read by sub_141A7C920 which reads variable data.
        # For simplicity, scan forward for the entry boundary instead.
        #
        # Alternative: find _alwaysCallVehicle_dev by reading the LAST byte of the entry.
        # Since it's the very last field (1 byte), it's at (end - 1).

        entry['always_call_vehicle_dev'] = D[end - 1]
        entry['always_call_vehicle_dev_offset'] = end - 1

        # Also grab the 3 enum4B keys before it (12B + 1B = 13B from end)
        # Layout at end: enum4B + enum4B + enum4B + u8 = 13 bytes
        if end - 13 > p:
            entry['region_key1'] = struct.unpack_from('<I', D, end - 13)[0]
            entry['region_key2'] = struct.unpack_from('<I', D, end - 9)[0]
            entry['region_key3'] = struct.unpack_from('<I', D, end - 5)[0]

        return entry

    except (struct.error, IndexError):
        return None


def parse_all_entries(pabgb_path, pabgh_path):
    """Parse all FieldInfo entries.

    Returns (entries_list, failure_count).
    """
    with open(pabgb_path, 'rb') as f:
        D = f.read()
    with open(pabgh_path, 'rb') as f:
        G = f.read()

    idx = parse_pabgh_index(G)
    sorted_offs = sorted(set(idx.values()))
    entries = []
    failures = 0

    for key, eoff in idx.items():
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)

        entry = parse_entry(D, eoff, end)
        if entry is None:
            failures += 1
            continue
        entries.append(entry)

    return entries, failures


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')

    # Extract from game if possible
    try:
        import crimson_rs
        game_path = 'C:/Program Files (x86)/Steam/steamapps/common/Crimson Desert'
        dp = 'gamedata/binary__/client/bin'
        body = crimson_rs.extract_file(game_path, '0008', dp, 'fieldinfo.pabgb')
        gh = crimson_rs.extract_file(game_path, '0008', dp, 'fieldinfo.pabgh')
        with open('fieldinfo_game.pabgb', 'wb') as f:
            f.write(body)
        with open('fieldinfo_game.pabgh', 'wb') as f:
            f.write(gh)
        pb, pg = 'fieldinfo_game.pabgb', 'fieldinfo_game.pabgh'
        print(f"Extracted fieldinfo: pabgb={len(body)}B pabgh={len(gh)}B")
    except Exception as e:
        print(f"Could not extract from game: {e}")
        EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
        pb = f'{EXT}/fieldinfo.pabgb'
        pg = f'{EXT}/fieldinfo.pabgh'

    entries, failures = parse_all_entries(pb, pg)
    print(f"Parsed: {len(entries)} entries, {failures} failures")

    from collections import Counter
    acv = Counter()
    ccv = Counter()
    for e in entries:
        acv[e['always_call_vehicle_dev']] += 1
        ccv[e['can_call_vehicle']] += 1

    print(f"\n_alwaysCallVehicle_dev: {dict(acv.most_common())}")
    print(f"_canCallVehicle: {dict(ccv.most_common())}")

    print(f"\nSample entries:")
    for e in sorted(entries, key=lambda x: x['key'])[:20]:
        name = e['name'][:40]
        print(f"  key={e['key']:>8d} {name:40s} canCall={e['can_call_vehicle']} alwaysDev={e['always_call_vehicle_dev']} pos={e['position']}")
