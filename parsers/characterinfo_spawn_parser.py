"""
CharacterInfo sequential binary parser.
Finds _terrainRegionSpawnPerCount byte offset for each entry.

Based on IDA decompile of sub_141037900 (readEntryFields) and
reader function element sizes from ida_dump_readers3.py.
"""
import struct
import sys


def parse_spawn_fields(pabgb_path, pabgh_path):
    """Parse all CharacterInfo entries and return spawn field offsets.

    Returns: ({char_key: (spawn_count_abs_offset, spawn_count_value)}, failure_count)
    """
    with open(pabgb_path, 'rb') as f:
        D = f.read()
    with open(pabgh_path, 'rb') as f:
        G = f.read()

    c16 = struct.unpack_from('<H', G, 0)[0]
    idx = {}
    for i in range(c16):
        k = struct.unpack_from('<I', G, 2 + i * 8)[0]
        o = struct.unpack_from('<I', G, 2 + i * 8 + 4)[0]
        idx[k] = o

    sorted_offs = sorted(set(idx.values()))
    results = {}
    failures = 0

    for entry_key, entry_off in idx.items():
        bi = sorted_offs.index(entry_off)
        entry_end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry_size = entry_end - entry_off

        try:
            r = _parse_one(D, entry_off, entry_size)
            if r is not None:
                results[entry_key] = r
            else:
                failures += 1
        except Exception:
            failures += 1

    return results, failures


def _parse_one(D, off, sz):
    """Parse a single CharacterInfo entry. Returns (spawn_count_offset, spawn_count) or None."""
    p = off
    end = off + sz

    def ru8():
        nonlocal p; v = D[p]; p += 1; return v
    def ru16():
        nonlocal p; v = struct.unpack_from('<H', D, p)[0]; p += 2; return v
    def ru32():
        nonlocal p; v = struct.unpack_from('<I', D, p)[0]; p += 4; return v
    def ru64():
        nonlocal p; v = struct.unpack_from('<Q', D, p)[0]; p += 8; return v
    def cs():
        slen = ru32(); nonlocal p; p += slen
    def ls():
        ru8(); ru64(); cs()
    def e4():
        ru32()
    def e2():
        ru16()
    def e1():
        ru8()
    def arr(elem):
        nonlocal p
        cnt = ru32()
        if cnt > 10000:
            return False
        p += cnt * elem
        return True
    def ok():
        return p <= end

    # ===== Entry header (consumed by readEntryFields) =====
    ru32()              # entry_id
    cs()                # entry_name (CString)
    ru8()               # _isBlocked

    # ===== String keys =====
    ls()                # _stringKey1 (LocalizableString)
    ls()                # _stringKey2 (LocalizableString)

    # ===== Enums & simple fields =====
    e4(); e4()          # a2+88, a2+90
    cs()                # a2+96: CString
    ru8(); ru8()        # a2+104, a2+105
    ru32(); ru32()      # a2+106, a2+108: key lookups (4B each)
    e2()                # a2+110: sub_14105F770 (2B)
    ru64(); ru64()      # a2+112, a2+120
    ru8()               # a2+128

    # loop 2x { enum4 + enum2 }
    for _ in range(2):
        e4(); e2()

    # Enums a2+138..152
    e4()                # a2+138
    for _ in range(7):  # a2+140..152
        e4()

    ru32()              # a2+156
    e4(); e4()          # a2+160, a2+162
    e4()                # a2+164: sub_1408F5560_0_1343 (4B)
    if not ok(): return None

    ru32()              # a2+168
    e4()                # a2+172
    ru32(); ru32()      # a2+176, a2+180
    ru8(); ru8()        # a2+184, a2+185
    e1()                # a2+186: sub_14105F910 (1B)
    ls()                # a2+192: LocalizableString
    e4()                # a2+224
    ru8()               # a2+226
    ru16()              # a2+228

    # 40 booleans a2+230..269
    for _ in range(40):
        ru8()
    if not ok(): return None

    ru32()              # a2+272
    e4(); e4()          # a2+276, a2+278

    # ===== CArray fields (element sizes from IDA dump) =====

    # sub_14105F9C0: 4B elements (x4 arrays)
    for _ in range(4):
        if not arr(4): return None
    if not ok(): return None

    # sub_14105FAD0: 4B elements
    if not arr(4): return None

    ru32()              # a2+360
    e4()                # a2+364

    # sub_141E99EB0: 4B elements
    if not arr(4): return None
    if not ok(): return None

    ru32()              # a2+384
    ru8(); ru8()        # a2+388, a2+389
    ru32()              # a2+390: key lookup
    ru8()               # a2+392
    e4()                # a2+394
    ru8()               # a2+396

    # sub_141076950: 4B elements (array, confirmed)
    if not arr(4): return None
    if not ok(): return None

    # sub_14105E000: 2B elements
    if not arr(2): return None
    if not ok(): return None

    cond = ru8()        # a2+432
    if cond == 0:
        e4()            # a2+434: conditional enum

    e2()                # a2+436: _1344 reads 2B!
    ru16()              # a2+438
    ru8(); ru8()        # a2+440, a2+441

    # sub_14105EA70: 2B elements
    if not arr(2): return None
    if not ok(): return None

    ru8()               # a2+464
    cs()                # a2+472: CString

    # sub_14105DDD0: first_read=2B, loop — u16 count + count*4B
    cnt_raw = ru16()
    if cnt_raw > 10000: return None
    p += cnt_raw * 4
    if not ok(): return None

    ru16()              # a2+482: u16 key lookup
    e4(); e4()          # a2+484, a2+486
    ru32()              # a2+488
    ru8()               # a2+492

    # sub_14105F4D0: 4B elements
    if not arr(4): return None

    # sub_14105E840: 4B elements (x2)
    if not arr(4): return None
    if not arr(4): return None
    if not ok(): return None

    ru32()              # a2+544

    # sub_1410767B0: 8B elements (4+4)
    if not arr(8): return None
    if not ok(): return None

    ru8()               # a2+568

    # sub_14105F4D0: 4B elements (second use)
    if not arr(4): return None

    # sub_14105FD40: count + sub-calls (0B detected per element)
    cnt_fd40 = ru32()
    if cnt_fd40 > 0:
        return None     # Can't skip elements with sub-calls
    if not ok(): return None

    # sub_14105FE60: 4B elements
    if not arr(4): return None

    # sub_1410765F0: 12B elements (8+4) (x2)
    if not arr(12): return None
    if not arr(12): return None
    if not ok(): return None

    # ===== TARGET FIELDS =====
    terrain_key_off = p
    terrain_key = ru32()        # a2+656: _terrainRegionAutoSpawnInfo

    spawn_count_off = p
    spawn_count = ru32()        # a2+660: _terrainRegionSpawnPerCount

    if not ok(): return None

    return (spawn_count_off, spawn_count)


# ── Main ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
    results, failures = parse_spawn_fields(
        f'{EXT}/characterinfo.pabgb',
        f'{EXT}/characterinfo.pabgh',
    )

    total = len(results) + failures
    print(f"Parsed: {len(results)} OK, {failures} failed out of {total}")

    # Show distribution
    from collections import Counter
    vals = Counter(v for _, v in results.values())
    print(f"\nSpawn count distribution:")
    for v, cnt in vals.most_common(20):
        print(f"  {v:>6}: {cnt} entries")

    # Show specific entries
    print(f"\nKey entries:")
    with open(f'{EXT}/characterinfo.pabgb', 'rb') as f:
        D = f.read()
    with open(f'{EXT}/characterinfo.pabgh', 'rb') as f:
        G = f.read()
    c16 = struct.unpack_from('<H', G, 0)[0]
    names = {}
    for i in range(c16):
        k = struct.unpack_from('<I', G, 2+i*8)[0]
        o = struct.unpack_from('<I', G, 2+i*8+4)[0]
        nlen = struct.unpack_from('<I', D, o+4)[0]
        if nlen < 200:
            names[k] = D[o+8:o+8+nlen].decode('utf-8', errors='replace').rstrip('\x00')

    for key in [1, 4, 6, 100, 30030, 3002, 1000781, 30065]:
        if key in results:
            off, val = results[key]
            print(f"  {key:>8} {names.get(key,'?'):40s} spawn_count={val} @{off}")
        else:
            print(f"  {key:>8} {names.get(key,'?'):40s} FAILED")
