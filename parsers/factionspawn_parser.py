"""
FactionSpawnDataInfo parser — parse enemy/NPC spawn definitions.
Based on IDA decompile of sub_14103F360 and all sub-functions.
"""
import struct
import sys


def parse_faction_spawns(pabgb_path, pabgh_path):
    """Parse all FactionSpawnDataInfo entries.

    Returns list of dicts with spawn data per entry.
    """
    with open(pabgb_path, 'rb') as f:
        D = f.read()
    with open(pabgh_path, 'rb') as f:
        G = f.read()

    # Parse pabgh index (u16 count format)
    c16 = struct.unpack_from('<H', G, 0)[0]
    if 2 + c16 * 8 != len(G):
        # Try u32 count
        c16 = struct.unpack_from('<I', G, 0)[0]
        idx_start = 4
    else:
        idx_start = 2

    idx = {}
    for i in range(c16):
        pos = idx_start + i * 8
        if pos + 8 > len(G):
            break
        k = struct.unpack_from('<I', G, pos)[0]
        o = struct.unpack_from('<I', G, pos + 4)[0]
        idx[k] = o

    sorted_offs = sorted(set(idx.values()))
    entries = []

    for entry_key, entry_off in sorted(idx.items(), key=lambda x: x[1]):
        bi = sorted_offs.index(entry_off)
        entry_end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)

        try:
            result = _parse_entry(D, entry_off, entry_end)
            if result:
                entries.append(result)
        except Exception as e:
            pass  # skip unparseable entries

    return entries


def _parse_entry(D, off, end):
    """Parse a single FactionSpawnDataInfo entry."""
    p = off
    sz = end - off

    def ru8():
        nonlocal p; v = D[p]; p += 1; return v
    def ru16():
        nonlocal p; v = struct.unpack_from('<H', D, p)[0]; p += 2; return v
    def ru32():
        nonlocal p; v = struct.unpack_from('<I', D, p)[0]; p += 4; return v
    def cs():
        slen = ru32()
        nonlocal p
        s = D[p:p+slen].decode('utf-8', errors='replace')
        p += slen
        return s
    def ok():
        return p <= end

    entry = {}

    # ── Entry header ──
    entry['key'] = ru32()
    entry['name'] = cs()
    entry['is_blocked'] = ru8()

    # ── _patrolSpawnData (sub_1410733E0) ──
    patrol_flag = ru8()
    entry['has_patrol'] = bool(patrol_flag)

    patrol_parties = []
    schedule_elements = []

    if patrol_flag:
        # Patrol party list (sub_1410624C0)
        party_count = ru32()
        if party_count > 500:
            return None
        for _ in range(party_count):
            party_name = cs()
            char_key = ru32()  # _1337 enum lookup
            patrol_parties.append({
                'party_name': party_name,
                'character_key': char_key,
            })
        if not ok():
            return None

        # Patrol schedule list (sub_141073540)
        sched_count = ru32()
        if sched_count > 500:
            return None
        for _ in range(sched_count):
            se = _parse_schedule_element(D, p, end)
            if se is None:
                return None
            p = se['_next_pos']
            schedule_elements.append(se)
        if not ok():
            return None

    entry['patrol_parties'] = patrol_parties
    entry['schedule_elements'] = schedule_elements

    # ── _gimmickSpawnDataList (sub_141073210) ──
    gimmick_count = ru32()
    if gimmick_count > 500:
        return None
    gimmicks = []
    for _ in range(gimmick_count):
        tag = cs()
        spawn_type = ru16()   # F3A0: 2B read
        char_key = ru32()     # _1337: 4B read
        gimmicks.append({
            'spawn_tag': tag,
            'spawn_type': spawn_type,
            'character_key': char_key,
        })
    if not ok():
        return None
    entry['gimmicks'] = gimmicks

    # ── Conditional _scheduleSpawnInfo ──
    sched_flag = ru8()
    if sched_flag:
        sched2_count = ru32()
        if sched2_count > 500:
            return None
        sched2_keys = []
        for _ in range(sched2_count):
            sched2_keys.append(ru16())
        entry['schedule_keys'] = sched2_keys
    else:
        entry['schedule_keys'] = []

    entry['consumed'] = p - off
    entry['entry_size'] = sz
    return entry


def _parse_schedule_element(D, p_start, end):
    """Parse one schedule element (sub_14103F1B0)."""
    p = p_start

    def ru8():
        nonlocal p; v = D[p]; p += 1; return v
    def ru16():
        nonlocal p; v = struct.unpack_from('<H', D, p)[0]; p += 2; return v
    def ru32():
        nonlocal p; v = struct.unpack_from('<I', D, p)[0]; p += 4; return v

    se = {}
    se['hash_1'] = ru32()
    se['hash_2'] = ru32()
    se['faction_key'] = ru32()  # key lookup

    # Waypoint list (sub_1410623D0)
    wp_count = ru32()
    if wp_count > 500:
        return None
    waypoints = []
    for _ in range(wp_count):
        # sub_14103F0A0: 4+2+4+2+1+1 = 14B
        wp = {
            'key_1': ru32(),
            'type_1': ru16(),
            'key_2': ru32(),
            'type_2': ru16(),
            'flag_1': ru8(),
            'flag_2': ru8(),
        }
        waypoints.append(wp)
    se['waypoints'] = waypoints

    se['character_key'] = ru32()       # _1337: character reference
    se['field_36'] = ru32()            # ** MYSTERY FIELD — spawn count? timer? **
    se['field_36_offset'] = p - 4      # absolute offset for editing
    se['field_40'] = ru32()            # ** MYSTERY FIELD — timer? spawn count? **
    se['field_40_offset'] = p - 4
    se['flag'] = ru8()

    if p > end:
        return None

    se['_next_pos'] = p
    return se


# ── Main ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8')

    EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
    entries = parse_faction_spawns(
        f'{EXT}/factionspawndatainfo.pabgb',
        f'{EXT}/factionspawndatainfo.pabgh',
    )

    print(f"Parsed {len(entries)} faction spawn entries\n")

    # Collect all field_36 and field_40 values
    all_f36 = []
    all_f40 = []
    all_schedules = 0

    for e in entries:
        for se in e['schedule_elements']:
            all_f36.append(se['field_36'])
            all_f40.append(se['field_40'])
            all_schedules += 1

    print(f"Total schedule elements: {all_schedules}")

    if all_f36:
        from collections import Counter

        print(f"\n=== field_36 distribution ===")
        for v, cnt in Counter(all_f36).most_common(20):
            print(f"  {v:>12d} (0x{v:08X}): {cnt}x")

        print(f"\n=== field_40 distribution ===")
        for v, cnt in Counter(all_f40).most_common(20):
            print(f"  {v:>12d} (0x{v:08X}): {cnt}x")

    # Show sample entries
    print(f"\n=== Sample entries ===")
    for e in entries[:10]:
        print(f"\n  {e['key']} — {e['name']}")
        print(f"    patrol_parties: {len(e['patrol_parties'])}")
        for pp in e['patrol_parties'][:3]:
            print(f"      party='{pp['party_name']}' char_key={pp['character_key']}")
        print(f"    schedule_elements: {len(e['schedule_elements'])}")
        for se in e['schedule_elements'][:3]:
            print(f"      char={se['character_key']} f36={se['field_36']} f40={se['field_40']} "
                  f"flag={se['flag']} waypoints={len(se['waypoints'])}")
        print(f"    gimmicks: {len(e['gimmicks'])}")
        for g in e['gimmicks'][:3]:
            print(f"      tag='{g['spawn_tag']}' type={g['spawn_type']} char={g['character_key']}")
        print(f"    consumed: {e['consumed']}/{e['entry_size']}B")
