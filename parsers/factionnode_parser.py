"""
FactionNodeSpawnInfo parser — parse per-node enemy spawn slot data.
Based on IDA decompile of sub_14103EF10 and all sub-functions.
"""
import struct
import sys


def parse_faction_nodes(pabgb_path, pabgh_path):
    """Parse all FactionNodeSpawnInfo entries.
    Returns list of parsed node dicts.
    """
    with open(pabgb_path, 'rb') as f:
        D = f.read()
    with open(pabgh_path, 'rb') as f:
        G = f.read()

    c16 = struct.unpack_from('<H', G, 0)[0]
    if 2 + c16 * 8 == len(G):
        idx_start = 2
    else:
        c16 = struct.unpack_from('<I', G, 0)[0]
        idx_start = 4

    idx = {}
    for i in range(c16):
        pos = idx_start + i * 8
        if pos + 8 > len(G):
            break
        k = struct.unpack_from('<I', G, pos)[0]
        o = struct.unpack_from('<I', G, pos + 4)[0]
        idx[k] = o

    sorted_offs = sorted(set(idx.values()))
    nodes = []
    failures = 0

    for key, off in sorted(idx.items(), key=lambda x: x[1]):
        bi = sorted_offs.index(off)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        try:
            node = _parse_node(D, off, end)
            if node:
                nodes.append(node)
            else:
                failures += 1
        except Exception:
            failures += 1

    return nodes, failures


def _parse_node(D, off, end):
    p = off

    def ru8():
        nonlocal p; v = D[p]; p += 1; return v
    def ru16():
        nonlocal p; v = struct.unpack_from('<H', D, p)[0]; p += 2; return v
    def ru32():
        nonlocal p; v = struct.unpack_from('<I', D, p)[0]; p += 4; return v
    def rfloat():
        nonlocal p; v = struct.unpack_from('<f', D, p)[0]; p += 4; return v
    def rN(n):
        nonlocal p; v = D[p:p+n]; p += n; return v
    def cs():
        slen = ru32()
        nonlocal p
        s = D[p:p+slen].decode('utf-8', errors='replace')
        p += slen
        return s
    def ok():
        return p <= end

    node = {}

    # Entry header
    node['key'] = ru32()
    node['name'] = cs()
    node['is_blocked'] = ru8()
    node['faction_key_raw'] = ru32()  # _1347: 4B read, key lookup

    # World bounds
    node['bounds_min'] = (rfloat(), rfloat(), rfloat())
    node['bounds_max'] = (rfloat(), rfloat(), rfloat())

    if not ok():
        return None

    # Spawn slot list (sub_141073710)
    slot_count = ru32()
    if slot_count > 500:
        return None

    slots = []
    for _ in range(slot_count):
        # 16B raw per slot (transform/position)
        slot_data = rN(16)

        # SpawnSlot (sub_14133A090)
        has_data = ru8()
        if not has_data:
            slots.append({'has_data': False, 'actors': []})
            continue

        # Read u8 at +24
        slot_flag = ru8()

        # Actor list (sub_14133B1A0)
        actor_count = ru32()
        if actor_count > 500:
            return None

        actors = []
        for _ in range(actor_count):
            actor = {}
            # 12B position
            actor['pos'] = (rfloat(), rfloat(), rfloat())
            # 16B hash/GUID (sub_1410103E0: 4x u32)
            actor['guid'] = (ru32(), ru32(), ru32(), ru32())
            # u32 unknown_28 (float — spawn radius, default 1.0)
            actor['unknown_28_offset'] = p  # absolute offset
            actor['unknown_28'] = ru32()
            # u8 flag
            actor['flag'] = ru8()
            # 12B vec3 data_1
            actor['data_1'] = (rfloat(), rfloat(), rfloat())
            # 12B vec3 data_2
            actor['data_2'] = (rfloat(), rfloat(), rfloat())
            # u32 at +60 — candidate spawn param
            actor['field_60'] = ru32()
            actor['field_60_offset'] = p - 4  # absolute offset for editing
            # u32 at +64 — candidate spawn param
            actor['field_64'] = ru32()
            actor['field_64_offset'] = p - 4

            actors.append(actor)

            if not ok():
                return None

        slots.append({
            'has_data': True,
            'slot_flag': slot_flag,
            'actors': actors,
        })

    node['slots'] = slots
    node['consumed'] = p - off
    node['entry_size'] = end - off
    return node


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8')

    EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
    nodes, failures = parse_faction_nodes(
        f'{EXT}/factionnodespawninfo.pabgb',
        f'{EXT}/factionnodespawninfo.pabgh',
    )

    total = len(nodes) + failures
    print(f"Parsed: {len(nodes)} OK, {failures} failed out of {total}")

    # Collect all field_60 and field_64 values
    all_f60 = []
    all_f64 = []
    total_actors = 0
    total_slots = 0

    for n in nodes:
        for s in n['slots']:
            total_slots += 1
            for a in s['actors']:
                total_actors += 1
                all_f60.append(a['field_60'])
                all_f64.append(a['field_64'])

    print(f"Total slots: {total_slots}, Total actors: {total_actors}")

    if all_f60:
        from collections import Counter

        print(f"\n=== field_60 distribution (candidate spawn param) ===")
        for v, cnt in Counter(all_f60).most_common(20):
            f_val = struct.unpack('<f', struct.pack('<I', v))[0]
            print(f"  {v:>12d} (0x{v:08X}) float={f_val:>12.3f}: {cnt}x")

        print(f"\n=== field_64 distribution (candidate spawn param) ===")
        for v, cnt in Counter(all_f64).most_common(20):
            f_val = struct.unpack('<f', struct.pack('<I', v))[0]
            print(f"  {v:>12d} (0x{v:08X}) float={f_val:>12.3f}: {cnt}x")

    # Show sample nodes
    print(f"\n=== Sample nodes with actors ===")
    shown = 0
    for n in nodes:
        actor_count = sum(len(s['actors']) for s in n['slots'])
        if actor_count == 0:
            continue
        print(f"\n  {n['key']} — {n['name']}")
        print(f"    slots={len(n['slots'])} actors={actor_count} "
              f"consumed={n['consumed']}/{n['entry_size']}B")
        for si, s in enumerate(n['slots']):
            if not s['actors']:
                continue
            for ai, a in enumerate(s['actors'][:2]):
                print(f"    slot[{si}] actor[{ai}]: "
                      f"pos=({a['pos'][0]:.0f},{a['pos'][1]:.0f},{a['pos'][2]:.0f}) "
                      f"f60={a['field_60']} f64={a['field_64']} flag={a['flag']}")
        shown += 1
        if shown >= 8:
            break
