"""
FactionNodeInfo parser — full entry header + schedule integration.

Schema source: lukerz (pycrimson), field names confirmed.
Stream sizes from IDA decompile of sub_14103E930.

Field order and stream consumption:
  _key:                          4B (u32)
  _stringKey:                    CString (4+len)
  _isBlocked:                    1B (u8/bool)
  _knowledgeInfo:                4B (enum _1340)
  _skillTreeInfo:                4B (enum _1354)
  _connectResearchNodeInfo:      4B (enum _1347)
  _storeInfo:                    2B (sub_141062200)
  _royalSupplyInfo:              2B (sub_1410622B0)
  _memo:                         CString (4+len)
  _childFactionInfoList:         array u32 count + count*4B
  _nodeLineMainFactionInfoList:  array u32 count + count*4B
  _worldPosition:                12B (3*f32)
  _nodeRadius:                   4B (f32)
  _applySkillDataList:           complex array (bail if count>0)
  _resourceItemList:             complex array (bail if count>0)
  _revivalStageInfoList:         array u32 count + count*4B
  _wayPointDataList_deprecated:  complex array (bail if count>0)
  _factionScheduleInfoList:      u32 count + count * FactionScheduleInfo
  --- post-schedule ---
  _factionType:                  1B (u8)
  _subInnerTypeString:           Blob (4+len)
  _workerCount:                  1B (u8)
  _knockDownCondition:           4B (enum _1337)
  _bitMapColorKey:               1B (u8)
  _extraField:                   1B (u8, not in schema — IDA a2+181)
  _researchDataList:             complex array (sub_1410738A0)
  _factionEventDataList:         13 x sub_1410859A0 elements
  _useCustomWayPointforDev:      1B (u8/bool)
  _observeData:                  sub-struct (sub_14103E820)
  _religionMaxBlockDay:          4B (u32)
  _religionBlockCostList:        array u32 count + count*4B
  _religionEffectRegionInfoList: array u32 count + count*2B
  _religionSubLevelInfo:         4B (enum _1355)
"""
import struct
import sys
import json


def _u8(D, p):
    return D[p], p + 1

def _u16(D, p):
    return struct.unpack_from('<H', D, p)[0], p + 2

def _u32(D, p):
    return struct.unpack_from('<I', D, p)[0], p + 4

def _f32(D, p):
    return struct.unpack_from('<f', D, p)[0], p + 4

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

def _skip_blob(D, p):
    """Blob: u32 len, then skip len bytes in stream."""
    blen, p = _u32(D, p)
    if blen > 1000000:
        return -1
    return p + blen

def _skip_array_4B(D, p):
    """Array of 4B elements: u32 count + count*4."""
    cnt, p = _u32(D, p)
    if cnt > 100000:
        return -1
    return p + cnt * 4

def _skip_array_2B(D, p):
    """Array of 2B elements: u32 count + count*2."""
    cnt, p = _u32(D, p)
    if cnt > 100000:
        return -1
    return p + cnt * 2

def _skip_complex_array(D, p):
    """Complex array: u32 count. Returns -1 if count > 0 (can't skip elements)."""
    cnt, p = _u32(D, p)
    if cnt > 0:
        return -1  # can't skip variable-size elements
    return p


def parse_pabgh_index(G):
    """Parse pabgh index. Returns dict {key: offset}."""
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
    """Parse a single FactionNodeInfo entry.

    Returns dict with all parsed fields, or None on failure.
    Entries with non-zero complex arrays are skipped (can't parse variable elements).
    """
    p = eoff
    entry = {}

    try:
        # _key
        entry['key'], p = _u32(D, p)

        # _stringKey
        entry['name'], p = _cstring(D, p)
        if p < 0:
            return None

        # _isBlocked
        entry['is_blocked'], p = _u8(D, p)

        # _knowledgeInfo (enum4B _1340)
        entry['knowledge_key'], p = _u32(D, p)

        # _skillTreeInfo (enum4B _1354)
        entry['skill_tree_key'], p = _u32(D, p)

        # _connectResearchNodeInfo (enum4B _1347)
        entry['connect_research_node_key'], p = _u32(D, p)

        # _storeInfo (2B reader sub_141062200)
        entry['store_key'], p = _u16(D, p)

        # _royalSupplyInfo (2B reader sub_1410622B0)
        entry['royal_supply_key'], p = _u16(D, p)

        # _memo
        entry['memo'], p = _cstring(D, p)
        if p < 0:
            return None

        # _childFactionInfoList (array of u32 keys)
        child_count, p = _u32(D, p)
        entry['child_faction_keys'] = []
        for _ in range(child_count):
            v, p = _u32(D, p)
            entry['child_faction_keys'].append(v)

        # _nodeLineMainFactionInfoList (array of u32 keys)
        nodeline_count, p = _u32(D, p)
        entry['nodeline_keys'] = []
        for _ in range(nodeline_count):
            v, p = _u32(D, p)
            entry['nodeline_keys'].append(v)

        # _worldPosition (3 floats)
        x, p = _f32(D, p)
        y, p = _f32(D, p)
        z, p = _f32(D, p)
        entry['world_position'] = (round(x, 2), round(y, 2), round(z, 2))

        # _nodeRadius (f32)
        entry['node_radius'], p = _f32(D, p)
        entry['node_radius'] = round(entry['node_radius'], 2)
        entry['node_radius_offset'] = p - 4

        # _applySkillDataList (complex — bail if non-empty)
        p = _skip_complex_array(D, p)
        if p < 0:
            return None

        # _resourceItemList (complex — bail if non-empty)
        p = _skip_complex_array(D, p)
        if p < 0:
            return None

        # _revivalStageInfoList (array of 4B keys)
        p = _skip_array_4B(D, p)
        if p < 0:
            return None

        # _wayPointDataList_deprecated (complex — bail if non-empty)
        p = _skip_complex_array(D, p)
        if p < 0:
            return None

        # _factionScheduleInfoList count
        sched_count, p = _u32(D, p)
        entry['schedule_count'] = sched_count
        entry['schedule_start'] = p

        # Skip schedules (parsed separately by factionnode_operator_parser)
        # We just record the start position
        entry['_parse_end'] = p  # caller can continue from here

        return entry

    except (struct.error, IndexError):
        return None


def parse_all_entries(pabgb_path, pabgh_path):
    """Parse all FactionNodeInfo entries from pabgb/pabgh files.

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

    import os
    # Try game file first, fall back to extracted
    if os.path.exists('factionnode_game.pabgb'):
        pb, pg = 'factionnode_game.pabgb', 'factionnode_game.pabgh'
    else:
        EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
        pb, pg = f'{EXT}/factionnode.pabgb', f'{EXT}/factionnode.pabgh'

    entries, failures = parse_all_entries(pb, pg)

    print(f"Parsed: {len(entries)} entries, {failures} failures")

    # Stats
    with_scheds = sum(1 for e in entries if e['schedule_count'] > 0)
    blocked = sum(1 for e in entries if e['is_blocked'])
    has_store = sum(1 for e in entries if e['store_key'] != 0xFFFF)
    has_radius = sum(1 for e in entries if e['node_radius'] > 0)

    print(f"With schedules: {with_scheds}")
    print(f"Blocked: {blocked}")
    print(f"Has store: {has_store}")
    print(f"Has non-zero radius: {has_radius}")

    # Radius distribution
    from collections import Counter
    radii = Counter()
    for e in entries:
        radii[e['node_radius']] += 1
    print(f"\nNode radius distribution (top 10):")
    for v, cnt in radii.most_common(10):
        print(f"  {v:>8.1f}: {cnt}x")

    # Sample entries
    print(f"\nSample entries:")
    shown = 0
    for e in entries:
        if e['schedule_count'] > 0:
            name = e['name'].replace('Node_', '').replace('_', ' ')[:45]
            pos = e['world_position']
            print(f"  {name:45s} scheds={e['schedule_count']} radius={e['node_radius']:>6.1f} "
                  f"pos=({pos[0]:.0f},{pos[1]:.0f},{pos[2]:.0f}) "
                  f"store={e['store_key']} blocked={e['is_blocked']}")
            shown += 1
            if shown >= 15:
                break
