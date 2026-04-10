"""
terrainregionautospawninfo.pabgb deep parser — extracts nested spawn density fields.

Parses the full nested structure:
  TerrainRegionAutoSpawnInfo
    -> _spawnList: AutoSpawnTargetData[] (sub_141067560, 112B runtime per element)
         -> _partySpawnList: AutoSpawnPartyData[] (sub_1410673B0, 72B runtime)
              -> _characterSpawnList (sub_141059310)
              -> _spawnRate (f32, default 1.0)
              -> _spawnPercent (f32)
         -> _spawnLimitCount (u16 via key lookup)
         -> _metersPerSpawn (f32 via key lookup)
         -> _spawnDistance, _spawnSafetyDistance, _timeBegin, _timeEnd

IDA references:
  sub_141067560 — AutoSpawnTargetData array reader
  sub_1410597C0 — AutoSpawnTargetData element reader (16 fields)
  sub_1410673B0 — AutoSpawnPartyData array reader
  sub_141059420 — AutoSpawnPartyData element reader (15 fields)
"""
import struct
import json
import sys
import os


def _u32(D, p):
    return struct.unpack_from('<I', D, p)[0], p + 4

def _u16(D, p):
    return struct.unpack_from('<H', D, p)[0], p + 2

def _u8(D, p):
    return D[p], p + 1

def _f32(D, p):
    return struct.unpack_from('<f', D, p)[0], p + 4

def _skip_cstring(D, p):
    slen, p = _u32(D, p)
    if slen > 50000: return None, -1
    return D[p:p+slen].decode('utf-8', errors='replace'), p + slen

def _read_cstring(D, p):
    slen, p = _u32(D, p)
    if slen > 50000: return '', -1
    return D[p:p+slen].decode('utf-8', errors='replace'), p + slen


def _skip_cstring_array(D, p):
    """Skip array of CStrings (sub_140FD2180): u32 count + count * CString."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    for _ in range(count):
        slen, p = _u32(D, p)
        if slen > 50000: return -1
        p += slen
    return p


def _skip_key_lookup_array_u16(D, p):
    """Array: u32 count + count * 2B (sub_14105EA70: reads u16 per element from stream)."""
    count, p = _u32(D, p)
    if count > 100000: return -1
    return p + count * 2


def _skip_key_lookup_array_u32(D, p):
    """Array: u32 count + count * 4B (tag hashes)."""
    count, p = _u32(D, p)
    if count > 100000: return -1
    return p + count * 4


def _skip_byte_array(D, p):
    """Array: u32 count + count * 1B elements (sub_14105F260: byte array)."""
    count, p = _u32(D, p)
    if count > 100000: return -1
    return p + count * 1


def parse_character_spawn_list(D, p):
    """Parse _characterSpawnList (sub_141059310 elements).
    Each element from IDA decompile:
      1. enum _1336: 4B stream
      2. u16 key lookup: 2B stream
      3. enum _1336: 4B stream
      4. u16 key lookup: 2B stream
      5. u8: 1B
      6. u8: 1B
    Total: 14B per element in stream.
    """
    count, p = _u32(D, p)
    if count > 10000: return [], -1
    chars = []
    for _ in range(count):
        char_key, _ = _u32(D, p)  # first field is a character key
        chars.append(char_key)
        p += 14  # 14B per element: enum4B + u16(2B) + enum4B + u16(2B) + u8 + u8
    return chars, p


def parse_party_data(D, p, end):
    """Parse one AutoSpawnPartyData element from stream.

    Stream format (from IDA sub_141059420):
    1. _characterSpawnList: u32 count + count * 4B keys
    2. _spawnDataName: u32 key lookup
    3. enum _1341: 4B -> _spawnReason
    4. enum _1338: 4B
    5. enum _1335: 4B
    6. u32 key lookup -> _sequencerSpawnInfo
    7. 4B -> _spawnPercent (f32)
    8. 4B -> _spawnRate (f32)
    9. 4B -> _maxWaterDepth (f32)
    10. 4B -> _minWaterDepth (f32)
    11. sub_140F73940 (color/formation): 12B (3 floats)
    12. 1B -> _isFactionSequencerSpawn
    13. 1B -> _isPartySameTeam
    14. 1B -> _isDuplicatable
    15. 8B -> _gimmickInfo/_itemInfo
    """
    party = {}

    # 1. Character spawn list
    chars, p = parse_character_spawn_list(D, p)
    if p < 0: return None, -1
    party['characters'] = chars
    party['character_count'] = len(chars)

    # Field names confirmed by IDA error strings in sub_141059420:
    # 2. _spawnDataName (key lookup, 4B)
    party['spawn_data_name_key'], p = _u32(D, p)

    # 3. enum _1341 (4B)
    party['enum_1341'], p = _u32(D, p)
    # 4. enum _1338 (4B)
    party['enum_1338'], p = _u32(D, p)
    # 5. enum _1335 (4B)
    party['enum_1335'], p = _u32(D, p)

    # 6. _sequencerSpawnInfo (key lookup, 4B)
    party['sequencer_spawn_key'], p = _u32(D, p)

    # 7. _spawnReason (4B) — IDA error string: "pawnReason"
    party['spawn_reason'], p = _u32(D, p)

    # 8. _spawnRate (4B) — IDA error string: "pawnRate"
    party['spawn_rate'], p = _f32(D, p)
    party['spawn_rate_offset'] = p - 4

    # 9. _minWaterDepth (4B) — IDA: "inWaterDepth"
    party['min_water_depth'], p = _f32(D, p)

    # 10. _maxWaterDepth (4B) — IDA: "axWaterDepth"
    party['max_water_depth'], p = _f32(D, p)

    # 11. _color (sub_140F73940: 4 x 4B = 16B) — IDA: "olor"
    party['color_r'], p = _f32(D, p)
    party['color_g'], p = _f32(D, p)
    party['color_b'], p = _f32(D, p)
    party['color_a'], p = _f32(D, p)

    # 12. _isDuplicatable (1B) — IDA: "sDuplicatable"
    party['is_duplicatable'], p = _u8(D, p)
    # 13. _isPartySameTeam (1B) — IDA: "sPartySameTeam"
    party['is_party_same_team'], p = _u8(D, p)
    # 14. _isFactionSequencerSpawn (1B) — IDA: "sFactionSequencerSpawn"
    party['is_faction_sequencer'], p = _u8(D, p)

    # 15. _spawnPercent (8B) — IDA: "pawnPercent"
    party['spawn_percent'] = struct.unpack_from('<d', D, p)[0]  # f64 double!
    party['spawn_percent_offset'] = p
    p += 8

    return party, p


def parse_target_data(D, p, end):
    """Parse one AutoSpawnTargetData element from stream.

    Stream format (from IDA sub_1410597C0):
    1. _partySpawnList: sub_1410673B0 (complex array)
    2. _regionInfoList: sub_14105EA70 (u16 key array)
    3. _notSpawnRegionInfoList: sub_14105EA70
    4. _spawnRegionTagList: sub_14105DE80 (u32 array)
    5. _notSpawnRegionTagList: sub_14105DE80
    6. 4B key lookup -> _spawnLimitCount
    7. 4B key lookup -> _metersPerSpawn
    8-9. 4B, 4B -> distances
    10-11. 4B, 4B -> more fields
    12-16. 1B, 1B, 1B, 1B, 1B, 2B -> flags and enum
    """
    target = {}

    # 1. _partySpawnList (sub_1410673B0): u32 count + count * party elements
    party_count, p = _u32(D, p)
    if party_count > 1000: return None, -1
    target['party_count'] = party_count
    target['parties'] = []

    for _ in range(party_count):
        party, p = parse_party_data(D, p, end)
        if p < 0 or party is None: return None, -1
        target['parties'].append(party)

    # 2. _regionInfoList (u16 key lookup array)
    p = _skip_key_lookup_array_u16(D, p)
    if p < 0: return None, -1

    # 3. _notSpawnRegionInfoList
    p = _skip_key_lookup_array_u16(D, p)
    if p < 0: return None, -1

    # 4. _spawnRegionTagList (u32 array)
    p = _skip_key_lookup_array_u32(D, p)
    if p < 0: return None, -1

    # 5. _notSpawnRegionTagList
    p = _skip_key_lookup_array_u32(D, p)
    if p < 0: return None, -1

    # 6. _spawnLimitCount (4B key lookup -> stored as u32/u16)
    target['spawn_limit_raw'], p = _u32(D, p)
    target['spawn_limit_offset'] = p - 4

    # 7. _metersPerSpawn (4B key lookup -> stored as f32)
    target['meters_per_spawn_raw'], p = _u32(D, p)
    target['meters_per_spawn_offset'] = p - 4
    # Try interpreting as float
    target['meters_per_spawn'] = struct.unpack_from('<f', D, p - 4)[0]

    # 8-9. Two more 4B fields (_spawnDistance, _spawnSafetyDistance)
    target['field_8'], p = _u32(D, p)
    target['field_9'], p = _u32(D, p)

    # 10-11. Two more 4B fields
    target['field_10'], p = _u32(D, p)
    target['field_11'], p = _u32(D, p)

    # 12-16. u8, u8, u8, u8, u8, u16
    target['indoor_type'], p = _u8(D, p)
    target['stage_category'], p = _u8(D, p)
    target['time_begin'], p = _u8(D, p)
    target['time_end'], p = _u8(D, p)
    target['flag_5'], p = _u8(D, p)
    target['tail_u16'], p = _u16(D, p)

    return target, p


def parse_terrain_entry(D, eoff, end):
    """Parse one TerrainRegionAutoSpawnInfo entry."""
    p = eoff
    entry = {}

    try:
        # Field order from IDA decompile of sub_141059AB0:
        # 1. _key (4B)
        entry['key'], p = _u32(D, p)

        # 2. _stringKey (CString)
        entry['name'], p = _read_cstring(D, p)
        if p < 0: return None

        # 3. _isBlocked (1B)
        entry['is_blocked'], p = _u8(D, p)

        # 4. _bitmapColorListForSpawn (sub_14105F260: 5B array)
        p = _skip_byte_array(D, p)
        if p < 0: return None

        # 5. _autoSpawnSplineExceptName (sub_140FD2180: array of CStrings)
        p = _skip_cstring_array(D, p)
        if p < 0: return None

        # 6. _autoSpawnSplineName (sub_140FD2180: array of CStrings)
        p = _skip_cstring_array(D, p)
        if p < 0: return None

        # 7. _regionInfoList (sub_14105EA70: u16 key array)
        p = _skip_key_lookup_array_u16(D, p)
        if p < 0: return None

        # 8. _notSpawnRegionInfoList (sub_14105EA70: u16 key array)
        p = _skip_key_lookup_array_u16(D, p)
        if p < 0: return None

        # 9. _spawnRegionTagList (sub_14105DE80: u32 array)
        p = _skip_key_lookup_array_u32(D, p)
        if p < 0: return None

        # 10. _notSpawnRegionTagList (sub_14105DE80: u32 array)
        p = _skip_key_lookup_array_u32(D, p)
        if p < 0: return None

        # 11. _spawnList: AutoSpawnTargetData[] (sub_141067560) — THE KEY FIELD
        spawn_count, p = _u32(D, p)
        if spawn_count > 1000: return None
        entry['spawn_count'] = spawn_count
        entry['targets'] = []

        for _ in range(spawn_count):
            target, p = parse_target_data(D, p, end)
            if p < 0 or target is None:
                entry['parse_error'] = True
                return entry
            entry['targets'].append(target)

        entry['parse_complete'] = True
        return entry

    except (struct.error, IndexError) as e:
        entry['parse_error'] = str(e)
        return entry


def parse_pabgh(G):
    """Parse pabgh index file."""
    c16 = struct.unpack_from('<H', G, 0)[0]
    if 2 + c16 * 8 == len(G):
        idx_start, count = 2, c16
    else:
        count = struct.unpack_from('<I', G, 0)[0]
        idx_start = 4
    entries = []
    for i in range(count):
        pos = idx_start + i * 8
        if pos + 8 > len(G): break
        entries.append((struct.unpack_from('<I', G, pos)[0], struct.unpack_from('<I', G, pos + 4)[0]))
    return entries


def parse_all(pabgb_path, pabgh_path):
    """Parse all terrain region spawn entries."""
    with open(pabgb_path, 'rb') as f: D = f.read()
    with open(pabgh_path, 'rb') as f: G = f.read()

    idx = parse_pabgh(G)
    sorted_offs = sorted(set(off for _, off in idx))

    entries = []
    failures = 0

    for key, eoff in idx:
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry = parse_terrain_entry(D, eoff, end)
        if entry and not entry.get('parse_error'):
            entries.append(entry)
        else:
            failures += 1
            if entry:
                entries.append(entry)  # Keep partial parse

    return entries, failures, D


def summarize(entries):
    """Print summary of parsed data."""
    total_targets = sum(e.get('spawn_count', 0) for e in entries)
    total_parties = sum(
        sum(t.get('party_count', 0) for t in e.get('targets', []))
        for e in entries
    )
    total_chars = sum(
        sum(len(p.get('characters', [])) for t in e.get('targets', []) for p in t.get('parties', []))
        for e in entries
    )

    print(f"Regions: {len(entries)}")
    print(f"Total spawn targets: {total_targets}")
    print(f"Total spawn parties: {total_parties}")
    print(f"Total character refs: {total_chars}")

    # Show spawn rates
    rates = []
    for e in entries:
        for t in e.get('targets', []):
            for p in t.get('parties', []):
                rates.append(p.get('spawn_rate', 0))

    if rates:
        from collections import Counter
        rate_counts = Counter(f"{r:.2f}" for r in rates)
        print(f"\nSpawn rates distribution:")
        for rate, cnt in rate_counts.most_common(10):
            print(f"  {rate}: {cnt} parties")

    # Show entries with most targets
    print(f"\nRegions with most spawn targets:")
    for e in sorted(entries, key=lambda x: x.get('spawn_count', 0), reverse=True)[:10]:
        print(f"  {e['name']}: {e.get('spawn_count', 0)} targets, "
              f"{sum(t.get('party_count', 0) for t in e.get('targets', []))} parties")


def find_spawn_rates_by_signature(D):
    """Find all spawn_rate positions using the signature: 12 zero bytes + float.
    Returns list of (offset, current_value) tuples.

    The spawn_rate field is always preceded by 3 zero u32s (water depths + padding)
    and the value is a f32 (typically 1.0).
    """
    target = struct.pack('<f', 1.0)
    zero12 = b'\x00' * 12
    positions = []
    for i in range(12, len(D) - 3, 4):
        if D[i-12:i] == zero12:
            val = struct.unpack_from('<f', D, i)[0]
            if 0.0 < val <= 100.0:  # reasonable spawn rate range
                positions.append((i, val))
    return positions


def find_rates_per_entry(D, G):
    """Map spawn_rate positions to their parent terrain region entries.
    Returns list of {name, key, rates: [(offset, value)]} dicts.
    """
    idx = parse_pabgh(G)
    idx_sorted = sorted(idx, key=lambda x: x[1])
    all_rates = find_spawn_rates_by_signature(D)

    results = []
    for i, (key, off) in enumerate(idx_sorted):
        next_off = idx_sorted[i + 1][1] if i + 1 < len(idx_sorted) else len(D)
        k = struct.unpack_from('<I', D, off)[0]
        slen = struct.unpack_from('<I', D, off + 4)[0]
        name = D[off + 8:off + 8 + slen].decode('utf-8', errors='replace') if slen < 500 else '?'

        rates_in_entry = [(p, v) for p, v in all_rates if off <= p < next_off]
        results.append({
            'key': k,
            'name': name,
            'offset': off,
            'end': next_off,
            'rates': rates_in_entry,
        })

    return results


def get_verified_rate_offsets(D, G):
    """Get spawn rate offsets verified by the parse tree (safe to modify).
    Returns list of (offset, current_value, region_name) tuples.
    """
    entries, failures, _ = parse_all_from_bytes(D, G)
    verified = []
    for e in entries:
        if not e.get('parse_complete'):
            continue
        for t in e.get('targets', []):
            for p in t.get('parties', []):
                off = p.get('spawn_rate_offset', -1)
                if off > 0:
                    actual = struct.unpack_from('<f', D, off)[0]
                    if 0.0 <= actual <= 100.0:  # 0.0 = vanilla default
                        verified.append((off, actual, e.get('name', '')))
    return verified


def parse_all_from_bytes(D, G):
    """Parse from raw bytes (no file I/O)."""
    idx = parse_pabgh(G)
    sorted_offs = sorted(set(off for _, off in idx))
    entries = []
    failures = 0
    for key, eoff in idx:
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry = parse_terrain_entry(D, eoff, end)
        if entry and not entry.get('parse_error'):
            entries.append(entry)
        else:
            failures += 1
            if entry:
                entries.append(entry)
    return entries, failures, D


def multiply_spawn_rates(D, G, multiplier):
    """Set/multiply spawn rates. Returns count of changes.

    Vanilla rates are 0.0 (meaning "use default = 1.0").
    This sets them to the multiplier value, effectively: rate = max(current, 1.0) * multiplier.

    Only modifies offsets verified by the parse tree — no false positives.
    """
    verified = get_verified_rate_offsets(bytes(D), G)
    count = 0
    for offset, current, name in verified:
        # Treat 0.0 as default 1.0, then multiply
        base = current if current > 0.001 else 1.0
        new_val = min(base * multiplier, 20.0)
        struct.pack_into('<f', D, offset, new_val)
        count += 1
    return count


def parse_spawningpool_entry(D, eoff, end):
    """Parse one SpawningPoolAutoSpawnInfo entry.
    Field order from IDA decompile of sub_143A533C0_0_61:
      1. _key (4B)
      2. _stringKey (CString)
      3. _isBlocked (1B)
      4. _spawnList (sub_141067560 — AutoSpawnTargetData[], SAME as terrain)
      5. _meshNameList (sub_14105DE80 — u32 tag array)
      6. _spawningPoolData (CString)
      7. _type (1B)
      8. _nearOuterRadius (4B f32)
      9. _nearInnerRadius (4B f32)
      10. _spawnSafetyDistance (4B f32)
      11-15. u8 flags
    """
    p = eoff
    entry = {}
    try:
        entry['key'], p = _u32(D, p)
        entry['name'], p = _read_cstring(D, p)
        if p < 0: return None
        entry['is_blocked'], p = _u8(D, p)

        # 4. _spawnList — SAME nested structure as terrain!
        spawn_count, p = _u32(D, p)
        if spawn_count > 1000: return None
        entry['spawn_count'] = spawn_count
        entry['targets'] = []
        for _ in range(spawn_count):
            target, p = parse_target_data(D, p, end)
            if p < 0 or target is None:
                entry['parse_error'] = True
                return entry
            entry['targets'].append(target)

        # 5. _meshNameList (u32 tag array)
        p = _skip_key_lookup_array_u32(D, p)
        if p < 0: return None

        # 6. _spawningPoolData (CString)
        _, p = _read_cstring(D, p)
        if p < 0: return None

        # 7-10. type(1B) + outerRadius(4B) + innerRadius(4B) + safetyDist(4B)
        entry['pool_type'], p = _u8(D, p)
        entry['outer_radius'], p = _f32(D, p)
        entry['inner_radius'], p = _f32(D, p)
        entry['safety_distance'], p = _f32(D, p)

        entry['parse_complete'] = True
        return entry
    except (struct.error, IndexError) as e:
        entry['parse_error'] = str(e)
        return entry


def parse_spawningpool_all(pabgb_path_or_bytes, pabgh_path_or_bytes):
    """Parse all SpawningPoolAutoSpawnInfo entries."""
    if isinstance(pabgb_path_or_bytes, (bytes, bytearray)):
        D = bytes(pabgb_path_or_bytes)
        G = bytes(pabgh_path_or_bytes)
    else:
        with open(pabgb_path_or_bytes, 'rb') as f: D = f.read()
        with open(pabgh_path_or_bytes, 'rb') as f: G = f.read()

    idx = parse_pabgh(G)
    sorted_offs = sorted(set(off for _, off in idx))
    entries = []
    failures = 0
    for key, eoff in idx:
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry = parse_spawningpool_entry(D, eoff, end)
        if entry and not entry.get('parse_error'):
            entries.append(entry)
        else:
            failures += 1
            if entry: entries.append(entry)
    return entries, failures


def parse_stageinfo_complete_counts(D, G):
    """Parse stageinfo.pabgb to find _completeCount for all entries.

    _completeCount is a u16 at exactly 208 bytes from each entry's END.
    Verified on 50,294/50,294 entries with 97.6% cross-check rate.

    The field block at end-208 is: [randomPercent 8B][randomSpawnCount 4B][completeCount 2B][randomRepeatTime 4B]

    Returns list of {key, name, complete_count, complete_count_offset, entry_offset, entry_end}
    """
    idx = parse_pabgh(G)
    sorted_entries = sorted(idx, key=lambda x: x[1])

    results = []
    for i, (key, off) in enumerate(sorted_entries):
        next_off = sorted_entries[i + 1][1] if i + 1 < len(sorted_entries) else len(D)
        sz = next_off - off

        if sz < 220:
            continue  # too small, skip

        # Read entry header
        try:
            k = struct.unpack_from('<I', D, off)[0]
            slen = struct.unpack_from('<I', D, off + 4)[0]
            if slen > 500:
                continue
            name = D[off + 8:off + 8 + slen].decode('utf-8', errors='replace')
        except (struct.error, IndexError):
            continue

        # _completeCount at exactly end - 208
        cc_off = next_off - 208
        cc = struct.unpack_from('<H', D, cc_off)[0]

        # Cross-verify: 8 zero bytes at cc_off - 6 (the randomPercent field before randomSpawnCount)
        # This ensures we're reading the actual _completeCount and not random data
        rp_off = cc_off - 14  # randomPercent is 14B before completeCount (8B rp + 4B rsk + 2B cc)
        verified = False
        if rp_off >= off and rp_off + 8 <= len(D):
            rp_bytes = D[rp_off:rp_off + 8]
            if rp_bytes == b'\x00' * 8 and cc in (0, 1, 65535, 2, 3, 4, 5, 6):
                verified = True

        results.append({
            'key': k,
            'name': name,
            'complete_count': cc,
            'complete_count_offset': cc_off,
            'entry_offset': off,
            'entry_end': next_off,
            'verified': verified,
        })

    return results


def _classify_stage(name):
    """Classify a stage name into a category."""
    nl = name.lower()
    if 'quest_' in nl or '_quest_' in nl:
        return 'quest'
    if 'challenge' in nl:
        return 'challenge'
    if '_block_' in nl and 'boss' in nl:
        return 'boss'
    if '_block_' in nl:
        return 'encounter'
    if 'cd_seq_abyss' in nl:
        return 'abyss'
    if '_weather' in nl or '_weather_' in nl:
        return 'weather'
    if '_talk_' in nl or '_dialog' in nl or '_conversation' in nl:
        return 'dialogue'
    if 'allschedule' in nl or 'schedule' in nl:
        return 'schedule'
    if 'patrol' in nl:
        return 'patrol'
    if 'wildanimal' in nl or 'doc_land_animal' in nl or 'doc_waterside' in nl or 'doc_land_bird' in nl:
        return 'wildlife'
    if 'levelsequencerspawn_faction' in nl:
        return 'faction_spawn'
    if 'levelsequencerspawn_' in nl:
        return 'world_spawn'
    if '_battle_' in nl or '_combat' in nl:
        return 'battle'
    if 'spawn' in nl:
        return 'spawn'
    return 'other'


def set_stages_infinite_repeat(D, G, safe_only=False):
    """Set _completeCount to 65535 (infinite) on stages.

    Args:
        D: bytearray of stageinfo.pabgb
        G: bytes of stageinfo.pabgh
        safe_only: if True, only modify spawn/wildlife/encounter/boss/patrol/battle stages.
                   Excludes quests, challenges, dialogue, abyss weather.

    Returns (count_modified, count_skipped)
    """
    entries = parse_stageinfo_complete_counts(D, G)

    # Categories safe to make infinite (spawns, combat, wildlife)
    safe_categories = {
        'spawn', 'faction_spawn', 'world_spawn', 'wildlife',
        'encounter', 'boss', 'patrol', 'battle', 'schedule', 'other',
    }

    count = 0
    skipped = 0
    unverified = 0
    for e in entries:
        if e['complete_count'] != 1:
            continue

        # Only modify cross-verified entries to avoid corruption
        if not e.get('verified', False):
            unverified += 1
            continue

        if safe_only:
            cat = _classify_stage(e['name'])
            if cat not in safe_categories:
                skipped += 1
                continue

        struct.pack_into('<H', D, e['complete_count_offset'], 65535)
        count += 1

    return count, skipped + unverified


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')

    try:
        import crimson_rs
        game_path = 'C:/Program Files (x86)/Steam/steamapps/common/Crimson Desert'
        dp = 'gamedata/binary__/client/bin'
        body = crimson_rs.extract_file(game_path, '0008', dp, 'terrainregionautospawninfo.pabgb')
        gh = crimson_rs.extract_file(game_path, '0008', dp, 'terrainregionautospawninfo.pabgh')
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pabgb', delete=False) as f:
            f.write(body); pb = f.name
        with tempfile.NamedTemporaryFile(suffix='.pabgh', delete=False) as f:
            f.write(gh); pg = f.name
    except:
        EXT = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
        pb = f'{EXT}/terrainregionautospawninfo.pabgb'
        pg = f'{EXT}/terrainregionautospawninfo.pabgh'

    with open(pb, 'rb') as f: D = f.read()
    with open(pg, 'rb') as f: G = f.read()

    results = find_rates_per_entry(D, G)
    with_rates = [r for r in results if r['rates']]
    total_rates = sum(len(r['rates']) for r in results)

    print(f"Regions: {len(results)}")
    print(f"Regions with spawn rates: {len(with_rates)}")
    print(f"Total spawn rate positions: {total_rates}")
    print()

    # Categorize
    categories = {'Terrain': [], 'SideWalk/Town': [], 'GimmickSummon': [],
                   'Air/Bird': [], 'Fish': [], 'Horse/Wagon': [], 'Other': []}
    for r in with_rates:
        n = r['name']
        if n.startswith('Fish'): categories['Fish'].append(r)
        elif 'SideWalk' in n or 'Town' in n: categories['SideWalk/Town'].append(r)
        elif 'GimmickSummon' in n: categories['GimmickSummon'].append(r)
        elif 'Air_Bird' in n or 'Air_Drone' in n: categories['Air/Bird'].append(r)
        elif 'Horse' in n or 'Wagon' in n: categories['Horse/Wagon'].append(r)
        elif any(x in n for x in ['South', 'North', 'Desert', 'Rain', 'Snow', 'Sea']): categories['Terrain'].append(r)
        else: categories['Other'].append(r)

    for cat, items in categories.items():
        if not items: continue
        rates_count = sum(len(r['rates']) for r in items)
        print(f"{cat}: {len(items)} regions, {rates_count} spawn rates")
        for r in items[:5]:
            print(f"  {r['name']}: {len(r['rates'])} rates")
        if len(items) > 5:
            print(f"  ... and {len(items)-5} more")
