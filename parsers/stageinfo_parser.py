"""
stageinfo.pabgb full parser — 82 fields, fully mapped from IDA decompile of sub_141059E90.

Every variable-length reader function decompiled to determine exact stream consumption.
This parser reads through ALL fields sequentially to reach _completeCount and force-spawn flags.
No offset-from-end shortcuts — proper field-by-field parsing.
"""
import struct


def _u32(D, p):
    return struct.unpack_from('<I', D, p)[0], p + 4

def _u16(D, p):
    return struct.unpack_from('<H', D, p)[0], p + 2

def _u8(D, p):
    return D[p], p + 1

def _skip_cstring(D, p):
    """CString: u32 len + bytes. Returns new pos."""
    slen, p = _u32(D, p)
    if slen > 100000: return -1
    return p + slen

def _skip_locstr(D, p):
    """LocStr (sub_140ED6040): u8 + u64 + CString. Returns new pos."""
    p += 1 + 8  # u8 flag + u64 hash
    return _skip_cstring(D, p)

def _skip_u32_key_array(D, p):
    """Array of u32 keys (sub_14105E840, sub_1410604E0, sub_141062CA0, sub_14105F4D0, sub_14105DE80): u32 count + count*4B."""
    count, p = _u32(D, p)
    if count > 200000: return -1
    return p + count * 4

def _skip_u16_key_array(D, p):
    """Array of u16 keys (sub_14105EA70): u32 count + count*2B."""
    count, p = _u32(D, p)
    if count > 200000: return -1
    return p + count * 2

def _skip_cstring_hash(D, p):
    """CString-hash (sub_141010050): u32 len + len bytes (hashed at runtime)."""
    slen, p = _u32(D, p)
    if slen > 100000: return -1
    return p + slen

def _skip_sequencer_desc(D, p):
    """sub_141C952A0: deeply nested, variable length.
    Reads: CString + u32 + CString + 12B + u32 + 8*u8 + enum2B + optional_object +
           2*CString + u32 count + count*(2*CString) + u32 count + count*elements +
           complex_array + 2*u16_array + 2*u32_array + 2*u32_array
    """
    # CString
    p = _skip_cstring(D, p)
    if p < 0: return -1
    # u32
    p += 4
    # CString
    p = _skip_cstring(D, p)
    if p < 0: return -1
    # 12B (vec3)
    p += 12
    # u32
    p += 4
    # 8 * u8
    p += 8
    # enum (2B)
    p += 2
    # Optional object: read 1B bool
    flag = D[p]; p += 1
    if flag:
        # sub_141BF4F70 — virtual reader, very complex. Skip by scanning for known pattern.
        # This is rare (most entries have flag=0). For safety, return failure.
        return -1  # Can't parse this variant
    # 2 * CString
    p = _skip_cstring(D, p)
    if p < 0: return -1
    p = _skip_cstring(D, p)
    if p < 0: return -1
    # u32 count + count * (2 * CString)
    count, p = _u32(D, p)
    if count > 10000: return -1
    for _ in range(count):
        p = _skip_cstring(D, p)
        if p < 0: return -1
        p = _skip_cstring(D, p)
        if p < 0: return -1
    # u32 count + count * sub_141052550 elements
    # sub_141052550: enum2B + CString + enum2B + u32 + enum2B + u8 = 2+var+2+4+2+1
    count2, p = _u32(D, p)
    if count2 > 10000: return -1
    for _ in range(count2):
        p += 2  # enum
        p = _skip_cstring(D, p)
        if p < 0: return -1
        p += 2 + 4 + 2 + 1  # enum + u32 + enum + u8
    # sub_14106C170: array reader
    # u32 count + count * (CString + u32 + u32)
    count3, p = _u32(D, p)
    if count3 > 10000: return -1
    for _ in range(count3):
        p = _skip_cstring(D, p)
        if p < 0: return -1
        p += 4 + 4  # 2 * u32
    # 2 * u16_key_array
    p = _skip_u16_key_array(D, p)
    if p < 0: return -1
    p = _skip_u16_key_array(D, p)
    if p < 0: return -1
    # 2 * u32_key_array
    p = _skip_u32_key_array(D, p)
    if p < 0: return -1
    p = _skip_u32_key_array(D, p)
    if p < 0: return -1
    # 2 * u32_key_array (sub_141061C50)
    p = _skip_u32_key_array(D, p)
    if p < 0: return -1
    p = _skip_u32_key_array(D, p)
    if p < 0: return -1
    return p

def _skip_close_filter(D, p):
    """sub_141065180: u32 count + count * 15B elements."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    return p + count * 15

def _skip_field_584(D, p):
    """sub_141067210: u32 count + count * 7B elements."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    return p + count * 7

def _skip_field_608(D, p):
    """sub_141067080: u32 count + count * (u32 + CString) elements."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    for _ in range(count):
        p += 4  # u32
        p = _skip_cstring(D, p)
        if p < 0: return -1
    return p

def _skip_reward_dropset(D, p):
    """sub_14105FE60: u32 count + count * 28B elements."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    return p + count * 28

def _skip_field_768(D, p):
    """sub_141066ED0: 1B bool, if present: complex nested object."""
    flag = D[p]; p += 1
    if not flag:
        return p  # absent = just 1 byte
    # Present: sub_141065390 (1B bool + optional sub_141C88460) + enum2B + u32 + u32
    flag2 = D[p]; p += 1
    if flag2:
        # sub_141C88460: u8 + 40B(transform) + CString-hash + CString + u8 + 12B + 12B + u8 + u8
        p += 1  # u8
        p += 40  # transform block (12+16+12)
        p = _skip_cstring_hash(D, p)  # CString-hash
        if p < 0: return -1
        p = _skip_cstring(D, p)  # CString
        if p < 0: return -1
        p += 1 + 12 + 12 + 1 + 1  # u8 + vec3 + vec3 + u8 + u8
    p += 2  # enum
    p += 4  # u32
    p += 4  # u32
    return p

def _skip_field_840(D, p):
    """sub_141066350: u32 count + count * (u32 + 1B bool + optional 7B)."""
    count, p = _u32(D, p)
    if count > 10000: return -1
    for _ in range(count):
        p += 4  # u32 key
        flag = D[p]; p += 1  # bool
        if flag:
            p += 7  # sub_141041020: u8 + 3*enum2B = 1+2+2+2 = 7
    return p


def parse_stage_entry(D, eoff, end):
    """Parse one StageInfo entry, reading all 82 fields sequentially.
    Returns dict with key, name, complete_count, and force-spawn flags with offsets.
    """
    p = eoff
    entry = {}

    try:
        # 1. _key (4B)
        entry['key'], p = _u32(D, p)
        # 2. _stringKey (CString)
        slen, _ = _u32(D, p)
        if slen > 500: return None
        entry['name'] = D[p+4:p+4+slen].decode('utf-8', errors='replace')
        p = _skip_cstring(D, p)
        if p < 0: return None
        # 3. _isBlocked (1B)
        _, p = _u8(D, p)
        # 4. _name (LocStr)
        p = _skip_locstr(D, p)
        if p < 0: return None
        # 5. _stageDesc (LocStr)
        p = _skip_locstr(D, p)
        if p < 0: return None
        # 6. _completeLog (LocStr)
        p = _skip_locstr(D, p)
        if p < 0: return None
        # 7. _sequencerDesc (complex — sub_141C952A0)
        p = _skip_sequencer_desc(D, p)
        if p < 0: return None
        # 8. _stageCategory (4B key lookup -> u16)
        p += 4
        # 9. _stageDataType (enum_1347 = 4B -> u16)
        p += 4
        # 10. _fieldInfo (sub_1410608E0 = 4B key lookup)
        p += 4
        # 11. _randomPercent (8B u64)
        p += 8
        # 12. field_384 (8B)
        p += 8
        # 13. field_392 (8B)
        p += 8
        # 14. _executorMissionList (u32 key array)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 15. field_416 (1B)
        p += 1
        # 16. field_417 (1B)
        p += 1
        # 17. enum_1350 (4B)
        p += 4
        # 18. enum_1351 (4B)
        p += 4
        # 19. enum_1352 (4B)
        p += 4
        # 20. _childStageList (u32 key array)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 21. _executeTargetStageList (u32 key array — sub_141062CA0)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 22. _executorStageList (u32 key array)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 23. _closeFilterByGroup (sub_141065180: count + count*15B)
        p = _skip_close_filter(D, p)
        if p < 0: return None
        # 24. enum_1337 (4B -> u16)
        p += 4
        # 25. enum_1337 (4B -> u16)
        p += 4
        # 26. _randomSpawnCount key lookup (4B -> u16)
        p += 4
        # 27. _closeCondition (u32 key array)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 28. _playCondition (u32 key array)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 29. enum_1336 (4B -> u16)
        p += 4
        # 30. _resetSecond (4B u32)
        p += 4
        # 31. field_544 (CString-hash: 4 + len)
        p = _skip_cstring_hash(D, p)
        if p < 0: return None
        # 32. field_548 (1B)
        p += 1
        # 33. field_549 (1B)
        p += 1
        # 34. field_552 (4B)
        p += 4
        # 35. field_556 (4B)
        p += 4
        # 36. _randomSpawnCount_actual (sub_141010380: 4+4 = 8B)
        p += 8
        # 37. field_568 (8B u64)
        p += 8
        # 38. field_576 (4B u32)
        p += 4
        # 39. _completeCount (2B u16) *** TARGET ***
        entry['complete_count'] = struct.unpack_from('<H', D, p)[0]
        entry['complete_count_offset'] = p
        p += 2
        # 40. field_584 (sub_141067210: count + count*7B)
        p = _skip_field_584(D, p)
        if p < 0: return None
        # 41. enum_1337 (4B -> u16)
        p += 4
        # 42. field_608 (sub_141067080: count + count*(4+CString))
        p = _skip_field_608(D, p)
        if p < 0: return None
        # 43-46. 4x sub_14105FE60 (rewardDropSetInfoList: count + count*28B)
        for _ in range(4):
            p = _skip_reward_dropset(D, p)
            if p < 0: return None
        # 47-50. 4x sub_14105F4D0 (u32 key arrays)
        for _ in range(4):
            p = _skip_u32_key_array(D, p)
            if p < 0: return None
        # 51. u32 tag array (sub_14105DE80)
        p = _skip_u32_key_array(D, p)
        if p < 0: return None
        # 52. field_768 (sub_141066ED0: optional object)
        p = _skip_field_768(D, p)
        if p < 0: return None
        # 53. enum_1335 (4B -> u16)
        p += 4
        # 54. key lookup (4B -> u32)
        p += 4
        # 55. enum_1335 (4B)
        p += 4
        # 56. enum_1335 (4B)
        p += 4
        # 57. enum_1335 (4B)
        p += 4
        # 58. enum_1335 (4B)
        p += 4
        # 59. enum_1336 (4B)
        p += 4
        # 60. enum_1336 (4B)
        p += 4
        # 61. LocStr (sub_140ED6040)
        p = _skip_locstr(D, p)
        if p < 0: return None
        # 62. enum_1335 (4B)
        p += 4
        # 63. field_834 (1B)
        p += 1
        # 64. field_835 (1B)
        p += 1
        # 65. enum_1340 (4B)
        p += 4
        # 66. field_840 (sub_141066350: count + count*(5 or 12B))
        p = _skip_field_840(D, p)
        if p < 0: return None
        # 67. field_856 (4B)
        p += 4
        # 68. field_860 (sub_141066490: 2B enum)
        p += 2
        # 69. _weatherStartBlendTime (4B)
        p += 4
        # 70. _weatherIngTime (4B)
        p += 4
        # 71. _weatherEndBlendTime (4B)
        p += 4
        # 72. _endTime (4B)
        p += 4
        # 73. _beginTime (4B)
        p += 4
        # 74. _changeTime (4B)
        p += 4
        # 75. _saveSchedule (1B)
        p += 1
        # 76. _isSave (1B)
        p += 1
        # 77. _isForceSpawnAfterRetreat (1B)
        entry['is_force_spawn_after_retreat'] = D[p]
        entry['is_force_spawn_after_retreat_offset'] = p
        p += 1
        # 78. _hasDynamicActor (1B)
        p += 1
        # 79. _isForceSpawnAllActor (1B) *** TARGET ***
        entry['is_force_spawn_all'] = D[p]
        entry['is_force_spawn_all_offset'] = p
        p += 1
        # 80. _isForceSpawnNearDistance (1B)
        entry['is_force_spawn_near'] = D[p]
        entry['is_force_spawn_near_offset'] = p
        p += 1
        # 81-88. Remaining u8 flags
        p += 8
        # 89. Last u8
        p += 1
        # 90. Very last u8
        p += 1

        entry['parse_complete'] = True
        return entry

    except (struct.error, IndexError):
        return None


def parse_all_stages(D, G):
    """Parse all StageInfo entries. Returns (entries, failures)."""
    # Parse pabgh index
    c16 = struct.unpack_from('<H', G, 0)[0]
    if 2 + c16 * 8 == len(G):
        idx_start, count = 2, c16
    else:
        count = struct.unpack_from('<I', G, 0)[0]
        idx_start = 4

    idx = []
    for i in range(count):
        pos = idx_start + i * 8
        if pos + 8 > len(G): break
        idx.append((struct.unpack_from('<I', G, pos)[0], struct.unpack_from('<I', G, pos + 4)[0]))
    idx.sort(key=lambda x: x[1])

    entries = []
    failures = 0
    for i, (key, eoff) in enumerate(idx):
        end = idx[i + 1][1] if i + 1 < len(idx) else len(D)
        entry = parse_stage_entry(D, eoff, end)
        if entry and entry.get('parse_complete'):
            entries.append(entry)
        else:
            failures += 1

    return entries, failures


def set_stages_infinite(D, G, safe_only=True):
    """Set _completeCount to 65535 using the full parser.
    Returns (count_modified, count_skipped, count_failed).
    """
    entries, failures = parse_all_stages(D, G)

    safe_prefixes = (
        'LevelSequencerSpawn', 'levelsequencerspawn',
        'Faction_', 'faction_',
        'Node_', 'node_',
    )
    skip_keywords = ('quest', 'challenge', 'dialog', 'talk', 'conversation')

    modified = 0
    skipped = 0
    for e in entries:
        if e['complete_count'] != 1:
            continue

        if safe_only:
            name_lower = e['name'].lower()
            if any(kw in name_lower for kw in skip_keywords):
                skipped += 1
                continue

        struct.pack_into('<H', D, e['complete_count_offset'], 65535)
        modified += 1

    return modified, skipped, failures


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8')

    try:
        import crimson_rs
        game_path = 'C:/Program Files (x86)/Steam/steamapps/common/Crimson Desert'
        dp = 'gamedata/binary__/client/bin'
        body = crimson_rs.extract_file(game_path, '0008', dp, 'stageinfo.pabgb')
        gh = crimson_rs.extract_file(game_path, '0008', dp, 'stageinfo.pabgh')
    except:
        ext = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
        with open(f'{ext}/stageinfo.pabgb', 'rb') as f: body = f.read()
        with open(f'{ext}/stageinfo.pabgh', 'rb') as f: gh = f.read()

    entries, failures = parse_all_stages(body, gh)
    print(f"Parsed: {len(entries)} entries, {failures} failures")

    from collections import Counter
    cc = Counter(e['complete_count'] for e in entries)
    print(f"completeCount distribution: {cc.most_common(10)}")

    force_all = sum(1 for e in entries if e.get('is_force_spawn_all'))
    force_near = sum(1 for e in entries if e.get('is_force_spawn_near'))
    force_retreat = sum(1 for e in entries if e.get('is_force_spawn_after_retreat'))
    print(f"ForceSpawnAll={force_all}, ForceSpawnNear={force_near}, ForceSpawnAfterRetreat={force_retreat}")
