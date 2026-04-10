#!/usr/bin/env python3
"""RegionInfo PABGB Parser — complete field map from IDA decompilation of sub_141053790."""

import struct
import json
import os
import sys

def parse_pabgh_index(pabgh_data):
    count = struct.unpack_from('<H', pabgh_data, 0)[0]
    entries = {}
    pos = 2
    for i in range(count):
        key = struct.unpack_from('<H', pabgh_data, pos)[0]
        offset = struct.unpack_from('<I', pabgh_data, pos + 2)[0]
        entries[key] = offset
        pos += 6
    return entries

def parse_entry_header(data, off):
    """There is NO per-entry name header in RegionInfo PABGB.
    The _key and _stringKey are regular fields read by the table reader.
    Data starts directly at the PABGH offset."""
    return None, None, off

def parse_region_entry(data, off, end):
    """Parse one RegionInfo entry following the IDA-decoded reader order (sub_141053790)."""
    _, _, p = parse_entry_header(data, off)
    result = {}

    try:
        # 0: _key (u16, 2B) — stream.read(a2[0], 2)
        result['_key'] = struct.unpack_from('<H', data, p)[0]; p += 2

        # 1: _stringKey (sub_14100FE80: u32 len + string bytes)
        slen = struct.unpack_from('<I', data, p)[0]; p += 4
        if slen > 50000:
            result['_error'] = f'bad stringKey len={slen} at offset {p-4}'
            return result
        result['_stringKey'] = data[p:p+slen].decode('ascii', errors='replace'); p += slen

        # 2: _isBlocked (u8, 1B) — stream.read(a2[8], 1)
        result['_isBlocked'] = data[p]; p += 1

        # 3: _displayRegionName (sub_140ED6040: 1B flag + 8B hash + u32 len + string)
        flag = data[p]; p += 1
        hash_val = struct.unpack_from('<Q', data, p)[0]; p += 8
        dslen = struct.unpack_from('<I', data, p)[0]; p += 4
        if dslen > 50000:
            result['_error'] = f'bad displayRegionName len={dslen}'
            return result
        result['_displayRegionName_flag'] = flag
        result['_displayRegionName_hash'] = hash_val
        result['_displayRegionName_str'] = data[p:p+dslen].decode('utf-8', errors='replace'); p += dslen

        # 4: _knowledgeInfo (sub_1408F5560_0_1340: reads u32 key from stream, does hash lookup)
        result['_knowledgeInfo'] = struct.unpack_from('<I', data, p)[0]; p += 4

        # 5: _regionEnterknowledgeInfoList (sub_141064C20: u32 count + count*(u32 key + u32 val))
        # sub_1408F5560_0_1340 reads 4B from stream (not 2B), then 4B more = 8B per element
        rk_count = struct.unpack_from('<I', data, p)[0]; p += 4
        if rk_count > 50000:
            result['_error'] = f'bad rk_count={rk_count}'
            return result
        rk_list = []
        for _ in range(rk_count):
            rk_key = struct.unpack_from('<I', data, p)[0]; p += 4
            rk_val = struct.unpack_from('<I', data, p)[0]; p += 4
            rk_list.append((rk_key, rk_val))
        result['_regionEnterknowledgeInfoList'] = rk_list

        # 6: _parentRegionInfo (sub_14105E160: reads u16, 2B)
        result['_parentRegionInfo'] = struct.unpack_from('<H', data, p)[0]; p += 2

        # 7: _childRegionInfoList (sub_14105EA70: u32 count + count*u16)
        cr_count = struct.unpack_from('<I', data, p)[0]; p += 4
        if cr_count > 50000:
            result['_error'] = f'bad cr_count={cr_count}'
            return result
        cr_list = []
        for _ in range(cr_count):
            cr_list.append(struct.unpack_from('<H', data, p)[0]); p += 2
        result['_childRegionInfoList'] = cr_list

        # 8: _bitmapColor._r (u8, 1B) — stream.read(a2[52], 1)
        result['_bitmapColor_r'] = data[p]; p += 1

        # 9: _bitmapColor._g (u8, 1B) — stream.read((__int64)a2 + 105, 1)
        result['_bitmapColor_g'] = data[p]; p += 1

        # 10: _overriedMaxHeight (u32, 4B) — stream.read(a2[54], 4)
        result['_overriedMaxHeight_raw'] = struct.unpack_from('<I', data, p)[0]
        result['_overriedMaxHeight_float'] = struct.unpack_from('<f', data, p)[0]
        p += 4

        # 11: _regionType (u8, 1B) — stream.read(a2[56], 1)
        result['_regionType'] = data[p]; p += 1

        # 12: _fogClearCondition (sub_1408F5560_0_1337: reads u32, 4B key lookup)
        result['_fogClearCondition'] = struct.unpack_from('<I', data, p)[0]; p += 4

        # 13: _limitVehicleRun (u8, 1B) — stream.read(a2[58], 1)
        result['_limitVehicleRun'] = data[p]; p += 1

        # 14: _isTown (u8, 1B) — stream.read((__int64)a2 + 117, 1)
        result['_isTown'] = data[p]; p += 1

        # 15: _isWild (u8, 1B) — stream.read(a2[59], 1)
        result['_isWild'] = data[p]; p += 1

        # 16: _isUIMapDisable (u8, 1B) — stream.read((__int64)a2 + 119, 1)
        result['_isUIMapDisable'] = data[p]; p += 1

        # 17: _isSaveGimmickRegion (u8, 1B) — stream.read(a2[60], 1)
        result['_isSaveGimmickRegion'] = data[p]; p += 1

        # 18: _isNonePlayZone (u8, 1B) — stream.read((__int64)a2 + 121, 1)
        result['_isNonePlayZone'] = data[p]; p += 1

        # 19: _vehicleMercenaryAllowType (u8, 1B) — stream.read(a2[61], 1)
        result['_vehicleMercenaryAllowType'] = data[p]; p += 1

        # 20: _isWorldMapRoadPathFindable (u8, 1B) — stream.read((__int64)a2 + 123, 1)
        result['_isWorldMapRoadPathFindable'] = data[p]; p += 1

        # 21: _gimmickAliasPointerList (sub_141064D30: u32 count + count*(u32 key + u32 val))
        # sub_1408F5560_0_1356 reads 4B from stream (like _1340), then 4B more = 8B per element
        ga_count = struct.unpack_from('<I', data, p)[0]; p += 4
        if ga_count > 50000:
            result['_error'] = f'bad ga_count={ga_count}'
            return result
        ga_list = []
        for _ in range(ga_count):
            ga_key = struct.unpack_from('<I', data, p)[0]; p += 4
            ga_val = struct.unpack_from('<I', data, p)[0]; p += 4
            ga_list.append((ga_key, ga_val))
        result['_gimmickAliasPointerList'] = ga_list

        # 22: _domainFactionList (sub_141069840: u32 count + count*(4B cond + 4B faction + 4B prison))
        # All three sub-readers (_1337, _1342, _1351) read 4B from stream each = 12B per element
        df_count = struct.unpack_from('<I', data, p)[0]; p += 4
        if df_count > 50000:
            result['_error'] = f'bad df_count={df_count}'
            return result
        df_list = []
        for _ in range(df_count):
            df_cond = struct.unpack_from('<I', data, p)[0]; p += 4
            df_faction = struct.unpack_from('<I', data, p)[0]; p += 4
            df_prison = struct.unpack_from('<I', data, p)[0]; p += 4
            df_list.append({'_condition': df_cond, '_domainFaction': df_faction, '_prisonStage': df_prison})
        result['_domainFactionList'] = df_list

        # 23: _tagList (sub_14105DE80: u32 count + count*u32)
        tl_count = struct.unpack_from('<I', data, p)[0]; p += 4
        if tl_count > 50000:
            result['_error'] = f'bad tl_count={tl_count}'
            return result
        tl_list = []
        for _ in range(tl_count):
            tl_list.append(struct.unpack_from('<I', data, p)[0]); p += 4
        result['_tagList'] = tl_list

        result['_parsed_bytes'] = p - off
        result['_entry_size'] = end - off
        result['_bytes_remaining'] = end - p

    except (struct.error, IndexError) as e:
        result['_error'] = str(e)
        result['_error_at_abs'] = p

    return result


def main():
    base = os.environ.get('EXTRACTED_PAZ', './extracted/0008_full')
    with open(os.path.join(base, 'regioninfo.pabgb'), 'rb') as f:
        pabgb = f.read()
    with open(os.path.join(base, 'regioninfo.pabgh'), 'rb') as f:
        pabgh = f.read()

    entries = parse_pabgh_index(pabgh)
    sorted_entries = sorted(entries.items(), key=lambda x: x[1])
    sizes = {}
    for i in range(len(sorted_entries)):
        k, o = sorted_entries[i]
        if i + 1 < len(sorted_entries):
            sizes[k] = sorted_entries[i+1][1] - o
        else:
            sizes[k] = len(pabgb) - o

    # Parse all records
    success = 0
    fail = 0
    nonzero_remaining = 0
    results = []

    for key, eoff in sorted_entries:
        end = eoff + sizes[key]
        r = parse_region_entry(pabgb, eoff, end)
        results.append(r)
        if '_error' in r:
            fail += 1
            if fail <= 5:
                print(f'FAIL key={key}: {r["_error"]}', file=sys.stderr)
        else:
            success += 1
            rem = r['_bytes_remaining']
            if rem != 0:
                nonzero_remaining += 1
                if nonzero_remaining <= 5:
                    print(f'WARN key={key}: {rem} bytes remaining', file=sys.stderr)

    print(f'=== VALIDATION: {success}/{len(sorted_entries)} parsed OK, {fail} failed, {nonzero_remaining} with leftover bytes ===')

    # Print first 3 entries
    for r in results[:3]:
        print(json.dumps({k: v for k, v in r.items() if not k.startswith('_displayRegionName_hash')},
                         indent=2, default=str, ensure_ascii=True))

    # Find dismount-related fields
    print('\n=== DISMOUNT/VEHICLE FIELDS ANALYSIS ===')
    towns = []
    vehicle_restricted = []
    for r in results:
        if '_error' in r:
            continue
        if r.get('_isTown', 0):
            towns.append((r['_key'], r['_stringKey']))
        if r.get('_limitVehicleRun', 0):
            vehicle_restricted.append((r['_key'], r['_stringKey'], r['_limitVehicleRun']))

    print(f'Town regions (_isTown=1): {len(towns)}')
    for k, n in towns[:10]:
        print(f'  key={k}: {n}')
    print(f'Vehicle-restricted (_limitVehicleRun>0): {len(vehicle_restricted)}')
    for k, n, v in vehicle_restricted[:10]:
        print(f'  key={k}: {n} (value={v})')

    # vehicleMercenaryAllowType distribution
    vtypes = {}
    for r in results:
        if '_error' in r:
            continue
        vt = r.get('_vehicleMercenaryAllowType', 0)
        vtypes[vt] = vtypes.get(vt, 0) + 1
    print(f'\n_vehicleMercenaryAllowType distribution: {vtypes}')


if __name__ == '__main__':
    main()
