"""
Universal PABGB Dumper — Decompiles ALL pabgb files from the game PAZ.

Uses the auto-extracted schema (434 tables, 3708 fields, 70% with sizes)
to parse every entry in every pabgb and dump readable field values.

Outputs:
  pabgb_full_dump/           — one JSON per table (human-readable field values)
  pabgb_full_dump/index.json — master index with cross-references
  pabgb_full_dump/search.txt — flat text file for grep/string search

Usage:
  python universal_pabgb_dumper.py
"""
import struct
import json
import os
import sys
import time

# ── Schema + reader sizes ────────────────────────────────────

def load_schema():
    schema_path = os.path.join(os.path.dirname(__file__), 'pabgb_complete_schema.json')
    if not os.path.exists(schema_path):
        print("ERROR: pabgb_complete_schema.json not found. Run the schema dumper first.")
        sys.exit(1)
    return json.load(open(schema_path, 'r', encoding='utf-8'))


# Map table names (from schema) to pabgb filenames
TABLE_TO_FILE = {
    'ItemInfo': 'iteminfo',
    'CharacterInfo': 'characterinfo',
    'StoreInfo': 'storeinfo',
    'SkillInfo': 'skillinfo',
    'KnowledgeInfo': 'knowledgeinfo',
    'QuestInfo': 'questinfo',
    'MissionInfo': 'missioninfo',
    'BuffInfo': 'buffinfo',
    'FactionNodeInfo': 'factionnode',
    'FactionInfo': 'factioninfo',
    'FactionGroupInfo': 'factiongroupinfo',
    'FactionSpawnDataInfo': 'factionspawndatainfo',
    'FactionNodeSpawnInfo': 'factionnodespawninfo',
    'FieldInfo': 'fieldinfo',
    'VehicleInfo': 'vehicleinfo',
    'GamePlayTriggerInfo': 'gameplaytrigger',
    'GamePlayVariableInfo': 'gameplayvariableinfo',
    'GimmickInfo': 'gimmickinfo',
    'GimmickGroupInfo': 'gimmickgroupinfo',
    'DropSetInfo': 'dropsetinfo',
    'RegionInfo': 'regioninfo',
    'NpcInfo': 'npcinfo',
    'EquipTypeInfo': 'equiptypeinfo',
    'CategoryInfo': 'categoryinfo',
    'CategoryGroupInfo': 'categorygroupinfo',
    'ItemGroupInfo': 'itemgroupinfo',
    'StringInfo': 'stringinfo',
    'LocalStringInfo': 'localstringinfo',
    'ConditionInfo': 'conditioninfo',
    'InteractionInfo': 'interactioninfo',
    'StageInfo': 'stageinfo',
    'TerrainRegionAutoSpawnInfo': 'terrainregionautospawninfo',
    'SpawningPoolAutoSpawnInfo': 'spawningpoolautospawninfo',
    'SequencerSpawnInfo': 'sequencerspawninfo',
    'MercenaryInfo': 'mercenaryinfo',
    'TribeInfo': 'tribeinfo',
    'SubLevelInfo': 'sublevelinfo',
    'DialogVoiceInfo': 'dialogvoiceinfo',
    'EffectInfo': 'effectinfo',
    'SkillTreeInfo': 'skilltreeinfo',
    'SkillTreeGroupInfo': 'skilltreegroupinfo',
    'SkillGroupInfo': 'skillgroupinfo',
    'CharacterGroupInfo': 'charactergroupinfo',
    'AllyGroupInfo': 'allygroupinfo',
    'JobInfo': 'jobinfo',
    'StatusInfo': 'statusinfo',
    'StatusGroupInfo': 'statusgroupinfo',
    'GameAdviceInfo': 'gameadviceinfo',
    'GameAdviceGroupInfo': 'gameadvicegroupinfo',
    'LevelGimmickSceneObjectInfo': 'levelgimmicksceneobjectinfo',
    'QuestGroupInfo': 'questgroupinfo',
    'QuestGaugeInfo': 'questgaugeinfo',
    'FormationInfo': 'formationinfo',
    'BreakableObjectInfo': 'breakableobjectinfo',
    'RelationInfo': 'relationinfo',
    'SocketInfo': 'socketinfo',
    'SocketGroupInfo': 'socketgroupinfo',
    'DyeColorGroupInfo': 'dyecolorgroupinfo',
    'PartPrefabDyeSlotInfo': 'partprefabdyeslotinfo',
    'WantedInfo': 'wantedinfo',
    'RoyalSupplyInfo': 'royalsupplyinfo',
    'DetectInfo': 'detectinfo',
    'DetectDetailInfo': 'detectdetailinfo',
    'DetectReactionInfo': 'detectreactioninfo',
    'ElementalMaterialInfo': 'elementalmaterialinfo',
    'MaterialMatchInfo': 'materialmatchinfo',
    'MaterialRelationInfo': 'materialrelationinfo',
    'MiniGameDataInfo': 'minigamedatainfo',
    'MultiChangeInfo': 'multichangeinfo',
    'EnchantData': 'enchantdata',
    'InventoryInfo': 'inventoryinfo',
    'CollectionInfo': 'collectioninfo',
    'BoardInfo': 'boardinfo',
    'ItemUseInfo': 'itemuseinfo',
    'QuickTimeEventInfo': 'quicktimeeventinfo',
    'SpecialModeInfo': 'specialmodeinfo',
    'PlatformAchievementInfo': 'platformachievementinfo',
    'TradeMarketItemInfo': 'trademarketiteminfo',
    'BitmapPositionInfo': 'bitmappositioninfo',
    'FieldReviveInfo': 'fieldreviveinfo',
    'PatternDescriptionInfo': 'patterndescriptioninfo',
    'KnowledgeGroupInfo': 'knowledgegroupinfo',
    'GimmickGateInfo': 'gimmickgateinfo',
    'GimmickGateConnectionInfo': 'gimmickgateconnectioninfo',
    'GimmickEventTableInfo': 'gimmickeventtableinfo',
    'GameEventHandlerInfo': 'gameeventhandlerinfo',
    'GameGlobalEffectInfo': 'gameglobaleffectinfo',
    'GlobalGameEventInfo': 'globalgameeventinfo',
    'GlobalGameEventGroupInfo': 'globalgameeventgroupinfo',
    'GlobalStageSequencerInfo': 'globalstagesequencerinfo',
    'FactionRelationGroupInfo': 'factionrelationgroupinfo',
    'FactionWayPointInfo': 'factionwaypointinfo',
    'ValidScheduleActionInfo': 'validscheduleactioninfo',
    'TriggerRegionInfo': 'triggerregioninfo',
    'UIMapTextureInfo': 'uimaptextureinfo',
    'ActionRestrictionOrderInfo': 'actionrestrictionorderinfo',
    'AutoSpawnFilterInfo': 'autospawnfilterinfo',
    'FrameEventAttrGroupInfo': 'frameeventattrgroupinfo',
    'CraftToolInfo': 'crafttoolinfo',
    'CraftToolGroupInfo': 'crafttoolgroup',
    'LevelActionPointInfo': 'levelactionpointinfo',
    'AIDialogStringInfo': 'aidialogstringinfo',
    'AIDialogTypeInfo': 'aidialogtypeinfo',
    'AIEventTableInfo': 'aieventtableinfo',
    'AIMoveSpeedInfo': 'aimovespeedinfo',
    'FieldLevelNameTableInfo': 'fieldlevelnametableinfo',
    'CharacterChangeInfo': 'characterchangeinfo',
    'CharacterAppearanceIndexInfo': 'characterappearanceindexinfo',
    'FailMessageInfo': 'failmessageinfo',
    'ReserveSlotInfo': 'reserveslotinfo',
    'UISocialActionInfo': 'uisocialactioninfo',
    'VibratePatternInfo': 'vibratepatterninfo',
    'KeyMapSettingListInfo': 'keymapsettinglistinfo',
    'MaterialBloodDecalInfo': 'materialblooddecalinfo',
}


def parse_pabgh(data):
    """Parse pabgh index. Returns dict {key: offset}."""
    if len(data) < 4:
        return {}
    c16 = struct.unpack_from('<H', data, 0)[0]
    if 2 + c16 * 8 == len(data):
        idx_start, count = 2, c16
        entry_size = 8
    elif 2 + c16 * 6 == len(data):
        idx_start, count = 2, c16
        entry_size = 6
    else:
        count = struct.unpack_from('<I', data, 0)[0]
        idx_start = 4
        entry_size = 8

    idx = {}
    for i in range(count):
        pos = idx_start + i * entry_size
        if pos + entry_size > len(data):
            break
        if entry_size == 8:
            k = struct.unpack_from('<I', data, pos)[0]
            o = struct.unpack_from('<I', data, pos + 4)[0]
        else:  # 6-byte entries (u16 key + u32 offset)
            k = struct.unpack_from('<H', data, pos)[0]
            o = struct.unpack_from('<I', data, pos + 2)[0]
        idx[k] = o
    return idx


def read_field(D, p, field_info):
    """Read a single field from the data stream.
    Returns (value, new_position) or (None, -1) on failure.
    """
    stream = field_info.get('stream')
    ftype = field_info.get('type', 'unknown')

    try:
        if ftype == 'CString' or stream == '4+len':
            slen = struct.unpack_from('<I', D, p)[0]
            if slen > 50000:
                return f"<bad_len:{slen}>", -1
            s = D[p+4:p+4+slen].decode('utf-8', errors='replace')
            return s, p + 4 + slen

        elif ftype == 'LocStr' or stream == '1+8+4+len':
            flag = D[p]
            hash_val = struct.unpack_from('<Q', D, p+1)[0]
            slen = struct.unpack_from('<I', D, p+9)[0]
            if slen > 50000:
                return f"<locstr_bad_len:{slen}>", -1
            s = D[p+13:p+13+slen].decode('utf-8', errors='replace')
            return f"LocStr({hash_val:#x}, '{s}')", p + 13 + slen

        elif ftype == 'Blob' or stream == '4+len':
            blen = struct.unpack_from('<I', D, p)[0]
            if blen > 500000:
                return f"<blob_bad_len:{blen}>", -1
            return f"<blob:{blen}B>", p + 4 + blen

        elif ftype in ('direct_u8',) or stream == 1:
            return D[p], p + 1

        elif ftype in ('direct_u16',) or stream == 2:
            return struct.unpack_from('<H', D, p)[0], p + 2

        elif ftype in ('direct_u32', 'enum4B', 'reader_4B') or stream == 4:
            return struct.unpack_from('<I', D, p)[0], p + 4

        elif ftype in ('direct_u64', 'reader_8B') or stream == 8:
            return struct.unpack_from('<Q', D, p)[0], p + 8

        elif ftype in ('direct_12B', 'reader_12B') or stream == 12:
            x, y, z = struct.unpack_from('<fff', D, p)
            return f"({x:.2f}, {y:.2f}, {z:.2f})", p + 12

        elif ftype in ('direct_15B', 'reader_15B') or stream == 15:
            return D[p:p+15].hex(), p + 15

        elif ftype in ('direct_13B', 'reader_13B') or stream == 13:
            return D[p:p+13].hex(), p + 13

        elif ftype in ('direct_16B',) or stream == 16:
            return D[p:p+16].hex(), p + 16

        elif ftype in ('direct_u40',) or stream == 5:
            return D[p:p+5].hex(), p + 5

        elif ftype in ('reader_2B', 'key2B', 'enum2B') or stream == 2:
            return struct.unpack_from('<H', D, p)[0], p + 2

        elif ftype in ('reader_1B',) or stream == 1:
            return D[p], p + 1

        elif ftype == 'reader_14B' or stream == 14:
            return D[p:p+14].hex(), p + 14

        elif ftype == 'reader_5B' or stream == 5:
            return D[p:p+5].hex(), p + 5

        elif isinstance(stream, int) and stream > 0:
            return D[p:p+stream].hex(), p + stream

        elif 'array' in str(ftype):
            # Array: u32 count + count * element
            count = struct.unpack_from('<I', D, p)[0]
            if count > 100000:
                return f"<bad_array:{count}>", -1
            # We don't know element size for complex arrays, just record count
            return f"<array:{count}>", -1  # Stop parsing this entry

        else:
            return None, -1  # Unknown type, stop

    except (struct.error, IndexError):
        return None, -1


def parse_entry(D, offset, end, field_defs):
    """Parse one pabgb entry using field definitions.
    Returns dict of field_name → value.
    """
    result = {}
    p = offset

    for fdef in field_defs:
        if p >= end or p < 0:
            break

        fname = fdef['f']
        val, new_p = read_field(D, p, fdef)

        if val is not None:
            result[fname] = val
        else:
            result[fname] = f"<parse_stopped at +{p - offset}>"
            break

        if new_p < 0:
            # Can't continue (unknown size or array)
            result[fname + '_NOTE'] = 'parsing stopped here'
            break

        p = new_p

    result['_parsed_bytes'] = p - offset
    result['_entry_size'] = end - offset
    return result


def dump_table(game_path, table_name, file_name, field_defs, out_dir):
    """Extract and parse one pabgb table."""
    try:
        import crimson_rs
        dp = 'gamedata/binary__/client/bin'
        body = crimson_rs.extract_file(game_path, '0008', dp, f'{file_name}.pabgb')
        gh = crimson_rs.extract_file(game_path, '0008', dp, f'{file_name}.pabgh')
    except Exception as e:
        return None, str(e)

    D = bytes(body)
    idx = parse_pabgh(bytes(gh))
    if not idx:
        return None, "empty pabgh"

    sorted_offs = sorted(set(idx.values()))
    entries = []

    for key, eoff in sorted(idx.items()):
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry = parse_entry(D, eoff, end, field_defs)
        entry['_key'] = key
        entry['_offset'] = eoff
        entries.append(entry)

    # Save
    # Sanitize values for JSON
    for entry in entries:
        for k in list(entry.keys()):
            v = entry[k]
            if isinstance(v, bytes):
                entry[k] = v.hex()
            elif isinstance(v, (int, float, str, bool, type(None))):
                pass
            else:
                entry[k] = str(v)

    out_path = os.path.join(out_dir, f'{file_name}.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    return entries, None


def main():
    game_path = 'C:/Program Files (x86)/Steam/steamapps/common/Crimson Desert'
    out_dir = os.path.join(os.path.dirname(__file__), 'pabgb_full_dump')
    os.makedirs(out_dir, exist_ok=True)

    schema = load_schema()
    print(f"Loaded schema: {len(schema)} tables")

    # Reverse-sort field definitions by address (they're stored reversed in the schema)
    # Actually they should be in correct order from the error string addresses
    # But the SERIALIZATION order might be reversed — let me check
    # The fields with lowest address = last field read (error strings are sequential)
    # Actually from our FactionNodeInfo test, the order was correct as-is
    # The error strings are in the order they appear in the function

    search_lines = []
    index = {}
    success = 0
    fail = 0

    for table_name, file_name in sorted(TABLE_TO_FILE.items()):
        if table_name not in schema:
            continue

        field_defs = schema[table_name]
        sys.stdout.write(f"\r  {table_name:40s}")
        sys.stdout.flush()

        try:
            entries, err = dump_table(game_path, table_name, file_name, field_defs, out_dir)
        except Exception as e:
            err = str(e)
            entries = None

        if err:
            fail += 1
            continue

        if not entries:
            fail += 1
            continue

        success += 1
        index[table_name] = {
            'file': file_name,
            'entries': len(entries),
            'fields': len(field_defs),
            'sample_keys': [e['_key'] for e in entries[:5]],
        }

        # Build search text (limit huge tables to first 5000 entries)
        for entry in entries[:5000]:
            key = entry.get('_key', '?')
            name = entry.get('_stringKey', str(entry.get('_key', '')))
            for fname, fval in entry.items():
                if fname in ('_key', '_offset', '_parsed_bytes', '_entry_size'):
                    continue
                val_str = str(fval)
                if len(val_str) > 1 and not val_str.startswith('<parse_stopped') and not val_str.startswith('<bad'):
                    search_lines.append(f"{table_name}\t{key}\t{name}\t{fname}\t{val_str}")

    print(f"\n\nDumped {success} tables ({fail} failed)")

    # Save index
    with open(os.path.join(out_dir, 'index.json'), 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)

    # Save search text
    with open(os.path.join(out_dir, 'search.txt'), 'w', encoding='utf-8') as f:
        f.write("TABLE\tKEY\tNAME\tFIELD\tVALUE\n")
        for line in search_lines:
            f.write(line + '\n')

    print(f"Search file: {len(search_lines)} searchable values")
    print(f"Output: {out_dir}/")


if __name__ == '__main__':
    main()
