#!/usr/bin/env python3
"""
Build a complete game relationship map from all PABGB tables + localization.

Extracts: skills, knowledge, quests, missions, items, buffs, stores, drops
Links them via cross-references (key matching, name suffix, payload scanning)
Outputs: game_map.json — a single searchable graph of the entire game.

Usage:
    python tools/build_game_map.py --game "C:/Program Files/Steam/.../Crimson Desert"
    python tools/build_game_map.py  # auto-detect game path
"""

import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from universal_pabgb_parser import parse_from_game, parse_pabgb, _parse_pabgh_index

DEFAULT_GAME = r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert"
DUMP_DIR = r"F:\CDDump"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def load_localization(project_dir):
    """Load English localization from paloc JSON."""
    loc = {}
    for base in [project_dir, os.path.dirname(project_dir)]:
        p = os.path.join(base, "Localization", "paloc_json", "localizationstring_eng.paloc.json")
        if os.path.isfile(p):
            log(f"Loading localization from {p}")
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            for e in data.get("entries", []):
                key = str(e.get("key", ""))
                val = e.get("translation", "") or e.get("original", "")
                if val:
                    loc[key] = val
            log(f"  {len(loc):,} strings loaded")
            return loc

    # Try TSV fallback
    for base in [project_dir, os.getcwd()]:
        p = os.path.join(base, "localizationstring_eng_items.tsv")
        if os.path.isfile(p):
            log(f"Loading localization from TSV: {p}")
            with open(p, "r", encoding="utf-8-sig") as f:
                for line in f:
                    parts = line.strip().split(";", 1)
                    if len(parts) == 2 and parts[0].isdigit():
                        loc[parts[0]] = parts[1]
            log(f"  {len(loc):,} strings loaded")
            return loc

    log("WARNING: No localization file found")
    return loc


def load_knowledge_english(loc):
    """Build knowledge name → English display name from localization patterns."""
    # Pattern: {StaticInfo:Knowledge:Knowledge_XXX#English Name}
    knowledge_eng = {}
    for key, val in loc.items():
        for m in re.finditer(r'Knowledge:Knowledge_(\w+)#([^}"<]+)', val):
            suffix = m.group(1)
            display = m.group(2).strip()
            knowledge_eng[suffix] = display
    return knowledge_eng


def extract_skills(game_dir):
    """Extract all skills with field data."""
    log("Extracting skills...")
    p = parse_from_game(game_dir, "skill", deep=True)
    skills = {}
    for e in p.entries:
        skills[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "skill",
            "size": e.entry_size,
            "strings": e.strings[:3],
        }
    log(f"  {len(skills)} skills")
    return skills


def extract_knowledge(game_dir, loc, knowledge_eng):
    """Extract knowledge with skill links and English names."""
    log("Extracting knowledge...")
    p = parse_from_game(game_dir, "knowledgeinfo")
    knowledge = {}
    for e in p.entries:
        entry = {
            "key": e.key,
            "name": e.name,
            "type": "knowledge",
            "size": e.entry_size,
        }

        # English name from localization
        suffix = e.name.replace("Knowledge_", "")
        eng = knowledge_eng.get(suffix, "")
        if eng:
            entry["english_name"] = eng

        # English from string indices
        if not eng and e.strings:
            for s in e.strings[:3]:
                eng_val = loc.get(s, "")
                if eng_val and len(eng_val) < 80:
                    entry["english_name"] = eng_val
                    break

        # Skill link at payload +0x0E
        if len(e.payload) >= 18:
            skill_key = struct.unpack_from("<I", e.payload, 0x0E)[0]
            if 100 < skill_key < 200000:
                entry["skill_key"] = skill_key

        # Group from name prefix
        for prefix, group in [
            ("Knowledge_Recipe_", "recipe"),
            ("Knowledge_Character_", "character"),
            ("Knowledge_Location_", "location"),
            ("Knowledge_JiJeongTa", "skill_forcepalm"),
            ("Knowledge_CrowWing", "skill_flight"),
            ("Knowledge_Damian_", "skill_damian"),
            ("Knowledge_Oongka_", "skill_oongka"),
        ]:
            if e.name.startswith(prefix):
                entry["category"] = group
                break

        knowledge[e.key] = entry
    log(f"  {len(knowledge)} knowledge entries, {sum(1 for v in knowledge.values() if 'english_name' in v)} with English")
    return knowledge


def extract_quests(game_dir, loc):
    """Extract quests and missions."""
    log("Extracting quests...")
    qi = parse_from_game(game_dir, "questinfo")
    quests = {}
    for e in qi.entries:
        entry = {
            "key": e.key,
            "name": e.name,
            "type": "quest",
            "size": e.entry_size,
        }
        # English name from strings
        if e.strings:
            for s in e.strings[:3]:
                eng = loc.get(s, "")
                if eng and len(eng) < 100:
                    entry["english_name"] = eng
                    break
        quests[e.key] = entry
    log(f"  {len(quests)} quests")

    log("Extracting missions...")
    mi = parse_from_game(game_dir, "missioninfo")
    missions = {}
    for e in mi.entries:
        entry = {
            "key": e.key,
            "name": e.name,
            "type": "mission",
            "size": e.entry_size,
        }
        if e.strings:
            for s in e.strings[:3]:
                eng = loc.get(s, "")
                if eng and len(eng) < 100:
                    entry["english_name"] = eng
                    break
        missions[e.key] = entry
    log(f"  {len(missions)} missions")
    return quests, missions


def extract_buffs(game_dir):
    """Extract buff info."""
    log("Extracting buffs...")
    p = parse_from_game(game_dir, "buffinfo")
    buffs = {}
    for e in p.entries:
        # Parse level count
        r = 0
        key = struct.unpack_from("<I", e.payload, 0)[0] if len(e.payload) >= 4 else 0
        # Level count is after name+null in the raw entry
        raw_entry_data = bytearray(4)  # key already parsed by pabgb parser
        # Use the entry strings for Korean descriptions
        buffs[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "buff",
            "size": e.entry_size,
            "strings": e.strings[:2],
        }
    log(f"  {len(buffs)} buffs")
    return buffs


def extract_items(game_dir):
    """Extract items via crimson_rs (structured parsing)."""
    log("Extracting items via crimson_rs...")
    try:
        import crimson_rs
        content = crimson_rs.extract_file(game_dir, "0008",
                                          "gamedata/binary__/client/bin", "iteminfo.pabgb")
        items_raw = crimson_rs.parse_iteminfo_from_bytes(content)
        items = {}
        for it in items_raw:
            entry = {
                "key": it["key"],
                "name": it.get("string_key", ""),
                "type": "item",
                "item_type": it.get("item_type", 0),
                "category": it.get("category_info", 0),
                "tier": it.get("item_tier", 0),
                "max_stack": it.get("max_stack_count", 1),
            }
            # Buffs and passives
            psl = it.get("equip_passive_skill_list", [])
            if psl:
                entry["passive_skills"] = psl
            edl = it.get("enchant_data_list", [])
            if edl and edl[0].get("equip_buffs"):
                entry["equip_buffs"] = edl[0]["equip_buffs"]
            # Knowledge link
            ki = it.get("knowledge_info", 0)
            if ki and ki > 0:
                entry["knowledge_key"] = ki
            items[it["key"]] = entry
        log(f"  {len(items)} items")
        return items
    except Exception as e:
        log(f"  ERROR: {e}")
        return {}


def extract_stores(game_dir):
    """Extract store info."""
    log("Extracting stores...")
    p = parse_from_game(game_dir, "storeinfo")
    stores = {}
    for e in p.entries:
        stores[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "store",
            "size": e.entry_size,
        }
    log(f"  {len(stores)} stores")
    return stores


def extract_knowledge_groups(game_dir):
    """Extract knowledge group hierarchy."""
    log("Extracting knowledge groups...")
    p = parse_from_game(game_dir, "knowledgegroupinfo")
    groups = {}
    for e in p.entries:
        groups[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "knowledge_group",
            "size": e.entry_size,
        }
    log(f"  {len(groups)} knowledge groups")
    return groups


def extract_characters(game_dir):
    """Extract NPC/character info (summary only — full table is 22MB)."""
    log("Extracting characters (summary)...")
    p = parse_from_game(game_dir, "npcinfo")
    npcs = {}
    for e in p.entries:
        npcs[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "npc",
        }
    log(f"  {len(npcs)} NPCs")
    return npcs


def scan_icon_paths(dump_dir):
    """Scan CDDump for icon file paths."""
    icons = {}
    icon_dir = os.path.join(dump_dir, "ui")
    if not os.path.isdir(icon_dir):
        log(f"  No icon dir at {icon_dir}")
        return icons
    log(f"Scanning icons from {icon_dir}...")
    for fname in os.listdir(icon_dir):
        if fname.endswith(".mp4"):
            # Skill preview videos: skill_jijeongta_i.mp4
            base = fname.replace(".mp4", "")
            icons[base] = os.path.join("ui", fname)
    log(f"  {len(icons)} icon/video paths")
    return icons


def extract_character_groups(game_dir):
    """Extract character group info."""
    log("Extracting character groups...")
    p = parse_from_game(game_dir, "charactergroupinfo")
    groups = {}
    for e in p.entries:
        groups[e.key] = {
            "key": e.key,
            "name": e.name,
            "type": "char_group",
        }
    log(f"  {len(groups)} character groups")
    return groups


def build_links(game_dir, skills, knowledge, quests, missions, buffs, items, stores=None):
    """Build cross-reference links between all entities."""
    log("Building cross-reference links...")
    links = []

    knowledge_keys = set(knowledge.keys())
    skill_keys = set(skills.keys())
    quest_keys = set(quests.keys())
    mission_keys = set(missions.keys())

    # Knowledge → Skill (confirmed: skill key at payload +0x0E)
    for kk, kv in knowledge.items():
        sk = kv.get("skill_key")
        if sk and sk in skills:
            links.append({
                "from": f"knowledge:{kk}",
                "to": f"skill:{sk}",
                "type": "unlocks_skill",
            })

    # Item → Buff (equip_buffs)
    for ik, iv in items.items():
        for b in iv.get("equip_buffs", []):
            bk = b.get("buff", 0)
            if bk in buffs:
                links.append({
                    "from": f"item:{ik}",
                    "to": f"buff:{bk}",
                    "type": "applies_buff",
                    "level": b.get("level", 0),
                })

    # Item → Skill (passive skills)
    for ik, iv in items.items():
        for ps in iv.get("passive_skills", []):
            sk = ps.get("skill", 0)
            if sk in skills:
                links.append({
                    "from": f"item:{ik}",
                    "to": f"skill:{sk}",
                    "type": "grants_passive",
                    "level": ps.get("level", 0),
                })

    # Item → Knowledge (items that teach knowledge)
    for ik, iv in items.items():
        kk = iv.get("knowledge_key", 0)
        if kk and kk in knowledge_keys:
            links.append({
                "from": f"item:{ik}",
                "to": f"knowledge:{kk}",
                "type": "teaches_knowledge",
            })

    # Quest → Knowledge (scan quest payloads for knowledge keys)
    log("  Scanning quest→knowledge links...")
    qi = parse_from_game(game_dir, "questinfo")
    for qe in qi.entries:
        found = set()
        for off in range(0, min(len(qe.payload) - 3, 400), 4):
            v = struct.unpack_from("<I", qe.payload, off)[0]
            if v in knowledge_keys and v > 100 and v not in found:
                found.add(v)
                links.append({
                    "from": f"quest:{qe.key}",
                    "to": f"knowledge:{v}",
                    "type": "involves_knowledge",
                })

    # Mission → Knowledge (scan mission payloads)
    log("  Scanning mission→knowledge links...")
    mi = parse_from_game(game_dir, "missioninfo")
    for me in mi.entries:
        found = set()
        for off in range(0, min(len(me.payload) - 3, 200), 4):
            v = struct.unpack_from("<I", me.payload, off)[0]
            if v in knowledge_keys and v > 100 and v not in found:
                found.add(v)
                links.append({
                    "from": f"mission:{me.key}",
                    "to": f"knowledge:{v}",
                    "type": "involves_knowledge",
                })

    # Quest → Mission (scan quest payloads for mission keys)
    log("  Scanning quest→mission links...")
    for qe in qi.entries:
        found = set()
        for off in range(0, min(len(qe.payload) - 3, 400), 4):
            v = struct.unpack_from("<I", qe.payload, off)[0]
            if v in mission_keys and v > 100 and v not in found:
                found.add(v)
                links.append({
                    "from": f"quest:{qe.key}",
                    "to": f"mission:{v}",
                    "type": "has_mission",
                })

    # Knowledge Group → Knowledge (scan group payloads)
    log("  Scanning knowledge group→knowledge links...")
    kg = parse_from_game(game_dir, "knowledgegroupinfo")
    for ge in kg.entries:
        found = set()
        for off in range(0, min(len(ge.payload) - 3, 500), 4):
            v = struct.unpack_from("<I", ge.payload, off)[0]
            if v in knowledge_keys and v > 100 and v not in found:
                found.add(v)
                links.append({
                    "from": f"knowledge_group:{ge.key}",
                    "to": f"knowledge:{v}",
                    "type": "contains_knowledge",
                })

    # Skill Tree → Skill
    log("  Scanning skill tree→skill links...")
    st = parse_from_game(game_dir, "skilltreeinfo")
    for se in st.entries:
        found = set()
        for off in range(0, min(len(se.payload) - 3, 5000), 4):
            v = struct.unpack_from("<I", se.payload, off)[0]
            if v in skill_keys and v > 100 and v not in found:
                found.add(v)
                links.append({
                    "from": f"skill_tree:{se.key}",
                    "to": f"skill:{v}",
                    "type": "skill_tree_contains",
                })

    # Store → Item (scan store payloads for item keys)
    log("  Scanning store→item links...")
    si = parse_from_game(game_dir, "storeinfo")
    item_keys = set(items.keys())
    for se in si.entries:
        found = set()
        for off in range(0, min(len(se.payload) - 3, 5000), 4):
            v = struct.unpack_from("<I", se.payload, off)[0]
            if v in item_keys and v > 1000 and v not in found:
                found.add(v)
                links.append({
                    "from": f"store:{se.key}",
                    "to": f"item:{v}",
                    "type": "sells_item",
                })

    # NPC → Store
    log("  Scanning npc→store links...")
    npc_p = parse_from_game(game_dir, "npcinfo")
    store_keys = set(stores.keys()) if stores else set()
    for ne in npc_p.entries:
        found = set()
        for off in range(0, min(len(ne.payload) - 3, 300), 4):
            v = struct.unpack_from("<I", ne.payload, off)[0]
            if v in store_keys and v not in found:
                found.add(v)
                links.append({"from": f"npc:{ne.key}", "to": f"store:{v}", "type": "runs_store"})

    # Character Group → Character (characterinfo is 22MB — use key set from extract)
    log("  Scanning chargroup→character links...")
    cg_p = parse_from_game(game_dir, "charactergroupinfo")
    # Don't re-parse characterinfo — too large. Use name-based key lookup instead.
    char_keys = set()
    try:
        _ci_p = parse_from_game(game_dir, "characterinfo")
        char_keys = {e.key for e in _ci_p.entries}
        del _ci_p  # free memory
    except Exception:
        pass
    for ge in cg_p.entries:
        found = set()
        for off in range(0, min(len(ge.payload) - 3, 1000), 4):
            v = struct.unpack_from("<I", ge.payload, off)[0]
            if v in char_keys and v > 100 and v not in found:
                found.add(v)
                links.append({"from": f"char_group:{ge.key}", "to": f"character:{v}", "type": "contains_character"})

    # Drop Set → Knowledge
    log("  Scanning dropset→knowledge links...")
    ds_p = parse_from_game(game_dir, "dropsetinfo")
    for de in ds_p.entries:
        found = set()
        for off in range(0, min(len(de.payload) - 3, 200), 4):
            v = struct.unpack_from("<I", de.payload, off)[0]
            if v in knowledge_keys and v > 100 and v not in found:
                found.add(v)
                links.append({"from": f"dropset:{de.key}", "to": f"knowledge:{v}", "type": "drops_knowledge"})

    # Skill Group → Skill
    log("  Scanning skillgroup→skill links...")
    sg_p = parse_from_game(game_dir, "skillgroupinfo")
    for ge in sg_p.entries:
        found = set()
        for off in range(0, min(len(ge.payload) - 3, 500), 4):
            v = struct.unpack_from("<I", ge.payload, off)[0]
            if v in skill_keys and v > 100 and v not in found:
                found.add(v)
                links.append({"from": f"skill_group:{ge.key}", "to": f"skill:{v}", "type": "group_contains_skill"})

    # Faction Spawn → Character Group
    log("  Scanning faction spawn→chargroup links...")
    fs_p = parse_from_game(game_dir, "factionspawndatainfo")
    cg_keys = {e.key for e in cg_p.entries}
    for fe in fs_p.entries:
        found = set()
        for off in range(0, min(len(fe.payload) - 3, 300), 4):
            v = struct.unpack_from("<I", fe.payload, off)[0]
            if v in cg_keys and v > 100 and v not in found:
                found.add(v)
                links.append({"from": f"faction_spawn:{fe.key}", "to": f"char_group:{v}", "type": "spawns_group"})

    # Tribe → Character Group
    log("  Scanning tribe→chargroup links...")
    tribe_p = parse_from_game(game_dir, "tribeinfo")
    for te in tribe_p.entries:
        found = set()
        for off in range(0, min(len(te.payload) - 3, 300), 4):
            v = struct.unpack_from("<I", te.payload, off)[0]
            if v in cg_keys and v > 100 and v not in found:
                found.add(v)
                links.append({"from": f"tribe:{te.key}", "to": f"char_group:{v}", "type": "tribe_contains"})

    log(f"  {len(links)} links built")
    return links


def build_game_map(game_dir, project_dir, dump_dir=None):
    """Build the complete game map."""
    t0 = time.time()
    log("Building game map...")

    loc = load_localization(project_dir)
    knowledge_eng = load_knowledge_english(loc)

    skills = extract_skills(game_dir)
    knowledge = extract_knowledge(game_dir, loc, knowledge_eng)
    quests, missions = extract_quests(game_dir, loc)
    buffs = extract_buffs(game_dir)
    items = extract_items(game_dir)
    stores = extract_stores(game_dir)
    groups = extract_knowledge_groups(game_dir)
    npcs = extract_characters(game_dir)

    char_groups = extract_character_groups(game_dir)

    # Characters (from characterinfo — 6915 entries, summary only)
    log("Extracting characters...")
    _ci = parse_from_game(game_dir, "characterinfo")
    characters = {}
    for e in _ci.entries:
        characters[e.key] = {"key": e.key, "name": e.name, "type": "character"}
    log(f"  {len(characters)} characters")

    # Drop sets
    log("Extracting drop sets...")
    _ds = parse_from_game(game_dir, "dropsetinfo")
    drop_sets = {}
    for e in _ds.entries:
        drop_sets[e.key] = {"key": e.key, "name": e.name, "type": "dropset"}
    log(f"  {len(drop_sets)} drop sets")

    # Skill groups
    log("Extracting skill groups...")
    _sg = parse_from_game(game_dir, "skillgroupinfo")
    skill_groups = {}
    for e in _sg.entries:
        skill_groups[e.key] = {"key": e.key, "name": e.name, "type": "skill_group"}
    log(f"  {len(skill_groups)} skill groups")

    # Tribes
    log("Extracting tribes...")
    _tr = parse_from_game(game_dir, "tribeinfo")
    tribes = {}
    for e in _tr.entries:
        tribes[e.key] = {"key": e.key, "name": e.name, "type": "tribe"}
    log(f"  {len(tribes)} tribes")

    # Factions
    log("Extracting factions...")
    _fc = parse_from_game(game_dir, "faction")
    factions = {}
    for e in _fc.entries:
        factions[e.key] = {"key": e.key, "name": e.name, "type": "faction"}
    log(f"  {len(factions)} factions")

    # Regions
    log("Extracting regions...")
    _rg = parse_from_game(game_dir, "regioninfo")
    regions = {}
    for e in _rg.entries:
        regions[e.key] = {"key": e.key, "name": e.name, "type": "region"}
    log(f"  {len(regions)} regions")

    # Skill trees
    log("Extracting skill trees...")
    _st = parse_from_game(game_dir, "skilltreeinfo")
    skill_trees = {}
    for e in _st.entries:
        skill_trees[e.key] = {"key": e.key, "name": e.name, "type": "skill_tree"}
    log(f"  {len(skill_trees)} skill trees")

    icons = {}
    if dump_dir and os.path.isdir(dump_dir):
        icons = scan_icon_paths(dump_dir)

    # Apply English names from knowledge to skills
    for kk, kv in knowledge.items():
        sk = kv.get("skill_key")
        eng = kv.get("english_name", "")
        if sk and sk in skills and eng:
            skills[sk]["english_name"] = eng

    links = build_links(game_dir, skills, knowledge, quests, missions, buffs, items, stores)

    game_map = {
        "version": 1,
        "build_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "counts": {
            "skills": len(skills),
            "knowledge": len(knowledge),
            "quests": len(quests),
            "missions": len(missions),
            "buffs": len(buffs),
            "items": len(items),
            "stores": len(stores),
            "knowledge_groups": len(groups),
            "npcs": len(npcs),
            "char_groups": len(char_groups),
            "skill_trees": len(skill_trees),
            "characters": len(characters),
            "drop_sets": len(drop_sets),
            "skill_groups": len(skill_groups),
            "tribes": len(tribes),
            "factions": len(factions),
            "regions": len(regions),
            "links": len(links),
        },
        "skills": skills,
        "knowledge": knowledge,
        "quests": quests,
        "missions": missions,
        "buffs": buffs,
        "items": items,
        "stores": stores,
        "knowledge_groups": groups,
        "npcs": npcs,
        "char_groups": char_groups,
        "skill_trees": skill_trees,
        "characters": characters,
        "drop_sets": drop_sets,
        "skill_groups": skill_groups,
        "tribes": tribes,
        "factions": factions,
        "regions": regions,
        "links": links,
        "icons": icons,
    }

    elapsed = time.time() - t0
    total = sum(game_map["counts"].values())
    log(f"Game map built: {total:,} entities, {len(links):,} links in {elapsed:.1f}s")
    return game_map


def main():
    import argparse
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="Build Crimson Desert game relationship map")
    ap.add_argument("--game", default=DEFAULT_GAME, help="Game install directory")
    ap.add_argument("--dump", default=DUMP_DIR, help="CDDump directory for icons")
    ap.add_argument("-o", "--output", default="game_map.json", help="Output file")
    args = ap.parse_args()

    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    game_map = build_game_map(args.game, project_dir, args.dump)

    log(f"Writing {args.output}...")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(game_map, f, ensure_ascii=False, separators=(",", ":"))
    size = os.path.getsize(args.output)
    log(f"Done: {args.output} ({size:,} bytes)")

    # Also pretty-print a summary
    print("\n=== Game Map Summary ===")
    for k, v in game_map["counts"].items():
        print(f"  {k}: {v:,}")


if __name__ == "__main__":
    main()
