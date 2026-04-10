# Crimson Desert Modding Tools

Community modding tools for Crimson Desert game data. Standalone Python parsers for PABGB game data files and PAZ archive tools.

**No game files included.** You need extracted game data from the PAZ archives (group `0008`).

## Requirements

- Python 3.10+
- `lz4` (for PAZ tools): `pip install lz4`
- `cryptography` (for PAZ tools): `pip install cryptography`

## Setup

1. Extract game data using the PAZ tools or set the `EXTRACTED_PAZ` environment variable:
   ```bash
   export EXTRACTED_PAZ=/path/to/extracted/0008_full
   ```
2. Or pass paths directly when calling parsers.

## Directory Structure

```
parsers/                    # PABGB table parsers
  universal_pabgb_dumper.py # Dumps ALL pabgb tables to JSON (~70% field coverage)
  universal_pabgb_parser.py # CLI parser for any pabgb/pabgh pair
  pabgb_field_parsers.py    # Shared field decoder library
  pabgb_schema_dumper.py    # Extract schemas from IDA Pro MCP
  build_game_map.py         # Build cross-reference map of all game data
  regioninfo_parser.py      # Region zones, town flags, dismount flags
  characterinfo_parser.py   # Character spawn data (anchor-based)
  characterinfo_mount_parser.py  # Mount ride duration, cooldown, vehicle type
  characterinfo_spawn_parser.py  # Spawn count fields (sequential)
  fieldinfo_parser.py       # Field zone vehicle/mount flags
  vehicleinfo_parser.py     # Vehicle call types, altitude caps
  storeinfo_parser.py       # Store/vendor item lists
  iteminfo_parser.py        # All 5993 items with full field preservation
  questinfo_parser.py       # Quest -> stage -> mission links
  quest_deep_parser.py      # Quest state from save data (library)
  stageinfo_parser.py       # Stage completion, force-spawn flags (82 fields)
  factionnode_info_parser.py     # Faction node schedules (82 fields)
  factionnode_operator_parser.py # Faction operator max counts
  factionnode_parser.py     # Faction node entries
  factionspawn_parser.py    # Enemy/NPC spawn definitions
  terrain_spawn_parser.py   # Terrain region spawn density

paz_tools/                  # PAZ archive tools
  paz_parse.py              # PAMT index parser
  paz_unpack.py             # PAZ archive extractor (decrypt + decompress)
  paz_repack.py             # PAZ asset repacker
  paz_crypto.py             # ChaCha20 + LZ4 crypto library

schemas/                    # Game data schemas
  pabgb_complete_schema.json      # 434 tables, 3708 fields
  pabgb_all_schemas.json          # Alternative schema format
  pabgb_full_schema_with_readers.json  # Schema with IDA reader function refs
```

## Quick Start

### Extract game files from PAZ
```bash
cd paz_tools
python paz_unpack.py /path/to/game/0008/0.pamt --paz-dir /path/to/game/0008 -o ../extracted/0008_full
```

### Dump all PABGB tables to JSON
```bash
cd parsers
python universal_pabgb_dumper.py
# Outputs: pabgb_full_dump/<table>.json for each table
```

### Parse a specific table
```bash
# Region info (towns, dismount flags)
python regioninfo_parser.py

# Mount durations and cooldowns
python characterinfo_mount_parser.py

# Store/vendor items
python storeinfo_parser.py

# Item database (5993 items)
python iteminfo_parser.py
```

### Parse any PABGB table generically
```bash
python universal_pabgb_parser.py --pabgb /path/to/regioninfo.pabgb --pabgh /path/to/regioninfo.pabgh
```

## PABGB Format Overview

PABGB (Pearl Abyss Binary Game Binary) files store game data tables:

- **`.pabgh`** = index file: entry count + key-to-offset mapping
- **`.pabgb`** = data file: sequential binary records
- Fields are read in order defined by the game's reader function (decompiled from IDA)
- Field types: u8, u16, u32, u64, float, CString (u32 len + bytes), LocStr, arrays

### Schema

`pabgb_complete_schema.json` contains field definitions for all 434 tables extracted from IDA Pro decompilation of the game binary. Each field has:
- `f`: field name (from Korean error strings)
- `stream`: bytes consumed from binary stream
- `type`: field type (direct_u8, CString, array, etc.)
- `r`: reader function address in game binary

## PAZ Archive Format

PAZ archives use ChaCha20-Poly1305 encryption with per-file keys derived from filename hashes, plus LZ4 compression. The `paz_tools/` directory provides complete extraction and repacking capabilities.

## Credits

- NattKh — Primary reverse engineering, parsers, save editor
- Potter (lukerz) — crimson-rs PAZ toolkit, pycrimson schema extraction
- Community contributors

## License

MIT. These tools are for educational and modding purposes.
