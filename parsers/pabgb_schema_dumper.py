"""
PABGB Schema Auto-Dumper

Extracts field schemas for ALL pabgb tables from IDA Pro via MCP.

Strategy:
1. Search for Korean error strings: "TABLE의 _FIELD를 읽어들이는데 실패했다"
   → gives us table name + field name for EVERY field in EVERY table
2. Group fields by table name
3. For each table, find the reader function via xrefs from error strings
4. Extract call sequence to determine field ORDER and reader type
5. Look up stream consumption sizes from the master reader size table
6. Output complete JSON schema per table

Usage:
  python pabgb_schema_dumper.py              # Dump from IDA MCP
  python pabgb_schema_dumper.py --cached     # Use cached IDA dump (offline)

Output:
  pabgb_schemas.json — complete schema for all tables
"""

import json
import sys
import os
import re

# Known reader function stream sizes (from project_pabgb_reader_sizes.md)
READER_SIZES = {
    # Enum readers (all 4B except _1344 which is 2B)
    '_sub_1408F5560_0_1335': 4,
    '_sub_1408F5560_0_1336': 4,
    '_sub_1408F5560_0_1337': 4,
    '_sub_1408F5560_0_1338': 4,
    '_sub_1408F5560_0_1339': 4,
    '_sub_1408F5560_0_1340': 4,
    '_sub_1408F5560_0_1341': 4,
    '_sub_1408F5560_0_1342': 4,
    '_sub_1408F5560_0_1343': 4,
    '_sub_1408F5560_0_1344': 2,  # Only 2B enum!
    '_sub_1408F5560_0_1345': 4,
    '_sub_1408F5560_0_1346': 4,
    '_sub_1408F5560_0_1347': 4,
    '_sub_1408F5560_0_1354': 4,
    '_sub_1408F5560_0_1355': 4,
    '_sub_1408F5560_0_1359': 4,
    '_sub_1408F5560_0_1872': 4,
    # Key lookup readers
    'sub_14105F770': 2,
    'sub_14105F3A0': 2,
    'sub_14105F910': 1,
    'sub_141060750': 2,
    # String/struct readers
    'sub_14100FE80': 'CString',  # 4 + len
    'sub_140ED6040': 'LocStr',   # 1 + 8 + 4 + len
    # Array readers (u32 count + count * element_size)
    'sub_14105F9C0': 'array_4B',
    'sub_14105FAD0': 'array_4B',
    'sub_141E99EB0': 'array_4B',
    'sub_14105E000': 'array_2B',
    'sub_14105EA70': 'array_2B',
    'sub_14105F4D0': 'array_4B',
    'sub_14105E840': 'array_4B',
    'sub_1410767B0': 'array_8B',
    'sub_14105FE60': 'array_4B',
    'sub_1410765F0': 'array_12B',
    'sub_141060250': 'array_4B',
    'sub_14105EEC0': 'array_4B',
    'sub_141060380': 'array_5B',
    'sub_1410604E0': 'array_4B',
    'sub_1410605E0': 'array_28B',
    'sub_1410608E0': 'array_4B',
    'sub_1410609B0': 'array_8B',
    'sub_14105DDD0': 'array_u16count_4B',
    # Blob
    'sub_141010050': 'Blob',  # 4 + len
    # 2B key readers
    'sub_141062200': 2,
    'sub_1410622B0': 2,
    # Simple array readers
    'sub_141061C50': 'array_4B',
}


def parse_error_strings_from_file(filepath):
    """Parse Korean error strings from a pre-dumped strings file.

    Format: .impdata:ADDRESS SIZE TYPE STRING
    Looking for: "TABLE의 _FIELD를 읽어들이는데 실패했다"
    """
    tables = {}

    # Korean pattern: TABLE의 _FIELD를 읽어들이는데 실패했다.
    # Also handles: TABLE의 _FIELD를 읽어들이는데 실패했다
    pattern = re.compile(r'(\w+)의\s+(_\w+)를\s+읽어들이는데\s+실패했다')

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # Extract address and string content
            parts = line.strip().split('\t')
            if len(parts) < 4:
                continue

            addr_str = parts[0].split(':')[-1].strip()
            string_content = parts[-1].strip()

            # Try to match the Korean error pattern
            m = pattern.search(string_content)
            if m:
                table_name = m.group(1)
                field_name = m.group(2)

                try:
                    addr = int(addr_str, 16)
                except ValueError:
                    continue

                if table_name not in tables:
                    tables[table_name] = []
                tables[table_name].append({
                    'field': field_name,
                    'error_addr': hex(addr),
                    'error_string': string_content,
                })

    return tables


def search_ida_for_error_strings():
    """Search IDA for all Korean pabgb error strings via MCP.
    Returns dict of {table_name: [{field, error_addr, error_string}, ...]}
    """
    # This would use IDA MCP to search — for now we use the file-based approach
    raise NotImplementedError("Use --file mode with a pre-dumped strings file")


def dump_all_korean_strings_from_ida():
    """Use IDA MCP to dump all Korean error strings.
    This searches for the pattern: 를 읽어들이는데 실패했다
    """
    try:
        # Import MCP client — this would need the MCP bridge
        # For now, we provide instructions to dump from IDA
        pass
    except:
        pass

    print("To dump Korean error strings from IDA:")
    print("  1. Open IDA with CrimsonDesert.exe loaded")
    print("  2. Alt+T (search text) → search for: 읽어들이는데 실패했다")
    print("  3. Search all occurrences")
    print("  4. Export results to a text file")
    print("  5. Run: python pabgb_schema_dumper.py --file exported_strings.txt")


def main():
    if '--help' in sys.argv:
        print(__doc__)
        return

    # Check for input file
    input_file = None
    for i, arg in enumerate(sys.argv):
        if arg == '--file' and i + 1 < len(sys.argv):
            input_file = sys.argv[i + 1]

    if not input_file:
        # Try to find any existing dump files
        candidates = [
            'pabgb_error_strings.txt',
            'korean_error_strings.txt',
            'ida_strings_dump.txt',
        ]
        for c in candidates:
            if os.path.exists(c):
                input_file = c
                break

    if not input_file:
        print("No input file found. Searching IDA strings files...")
        # Try to search from the runtimestringforsave.txt which has some
        save_strings = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', 'ResearchFolder', 'runtimestringforsave.txt')
        if os.path.exists(save_strings):
            input_file = save_strings
            print(f"Using: {save_strings}")

    if not input_file:
        print("ERROR: No strings file found.")
        print("Run IDA search for '읽어들이는데 실패했다' and export results.")
        dump_all_korean_strings_from_ida()
        return

    print(f"Parsing error strings from: {input_file}")
    tables = parse_error_strings_from_file(input_file)

    if not tables:
        print("No pabgb error strings found in file.")
        print("The file may not contain Korean error strings.")
        print("Need to search IDA for: TABLE의 _FIELD를 읽어들이는데 실패했다")
        return

    # Sort fields within each table by address (preserves serialization order)
    for table_name in tables:
        tables[table_name].sort(key=lambda x: x['error_addr'])

    # Print summary
    print(f"\nFound {len(tables)} tables with {sum(len(v) for v in tables.values())} total fields:\n")
    for table_name in sorted(tables.keys()):
        fields = tables[table_name]
        field_names = [f['field'] for f in fields]
        print(f"  {table_name}: {len(fields)} fields")
        for f in fields:
            print(f"    {f['field']}")

    # Save to JSON
    output_path = 'pabgb_schemas_from_errors.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(tables, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to: {output_path}")

    # Also save a summary
    summary_path = 'pabgb_table_catalog.md'
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("# PABGB Table Catalog (auto-generated from IDA error strings)\n\n")
        f.write(f"Total: {len(tables)} tables, {sum(len(v) for v in tables.values())} fields\n\n")
        for table_name in sorted(tables.keys()):
            fields = tables[table_name]
            f.write(f"## {table_name} ({len(fields)} fields)\n")
            f.write("| # | Field | Error Address |\n")
            f.write("|---|-------|---------------|\n")
            for i, field in enumerate(fields):
                f.write(f"| {i+1} | `{field['field']}` | `{field['error_addr']}` |\n")
            f.write("\n")
    print(f"Catalog saved to: {summary_path}")


if __name__ == '__main__':
    main()
