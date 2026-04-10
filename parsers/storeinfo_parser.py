"""
Storeinfo Parser — Full binary parser for Crimson Desert storeinfo.pabgb/pabgh.

Properly decodes the PABGB store record format:
  Store Record = u16(store_key) + CString(name) + FixedHeader(51B) + Items(N*105B) + Tail(17B)
  Total overhead = 68 bytes (51 header + 17 tail)

FixedHeader (51 bytes after name):
  +0x00: u8(0)          null/flag
  +0x01: u32             field_a (usually 1)
  +0x05: u32             field_b (usually 1)
  +0x09: u32             field_c (usually 1)
  +0x0D: u64             field_d (usually 0, sometimes a timestamp)
  +0x15: u32             field_e (usually 0)
  +0x19: u8              field_f (usually 0)
  +0x1A: u8              format_tag_a (0x1D for standard stores)
  +0x1B: u8              format_tag_b (0xFD for standard stores)
  +0x1C: u32             sentinel_a (0xFFFFFFFF or variant)
  +0x20: u32             sentinel_b (0xFFFFFFFF or variant)
  +0x24: u16             sentinel_c (usually 0xFFFF or 0x0000 or 0x0700)
  +0x26: u32             item_count
  +0x2A: u32             field_g (usually 0)
  +0x2E: u8              field_h (usually 1)
  +0x2F: u32             item_count_2 (MUST match item_count!)

Item Entry (105 bytes):
  +0x00: u16             store_key_ref (copy of parent store key)
  +0x02: u64             buy_price
  +0x0A: u64             sell_price
  +0x12: u32             trade_flags (varies)
  +0x16: u32             field_1
  +0x1A: u32             field_2
  +0x1E: u8              pre_marker_a
  +0x1F: u8              pre_marker_b
  +0x20: u16             marker (always 0x0101)
  +0x22: u32             item_key
  +0x26: bytes[30]       item_data_1
  +0x44: u32             extra_field
  +0x48: bytes[28]       item_data_2
  +0x5B: u16             separator (usually 0xFFFF)
  +0x5D: u32             item_key_dup (same as item_key)
  +0x61: bytes[8]        item_tail

Tail (17 bytes):
  +0x00: u32             tail_field_a (usually 0)
  +0x04: u32             version_field (usually 2)
  +0x08: u32             tail_hash (e.g. 0x3E3D)
  +0x0C: u32             tail_field_b (usually 0)
  +0x10: u8              tail_flag (usually 1)

Format types at +0x1A/+0x1B from after_name:
  1D FD: Standard format (148 stores) — 68 + N*105 formula
  00 00: Special format (42 stores) — Camp, Church, Bank, Contribution
  40 42: BlackMarket format (13 stores)
  40 0D: StreetVendor format (8 stores)
  66 FC: Fishing format (17 stores)
  C6 FC: Leather format
  60 E3: Special high-tier stores
  80 4F: Salt BlackMarket
"""

import json
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

ITEM_ENTRY_SIZE = 105
HEADER_OVERHEAD = 51  # bytes from after_name to item data
TAIL_SIZE = 17
TOTAL_OVERHEAD = HEADER_OVERHEAD + TAIL_SIZE  # 68


@dataclass
class StoreItemEntry:
    """A parsed item entry within a store (105 bytes)."""
    offset: int            # absolute offset in body data (of the entry start, NOT the 0101 marker)
    store_key_ref: int     # u16 — copy of parent store key
    buy_price: int         # u64
    sell_price: int        # u64
    trade_flags: int       # u32
    item_key: int          # u32 (at +0x22, after 0101 marker)
    item_key_dup: int      # u32 (at +0x66, duplicate)
    extra_field: int       # u32 at +0x44
    raw: bytes             # full 105-byte entry for cloning


@dataclass
class StoreRecord:
    """A parsed store record from storeinfo.pabgb."""
    index: int             # index in header
    key: int               # store key (u16)
    name: str              # store name
    offset: int            # absolute offset in body data
    size: int              # total record size
    name_offset: int       # offset of name in body
    after_name: int        # first byte after name
    format_tag: int        # u16 at +0x1A from after_name (identifies format type)
    is_standard: bool      # True if 68+N*105 formula works
    item_count: int        # item count from +0x26
    items: List[StoreItemEntry] = field(default_factory=list)
    # Header fields for round-trip
    header_raw: bytes = b''   # 51 bytes from after_name to item data
    tail_raw: bytes = b''     # 17 bytes after item data


class StoreinfoParser:
    """Full parser for storeinfo.pabgb + pabgh."""

    def __init__(self):
        self.stores: List[StoreRecord] = []
        self._header_data: bytes = b''
        self._body_data: bytearray = bytearray()
        self._header_entries: List[Tuple[int, int]] = []  # (key, offset)
        self._name_lookup: Dict[int, str] = {}
        self._loaded = False

    def load_from_files(self, pabgh_path: str, pabgb_path: str) -> bool:
        """Load from extracted .pabgh and .pabgb files."""
        try:
            with open(pabgh_path, 'rb') as f:
                self._header_data = f.read()
            with open(pabgb_path, 'rb') as f:
                self._body_data = bytearray(f.read())
            self._parse_header()
            self._parse_all_stores()
            self._loaded = True
            return True
        except Exception as e:
            log.error("Failed to load storeinfo: %s", e)
            return False

    def load_from_bytes(self, header_bytes: bytes, body_bytes: bytes) -> bool:
        """Load from raw bytes (for PAZ extraction)."""
        self._header_data = header_bytes
        self._body_data = bytearray(body_bytes)
        self._parse_header()
        self._parse_all_stores()
        self._loaded = True
        return True

    def load_names(self, names_path: str = '') -> None:
        """Load item name database."""
        if not names_path:
            names_path = os.path.join(os.path.dirname(__file__), 'item_names.json')
        if os.path.isfile(names_path):
            with open(names_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for it in data.get('items', []):
                self._name_lookup[it['itemKey']] = it['name']

    def get_item_name(self, key: int) -> str:
        return self._name_lookup.get(key, f"Unknown({key})")

    def _parse_header(self) -> None:
        """Parse pabgh header: u16(count) + N * (u16 key, u32 offset)."""
        count = struct.unpack_from('<H', self._header_data, 0)[0]
        self._header_entries = []
        for i in range(count):
            base = 2 + i * 6
            key = struct.unpack_from('<H', self._header_data, base)[0]
            off = struct.unpack_from('<I', self._header_data, base + 2)[0]
            self._header_entries.append((key, off))

    def _parse_all_stores(self) -> None:
        """Parse all store records from body data."""
        self.stores.clear()
        data = self._body_data
        n = len(self._header_entries)

        for idx, (skey, soff) in enumerate(self._header_entries):
            if idx + 1 < n:
                rec_size = self._header_entries[idx + 1][1] - soff
            else:
                rec_size = len(data) - soff

            # Parse name
            name_len = struct.unpack_from('<I', data, soff + 2)[0]
            name = data[soff + 6:soff + 6 + name_len].decode('ascii', errors='replace')
            after_name = soff + 6 + name_len
            remaining = rec_size - 6 - name_len

            # Read format tag
            fmt_tag = 0
            if after_name + 0x1C <= len(data):
                fmt_tag = struct.unpack_from('<H', data, after_name + 0x1A)[0]

            # Check if standard format
            item_count = 0
            is_standard = False
            if after_name + 0x30 <= len(data):
                cnt = struct.unpack_from('<I', data, after_name + 0x26)[0]
                expected = TOTAL_OVERHEAD + cnt * ITEM_ENTRY_SIZE
                if expected == remaining and cnt < 10000:
                    is_standard = True
                    item_count = cnt

            store = StoreRecord(
                index=idx,
                key=skey,
                name=name,
                offset=soff,
                size=rec_size,
                name_offset=soff + 2,
                after_name=after_name,
                format_tag=fmt_tag,
                is_standard=is_standard,
                item_count=item_count,
            )

            if is_standard:
                # Extract header and tail
                store.header_raw = bytes(data[after_name:after_name + HEADER_OVERHEAD])
                items_end = after_name + HEADER_OVERHEAD + item_count * ITEM_ENTRY_SIZE
                store.tail_raw = bytes(data[items_end:items_end + TAIL_SIZE])

                # Parse items
                for i in range(item_count):
                    entry_off = after_name + HEADER_OVERHEAD + i * ITEM_ENTRY_SIZE
                    raw = bytes(data[entry_off:entry_off + ITEM_ENTRY_SIZE])
                    if len(raw) < ITEM_ENTRY_SIZE:
                        break

                    store_key_ref = struct.unpack_from('<H', raw, 0)[0]
                    buy_price = struct.unpack_from('<Q', raw, 2)[0]
                    sell_price = struct.unpack_from('<Q', raw, 0x0A)[0]
                    trade_flags = struct.unpack_from('<I', raw, 0x12)[0]
                    item_key = struct.unpack_from('<I', raw, 0x22)[0]
                    item_key_dup = struct.unpack_from('<I', raw, 0x5D)[0]
                    extra_field = struct.unpack_from('<I', raw, 0x36)[0]

                    store.items.append(StoreItemEntry(
                        offset=entry_off,
                        store_key_ref=store_key_ref,
                        buy_price=buy_price,
                        sell_price=sell_price,
                        trade_flags=trade_flags,
                        item_key=item_key,
                        item_key_dup=item_key_dup,
                        extra_field=extra_field,
                        raw=raw,
                    ))
            else:
                # Non-standard: heuristic scan for items using 0101 markers
                rec = data[after_name:soff + rec_size]
                for j in range(len(rec) - 5):
                    if rec[j] == 0x01 and rec[j + 1] == 0x01:
                        ik = struct.unpack_from('<I', rec, j + 2)[0]
                        if 100 < ik < 10000000:
                            # Can't fully parse, just record key and offset
                            store.items.append(StoreItemEntry(
                                offset=after_name + j - 0x20,  # approximate entry start
                                store_key_ref=skey,
                                buy_price=0,
                                sell_price=0,
                                trade_flags=0,
                                item_key=ik,
                                item_key_dup=ik,
                                extra_field=0,
                                raw=b'',
                            ))
                store.item_count = len(store.items)

            self.stores.append(store)

    def get_store_by_key(self, key: int) -> Optional[StoreRecord]:
        return next((s for s in self.stores if s.key == key), None)

    def get_store_by_name(self, name: str) -> Optional[StoreRecord]:
        name_lower = name.lower()
        return next((s for s in self.stores if name_lower in s.name.lower()), None)

    def swap_item(self, store_key: int, old_item_key: int, new_item_key: int) -> bool:
        """Swap an item key in a standard-format store."""
        store = self.get_store_by_key(store_key)
        if not store or not store.is_standard:
            log.warning("Store %d not found or not standard format", store_key)
            return False

        for item in store.items:
            if item.item_key == old_item_key:
                entry_off = item.offset
                # Patch item_key at +0x22
                struct.pack_into('<I', self._body_data, entry_off + 0x22, new_item_key)
                # Patch item_key_dup at +0x5D
                struct.pack_into('<I', self._body_data, entry_off + 0x5D, new_item_key)
                item.item_key = new_item_key
                item.item_key_dup = new_item_key
                log.info("Swapped %d -> %d in store %d", old_item_key, new_item_key, store_key)
                return True
        return False

    def add_item(self, store_key: int, donor_item_key: int, new_item_key: int,
                 buy_price: int = -1, sell_price: int = -1) -> bool:
        """Add an item to a standard-format store by cloning a donor entry.

        Properly updates BOTH count fields and rebuilds header offsets.
        """
        store = self.get_store_by_key(store_key)
        if not store or not store.is_standard:
            log.warning("Store %d not found or not standard format", store_key)
            return False

        # Find donor
        donor = None
        for item in store.items:
            if item.item_key == donor_item_key:
                donor = item
                break
        if not donor or len(donor.raw) < ITEM_ENTRY_SIZE:
            log.warning("Donor %d not found in store %d", donor_item_key, store_key)
            return False

        # Clone the entry
        new_entry = bytearray(donor.raw)
        # Patch item_key at +0x22
        struct.pack_into('<I', new_entry, 0x22, new_item_key)
        # Patch item_key_dup at +0x5D
        struct.pack_into('<I', new_entry, 0x5D, new_item_key)
        # Patch prices if specified
        if buy_price >= 0:
            struct.pack_into('<Q', new_entry, 0x02, buy_price)
        if sell_price >= 0:
            struct.pack_into('<Q', new_entry, 0x0A, sell_price)

        # Insert after the last item (before the tail)
        items_end = store.after_name + HEADER_OVERHEAD + store.item_count * ITEM_ENTRY_SIZE
        self._body_data[items_end:items_end] = new_entry

        # Update BOTH count fields
        new_count = store.item_count + 1
        struct.pack_into('<I', self._body_data, store.after_name + 0x26, new_count)
        struct.pack_into('<I', self._body_data, store.after_name + 0x2F, new_count)

        # Rebuild header offsets (all stores after this one shifted)
        self._rebuild_header_offsets(store.index, ITEM_ENTRY_SIZE)

        # Re-parse to refresh all offsets
        self._parse_all_stores()

        log.info("Added item %d (from donor %d) to store %d. New count: %d",
                 new_item_key, donor_item_key, store_key, new_count)
        return True

    def remove_item(self, store_key: int, item_key: int) -> bool:
        """Remove an item from a standard-format store."""
        store = self.get_store_by_key(store_key)
        if not store or not store.is_standard:
            return False

        for i, item in enumerate(store.items):
            if item.item_key == item_key:
                entry_off = item.offset
                self._body_data[entry_off:entry_off + ITEM_ENTRY_SIZE] = b''

                new_count = store.item_count - 1
                struct.pack_into('<I', self._body_data, store.after_name + 0x26, new_count)
                struct.pack_into('<I', self._body_data, store.after_name + 0x2F, new_count)

                self._rebuild_header_offsets(store.index, -ITEM_ENTRY_SIZE)
                self._parse_all_stores()
                return True
        return False

    def _rebuild_header_offsets(self, changed_index: int, size_delta: int) -> None:
        """Update header offsets after insertion/removal.

        All stores after changed_index need their offsets shifted.
        """
        new_entries = list(self._header_entries)
        for i in range(changed_index + 1, len(new_entries)):
            key, off = new_entries[i]
            new_entries[i] = (key, off + size_delta)
        self._header_entries = new_entries

        # Rebuild header binary
        count = len(new_entries)
        new_hdr = bytearray(struct.pack('<H', count))
        for skey, soff in new_entries:
            new_hdr += struct.pack('<HI', skey, soff)
        self._header_data = bytes(new_hdr)

    def get_header_bytes(self) -> bytes:
        """Get the current pabgh header bytes."""
        return self._header_data

    def get_body_bytes(self) -> bytes:
        """Get the current pabgb body bytes."""
        return bytes(self._body_data)

    def get_summary(self) -> str:
        """Human-readable summary."""
        std = sum(1 for s in self.stores if s.is_standard)
        total_items = sum(len(s.items) for s in self.stores)
        return (f"{len(self.stores)} stores ({std} standard, {len(self.stores)-std} special), "
                f"{total_items} total items, body={len(self._body_data):,} bytes")

    def validate(self) -> List[str]:
        """Validate all standard-format stores. Returns list of issues."""
        issues = []
        for store in self.stores:
            if not store.is_standard:
                continue
            # Check counts match
            cnt1 = struct.unpack_from('<I', self._body_data, store.after_name + 0x26)[0]
            cnt2 = struct.unpack_from('<I', self._body_data, store.after_name + 0x2F)[0]
            if cnt1 != cnt2:
                issues.append(f"{store.name}: count mismatch +0x26={cnt1} +0x2F={cnt2}")
            if cnt1 != len(store.items):
                issues.append(f"{store.name}: count={cnt1} but {len(store.items)} items parsed")
            # Check item keys match their duplicates
            for item in store.items:
                if item.item_key != item.item_key_dup:
                    issues.append(f"{store.name}: item {item.item_key} dup mismatch {item.item_key_dup}")
        return issues


def parse_storeinfo(pabgh_path: str, pabgb_path: str) -> StoreinfoParser:
    """Convenience: parse storeinfo files and return parser."""
    parser = StoreinfoParser()
    parser.load_from_files(pabgh_path, pabgb_path)
    parser.load_names()
    return parser


if __name__ == '__main__':
    import sys
    pabgh = sys.argv[1] if len(sys.argv) > 1 else './extracted/0008_full/storeinfo.pabgh'
    pabgb = sys.argv[2] if len(sys.argv) > 2 else './extracted/0008_full/storeinfo.pabgb'

    parser = parse_storeinfo(pabgh, pabgb)
    print(parser.get_summary())
    print()

    issues = parser.validate()
    if issues:
        print(f"Validation issues ({len(issues)}):")
        for iss in issues:
            print(f"  {iss}")
    else:
        print("Validation: all standard stores OK")

    print()
    print("Standard format stores with items:")
    for s in parser.stores:
        if s.is_standard and s.items:
            items_str = ', '.join(f"{parser.get_item_name(it.item_key)}({it.item_key})"
                                 for it in s.items[:3])
            if len(s.items) > 3:
                items_str += f", ... +{len(s.items)-3} more"
            print(f"  {s.name} (key={s.key}): {len(s.items)} items - {items_str}")
