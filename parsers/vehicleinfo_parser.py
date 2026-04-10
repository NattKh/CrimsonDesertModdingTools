"""
VehicleInfo parser — parses vehicleinfo.pabgb entries.

Reader: sub_14105D470
Target: F20 (_canCallInSafeZone) — only Horse has this set to 1 in vanilla.

NOTE: pabgh uses u16 count + (u16 key + u32 offset) = 6B per entry,
NOT the standard 8B format used by most pabgb files.
"""
import struct


def parse_pabgh_index_u16(G):
    """Parse pabgh with u16 count + 6B entries (u16 key + u32 offset)."""
    count = struct.unpack_from('<H', G, 0)[0]
    idx = {}
    for i in range(count):
        pos = 2 + i * 6
        if pos + 6 > len(G):
            break
        k = struct.unpack_from('<H', G, pos)[0]
        o = struct.unpack_from('<I', G, pos + 2)[0]
        idx[k] = o
    return idx


def parse_entry(D, eoff, end):
    """Parse a single VehicleInfo entry. Returns dict or None."""
    try:
        p = eoff

        # F1: _key (2B u16)
        key = struct.unpack_from('<H', D, p)[0]; p += 2

        # F2: _stringKey (CString)
        slen = struct.unpack_from('<I', D, p)[0]; p += 4
        if slen > 200:
            return None
        name = D[p:p + slen].decode('utf-8', errors='replace'); p += slen

        # F3: bool (1B)
        p += 1

        # F4: u32
        p += 4

        # F5: enum4B
        p += 4

        # F6: u8 flag (vehicle size category)
        vehicle_type = D[p]; p += 1

        # F7: 16x enum pairs (128B)
        p += 16 * 8

        # F8: u8 flag2
        p += 1

        # F9: 2x enum pairs (16B)
        p += 2 * 8

        # F10-12: 3x u32
        p += 12

        # F13: u8
        p += 1

        # F14: PlayList (u32 count + count bytes)
        pl_count = struct.unpack_from('<I', D, p)[0]; p += 4 + pl_count

        # F15: _callVehicleVoxelType (u32)
        voxel_type = struct.unpack_from('<I', D, p)[0]; p += 4

        # F16-17: 2x u8
        f16 = D[p]; p += 1
        f17 = D[p]; p += 1

        # F18: enum4B (vehicle character key)
        vehicle_char_key = struct.unpack_from('<I', D, p)[0]; p += 4

        # F19: u8 — mount call type (0=siege, 1=rideable, 2=flying)
        mount_call_type = D[p]; p += 1
        mount_call_type_offset = p - 1

        # F20: u8 — can call in safe zone (only Horse=1 in vanilla)
        can_call_safe_zone = D[p]; p += 1
        can_call_safe_zone_offset = p - 1

        # F21: u32 (float — altitude cap, 0x7F7FFFFF = no cap)
        altitude_cap_raw = struct.unpack_from('<I', D, p)[0]
        altitude_cap = struct.unpack_from('<f', D, p)[0]; p += 4

        return {
            'key': key,
            'name': name,
            'vehicle_type': vehicle_type,
            'voxel_type': voxel_type,
            'f16': f16,
            'f17': f17,
            'vehicle_char_key': vehicle_char_key,
            'mount_call_type': mount_call_type,
            'mount_call_type_offset': mount_call_type_offset,
            'can_call_safe_zone': can_call_safe_zone,
            'can_call_safe_zone_offset': can_call_safe_zone_offset,
            'altitude_cap': altitude_cap,
            'altitude_cap_offset': p - 4,
        }

    except (struct.error, IndexError):
        return None


def parse_all_entries(pabgb_path, pabgh_path):
    with open(pabgb_path, 'rb') as f:
        D = f.read()
    with open(pabgh_path, 'rb') as f:
        G = f.read()

    idx = parse_pabgh_index_u16(G)
    sorted_offs = sorted(set(idx.values()))
    entries = []
    failures = 0

    for key, eoff in idx.items():
        bi = sorted_offs.index(eoff)
        end = sorted_offs[bi + 1] if bi + 1 < len(sorted_offs) else len(D)
        entry = parse_entry(D, eoff, end)
        if entry is None:
            failures += 1
        else:
            entries.append(entry)

    return entries, failures
