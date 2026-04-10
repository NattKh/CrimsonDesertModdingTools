"""PAZ asset repacker for Crimson Desert.

Patches modified files back into PAZ archives. Handles encryption and
compression to produce output the game will accept.

Pipeline: modified file -> LZ4 compress -> ChaCha20 encrypt -> write to PAZ

Constraints:
  - Encrypted blob must be exactly comp_size bytes (original size in PAMT)
  - Decompressed output must be exactly orig_size bytes
  - PAMT files must never be modified (game integrity check)
  - NTFS timestamps on .paz files must be preserved

Usage:
    # Repack using PAMT metadata (recommended)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml"

    # Repack to a standalone file (for testing)
    python paz_repack.py modified.xml --pamt 0.pamt --paz-dir ./0003 \
        --entry "technique/rendererconfiguration.xml" --output repacked.bin

Library usage:
    from paz_repack import repack_entry
    from paz_parse import parse_pamt

    entries = parse_pamt("0.pamt", paz_dir="./0003")
    entry = next(e for e in entries if "rendererconfiguration" in e.path)
    repack_entry("modified.xml", entry)
"""

import os
import sys
import struct
import ctypes
import argparse

import lz4.block

from paz_parse import parse_pamt, PazEntry
from paz_crypto import encrypt, lz4_compress



def _save_timestamps(path: str):
    """Capture NTFS timestamps. Returns a callable to restore them."""
    if sys.platform != 'win32':
        return lambda: None

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

    OPEN_EXISTING = 3
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_ATTR = 0x80 | 0x02000000

    h = kernel32.CreateFileW(path, GENERIC_READ, 1, None, OPEN_EXISTING, FILE_ATTR, None)
    if h == -1:
        return lambda: None

    ct, at, mt = FILETIME(), FILETIME(), FILETIME()
    kernel32.GetFileTime(h, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
    kernel32.CloseHandle(h)

    def restore():
        h2 = kernel32.CreateFileW(path, GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_ATTR, None)
        if h2 != -1:
            kernel32.SetFileTime(h2, ctypes.byref(ct), ctypes.byref(at), ctypes.byref(mt))
            kernel32.CloseHandle(h2)

    return restore



def _pad_to_orig_size(data: bytes, orig_size: int) -> bytes:
    """Pad data to exactly orig_size bytes with zero bytes."""
    if len(data) >= orig_size:
        return data[:orig_size]
    return data + b'\x00' * (orig_size - len(data))


def _shrink_to_orig_size(data: bytes, orig_size: int) -> bytes:
    """Shrink XML data to exactly orig_size by removing comment content
    and collapsing redundant whitespace.

    Removes bytes from the end of XML comments first (replacing the
    comment body with fewer characters). If that's not enough, collapses
    runs of multiple spaces/tabs into single spaces.

    Returns:
        data trimmed to exactly orig_size bytes

    Raises:
        ValueError if the data can't be shrunk enough
    """
    if len(data) <= orig_size:
        return _pad_to_orig_size(data, orig_size)

    excess = len(data) - orig_size
    result = bytearray(data)

    comments = _find_xml_comments(bytes(result))
    comments.sort(key=lambda c: c[1] - c[0], reverse=True)

    for cstart, cend in comments:
        if excess <= 0:
            break
        body_len = cend - cstart
        removable = body_len - 1
        if removable <= 0:
            continue
        to_remove = min(removable, excess)
        result[cstart + 1:cstart + 1 + to_remove] = b''
        excess -= to_remove
        if excess <= 0:
            break
        comments = _find_xml_comments(bytes(result))
        comments.sort(key=lambda c: c[1] - c[0], reverse=True)

    if excess <= 0:
        return bytes(result[:orig_size]) if len(result) >= orig_size else \
            bytes(result) + b'\x00' * (orig_size - len(result))

    i = len(result) - 1
    while i > 0 and excess > 0:
        if result[i] in (0x20, 0x09) and result[i - 1] in (0x20, 0x09):
            del result[i]
            excess -= 1
        i -= 1

    if excess <= 0:
        return bytes(result[:orig_size]) if len(result) >= orig_size else \
            bytes(result) + b'\x00' * (orig_size - len(result))

    comments = _find_xml_comments(bytes(result))
    for cstart, cend in comments:
        if excess <= 0:
            break
        full_start = cstart - 4
        full_end = cend + 3
        removable = full_end - full_start
        if removable <= excess + 7:
            to_remove = min(removable, excess)
            result[full_start:full_start + to_remove] = b''
            excess -= to_remove
            if excess <= 0:
                break
            comments = _find_xml_comments(bytes(result))

    if len(result) > orig_size:
        raise ValueError(
            f"Modified file is {len(data) - orig_size} bytes over orig_size "
            f"({orig_size}). Could only trim {len(data) - len(result)} bytes "
            f"from comments and whitespace. Reduce content manually.")

    return bytes(result) + b'\x00' * (orig_size - len(result))


def _find_xml_comments(data: bytes) -> list[tuple[int, int]]:
    """Find all XML comment bodies (content between <!-- and -->).

    Returns list of (start, end) byte offsets for the comment content
    (not including the delimiters themselves).
    """
    comments = []
    search_from = 0
    while True:
        start = data.find(b'<!--', search_from)
        if start == -1:
            break
        content_start = start + 4
        end = data.find(b'-->', content_start)
        if end == -1:
            break
        if end > content_start:
            comments.append((content_start, end))
        search_from = end + 3
    return comments


def _make_xml_safe_incompressible(length: int) -> bytes:
    """Generate incompressible content that is safe inside an XML comment.

    Uses base64-encoded random bytes: all printable ASCII, no control
    characters, no '-->' sequences, and the randomness makes it
    incompressible by LZ4.
    """
    import os
    import base64
    raw = os.urandom(length)
    b64 = base64.b64encode(raw)
    return b64[:length]


def _inflate_with_comments(padded: bytes, plaintext_len: int,
                           target_comp_size: int,
                           target_orig_size: int) -> bytes | None:
    """Inflate compressed size to exactly target_comp_size.

    Three strategies, tried in order:

    1. Replace zero bytes in the trailing padding with spaces. Works well
       for small deltas when there is padding room.

    2. Insert an XML comment with incompressible content into the trailing
       padding. Binary-search the body length. Works for larger deltas
       when there is padding room.

    3. Replace existing XML comment body bytes with incompressible content
       in-place (same byte count). Works when plaintext fills orig_size
       completely and there is no padding room at all.

    Returns adjusted plaintext (exactly target_orig_size bytes) or None.
    """
    padding_available = target_orig_size - plaintext_len

    base_comp = len(lz4.block.compress(padded, store_size=False))
    needed = target_comp_size - base_comp

    if needed <= 0:
        return None

    if padding_available > 0:
        max_replaceable = padding_available

        def _build_zero_trial(n: int) -> bytes:
            trial = bytearray(padded)
            for i in range(n):
                trial[plaintext_len + i] = 0x20
            return bytes(trial)

        c_one = len(lz4.block.compress(_build_zero_trial(1), store_size=False))
        if c_one <= target_comp_size:
            lo, hi = 1, max_replaceable
            while lo <= hi:
                mid = (lo + hi) // 2
                c = len(lz4.block.compress(_build_zero_trial(mid), store_size=False))
                if c == target_comp_size:
                    return _build_zero_trial(mid)
                elif c < target_comp_size:
                    lo = mid + 1
                else:
                    hi = mid - 1
            for n in range(max(1, lo - 5), min(lo + 5, max_replaceable + 1)):
                trial = _build_zero_trial(n)
                if len(lz4.block.compress(trial, store_size=False)) == target_comp_size:
                    return trial

    if padding_available >= 8:
        max_body = padding_available - 7
        rand_body = _make_xml_safe_incompressible(max_body)

        def _build_comment_trial(body_len: int) -> bytes:
            body = rand_body[:body_len]
            comment = b'<!--' + body + b'-->'
            trial = padded[:plaintext_len] + comment
            if len(trial) < target_orig_size:
                trial = trial + b'\x00' * (target_orig_size - len(trial))
            else:
                trial = trial[:target_orig_size]
            return trial

        c_min = len(lz4.block.compress(_build_comment_trial(0), store_size=False))
        c_max = len(lz4.block.compress(_build_comment_trial(max_body), store_size=False))
        if c_min <= target_comp_size <= c_max:
            lo, hi = 0, max_body
            while lo <= hi:
                mid = (lo + hi) // 2
                trial = _build_comment_trial(mid)
                c = lz4.block.compress(trial, store_size=False)
                if len(c) == target_comp_size:
                    return trial
                elif len(c) < target_comp_size:
                    lo = mid + 1
                else:
                    hi = mid - 1
            for n in range(max(0, lo - 20), min(lo + 20, max_body + 1)):
                trial = _build_comment_trial(n)
                if len(lz4.block.compress(trial, store_size=False)) == target_comp_size:
                    return trial

    return None


def _inflate_by_replacing_comment_bodies(padded: bytes, target_comp_size: int) -> bytes | None:
    """Strategy 3: replace existing XML comment body bytes with incompressible
    content in-place (same byte count, no size change).

    Tries multiple random fills — each gives a different compressed-size curve,
    so retrying finds one where the target is reachable.

    Returns adjusted data or None.
    """
    comments = _find_xml_comments(padded)
    if not comments:
        return None

    positions = [i for cstart, cend in comments for i in range(cstart, cend)]
    if not positions:
        return None

    total = len(positions)

    def _try_fill(rand_fill: bytes) -> bytes | None:
        def _build_trial(n: int) -> bytes:
            trial = bytearray(padded)
            for idx, pos in enumerate(positions[:n]):
                trial[pos] = rand_fill[idx]
            return bytes(trial)

        c_none = len(lz4.block.compress(_build_trial(0), store_size=False))
        c_all  = len(lz4.block.compress(_build_trial(total), store_size=False))
        if target_comp_size < c_none or target_comp_size > c_all:
            return None

        lo, hi = 0, total
        while lo <= hi:
            mid = (lo + hi) // 2
            c = len(lz4.block.compress(_build_trial(mid), store_size=False))
            if c == target_comp_size:
                return _build_trial(mid)
            elif c < target_comp_size:
                lo = mid + 1
            else:
                hi = mid - 1

        for n in range(max(0, lo - 50), min(lo + 50, total + 1)):
            if len(lz4.block.compress(_build_trial(n), store_size=False)) == target_comp_size:
                return _build_trial(n)

        return None

    for _ in range(8):
        result = _try_fill(_make_xml_safe_incompressible(total))
        if result is not None:
            return result

    return None


def _match_compressed_size(plaintext: bytes, target_comp_size: int,
                           target_orig_size: int) -> bytes:
    """Adjust plaintext so it compresses to exactly target_comp_size.

    If the plaintext is larger than target_orig_size, trims comment content
    and whitespace to fit. Then finds individual byte positions where
    replacing with a space changes the LZ4 compressed output to exactly
    the target.

    Returns:
        adjusted plaintext (exactly target_orig_size bytes)

    Raises:
        ValueError if size matching fails
    """
    if len(plaintext) > target_orig_size:
        padded = _shrink_to_orig_size(plaintext, target_orig_size)
    else:
        padded = _pad_to_orig_size(plaintext, target_orig_size)

    comp = lz4.block.compress(padded, store_size=False)
    if len(comp) == target_comp_size:
        return padded

    delta = len(comp) - target_comp_size

    if delta < 0:
        result = _inflate_with_comments(padded, len(plaintext),
                                        target_comp_size, target_orig_size)
        if result is not None:
            return result
        result = _inflate_by_replacing_comment_bodies(padded, target_comp_size)
        if result is not None:
            return result
        raise ValueError(
            f"Cannot match target comp_size {target_comp_size} "
            f"(got {len(comp)}, delta {delta}). "
            f"File compresses too well — not enough padding room to inflate. "
            f"Try making fewer or smaller changes to the XML.")

    comments = _find_xml_comments(padded)
    comment_positions = set()
    for cstart, cend in comments:
        for i in range(cstart, cend):
            if padded[i:i+1] != b' ':
                comment_positions.add(i)

    candidates = sorted(comment_positions)
    candidates_set = set(candidates)

    for i in candidates:
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    step = max(1, len(padded) // 5000)
    for i in range(0, len(padded), step):
        if padded[i:i+1] == b' ' or i in candidates_set:
            continue
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    for i in range(len(padded)):
        if padded[i:i+1] == b' ' or i in candidates_set:
            continue
        trial = bytearray(padded)
        trial[i] = 0x20
        c = lz4.block.compress(bytes(trial), store_size=False)
        if len(c) == target_comp_size:
            return bytes(trial)

    if delta > 1:
        lo, hi = 0, len(candidates)
        while lo <= hi:
            mid = (lo + hi) // 2
            trial = bytearray(padded)
            for idx in candidates[:mid]:
                trial[idx] = 0x20
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)
            elif len(c) > target_comp_size:
                lo = mid + 1
            else:
                hi = mid - 1

        for n in range(max(0, lo - 20), min(lo + 20, len(candidates) + 1)):
            trial = bytearray(padded)
            for idx in candidates[:n]:
                trial[idx] = 0x20
            c = lz4.block.compress(bytes(trial), store_size=False)
            if len(c) == target_comp_size:
                return bytes(trial)

    raise ValueError(
        f"Cannot match target comp_size {target_comp_size} "
        f"(got {len(comp)}, delta {delta})")


PA_MAGIC = 0x2145E233

def rol(x, k):
    return ((x << k) & 0xFFFFFFFF) | (x >> (32 - k))

def ror(x, k):
    return (x >> k) | ((x << (32 - k)) & 0xFFFFFFFF)

def pa_checksum(data: bytes):
    length = len(data)
    if length == 0:
        return 0

    a = b = c = (length - PA_MAGIC) & 0xFFFFFFFF
    offset = 0
    remaining = length

    while remaining > 12:
        a = (a + struct.unpack_from("<I", data, offset)[0]) & 0xFFFFFFFF
        b = (b + struct.unpack_from("<I", data, offset + 4)[0]) & 0xFFFFFFFF
        c = (c + struct.unpack_from("<I", data, offset + 8)[0]) & 0xFFFFFFFF

        a = (a - c) & 0xFFFFFFFF; a ^= rol(c, 4); c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b ^= rol(a, 6); a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c ^= rol(b, 8); b = (b + a) & 0xFFFFFFFF
        a = (a - c) & 0xFFFFFFFF; a ^= rol(c,16); c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b ^= rol(a,19); a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c ^= rol(b, 4); b = (b + a) & 0xFFFFFFFF

        offset += 12
        remaining -= 12

    tail = data[offset:]

    for i in range(remaining):
        byte = tail[i]
        if i < 4:
            a = (a + (byte << (8 * i))) & 0xFFFFFFFF
        elif i < 8:
            b = (b + (byte << (8 * (i - 4)))) & 0xFFFFFFFF
        else:
            c = (c + (byte << (8 * (i - 8)))) & 0xFFFFFFFF

    v82 = ((b ^ c) - rol(b, 14)) & 0xFFFFFFFF
    v83 = ((a ^ v82) - rol(v82, 11)) & 0xFFFFFFFF
    v84 = ((v83 ^ b) - ror(v83, 7)) & 0xFFFFFFFF
    v85 = ((v84 ^ v82) - rol(v84, 16)) & 0xFFFFFFFF
    v86 = rol(v85, 4)
    t = ((v83 ^ v85) - v86) & 0xFFFFFFFF
    v87 = ((t ^ v84) - rol(t, 14)) & 0xFFFFFFFF

    return ((v87 ^ v85) - ror(v87, 8)) & 0xFFFFFFFF

def repack_entry(modified_path: str, entry,
                 output_path: str = None,
                 dry_run: bool = False,
                 pamt_path: str = None,
                 append_last: bool = False) -> dict:

    with open(modified_path, 'rb') as f:
        plaintext = f.read()

    basename = os.path.basename(entry.path)

    if entry.compressed and entry.compression_type == 2:
        payload = lz4.block.compress(plaintext, store_size=False)
    else:
        payload = plaintext

    if entry.encrypted:
        payload = encrypt(payload, basename)

    result = {
        "entry_path": entry.path,
        "paz_file": entry.paz_file,
        "modified_size": len(plaintext),
        "comp_size": len(payload),
        "orig_size": len(plaintext),
        "compressed": entry.compressed,
        "encrypted": entry.encrypted,
        "offset": entry.offset
    }

    if dry_run:
        result["action"] = "dry_run"
        return result

    if output_path:
        with open(output_path, 'wb') as f:
            f.write(payload)
        result["action"] = "written"
        result["output"] = output_path
        return result

    # ==========================================
    # APPEND TO LAST PAZ
    # ==========================================
    if append_last:
        folder = os.path.dirname(entry.paz_file)

        paz_files = sorted(
            [f for f in os.listdir(folder) if f.endswith(".paz")],
            key=lambda x: int(os.path.splitext(x)[0])
        )

        last_paz = paz_files[-1]
        target_paz = os.path.join(folder, last_paz)
        paz_index = int(os.path.splitext(last_paz)[0])

        current_size = os.path.getsize(target_paz)
        aligned = (current_size + 15) & ~15

        with open(target_paz, 'ab') as f:
            if aligned > current_size:
                f.write(b'\x00' * (aligned - current_size))

            new_offset = aligned
            f.write(payload)

            pad = (16 - (len(payload) % 16)) % 16
            if pad:
                f.write(b'\x00' * pad)

        result["paz_file"] = target_paz
        result["offset"] = new_offset

    # ==========================================
    # REPLACE INSIDE ORIGINAL PAZ
    # ==========================================
    else:
        with open(entry.paz_file, 'rb') as f:
            paz_data = f.read()

        start = entry.offset
        end = entry.offset + entry.comp_size

        new_paz = paz_data[:start] + payload + paz_data[end:]

        with open(entry.paz_file, 'wb') as f:
            f.write(new_paz)

        delta = len(payload) - entry.comp_size

    # ==========================================
    # PATCH PAMT
    # ==========================================
    if pamt_path:
        entries = parse_pamt(pamt_path, paz_dir=os.path.dirname(entry.paz_file))

        with open(pamt_path, 'r+b') as pmt:

            if append_last:
                pmt.seek(entry.table_offset + 4)
                pmt.write(struct.pack('<I', new_offset))
                pmt.write(struct.pack('<I', len(payload)))
                pmt.write(struct.pack('<I', len(plaintext)))
                pmt.write(struct.pack('<H', paz_index))

            else:
                pmt.seek(entry.table_offset + 8)
                pmt.write(struct.pack('<I', len(payload)))
                pmt.write(struct.pack('<I', len(plaintext)))

                for e in entries:
                    if e.paz_file == entry.paz_file and e.offset > entry.offset:
                        shifted = e.offset + delta
                        pmt.seek(e.table_offset + 4)
                        pmt.write(struct.pack('<I', shifted))

        # ==========================================
        # UPDATE LAST PAZ CRC
        # ==========================================
        if append_last:
            with open(target_paz, 'rb') as f:
                paz_crc = pa_checksum(f.read())

            table_offset = 12 + paz_index * 12

            with open(pamt_path, 'r+b') as pmt:
                pmt.seek(table_offset + 4)
                pmt.write(struct.pack('<I', paz_crc))
                pmt.write(struct.pack('<I', os.path.getsize(target_paz)))

        # ==========================================
        # PATCH PAMT HEADER CRC
        # ==========================================
        with open(pamt_path, 'rb') as f:
            final_data = bytearray(f.read())

        crc = pa_checksum(final_data[12:])
        final_data[0:4] = struct.pack('<I', crc)

        with open(pamt_path, 'wb') as f:
            f.write(final_data)

        result["pmt_crc"] = crc

    result["action"] = "replaced"
    return result

def find_entry(entries, target_path):
    target = target_path.replace("\\", "/").lower()
    for e in entries:
        if e.path.lower() == target:
            return e
    raise ValueError(f"Entry not found: {target_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Repack a modified file into a PAZ archive",
        epilog="Example: python paz_repack.py modified.xml --pamt 0.pamt "
               "--paz-dir ./0003 --entry technique/rendererconfiguration.xml")
    parser.add_argument("modified", help="Path to modified file")
    parser.add_argument("--pamt", required=True, help="Path to .pamt index file")
    parser.add_argument("--paz-dir", help="Directory containing .paz files")
    parser.add_argument("--entry", required=True,
                        help="Entry path within the archive (or partial match)")
    parser.add_argument("--output", help="Write to file instead of patching PAZ")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would happen without writing")
    parser.add_argument("--append-last", action="store_true")
    args = parser.parse_args()

    entries = parse_pamt(args.pamt, paz_dir=args.paz_dir)
    entry = find_entry(entries, args.entry)

    print(f"Entry:      {entry.path}")
    print(f"PAZ:        {entry.paz_file} @ 0x{entry.offset:08X}")
    print(f"comp_size:  {entry.comp_size:,}")
    print(f"orig_size:  {entry.orig_size:,}")
    print(f"Compressed: {'LZ4' if entry.compressed else 'no'}")
    print(f"Encrypted:  {'yes' if entry.encrypted else 'no'}")
    print()

    try:
        result = repack_entry(args.modified, entry,
                              output_path=args.output,
                              dry_run=args.dry_run,
                              pamt_path=args.pamt,
                              append_last=args.append_last)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if result["action"] == "dry_run":
        print("Dry run — no changes made.")
    elif result["action"] == "written":
        print(f"Written to {result['output']}")
    elif result["action"] == "replaced":
        print(f"Replaced {result['paz_file']} at {result['offset']}")
        print(f"PAMT CRC: 0x{result['pmt_crc']:08X}")

    print(f"Modified file: {result['modified_size']:,} bytes")


if __name__ == "__main__":
    main()
