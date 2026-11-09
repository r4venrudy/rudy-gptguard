"""Generate disposable, deterministic GPT disk images for the examples and tests."""
from argparse import ArgumentParser
from binascii import crc32
from dataclasses import dataclass, replace
from pathlib import Path
import struct
from uuid import UUID

DISK = UUID("378e5c5f-4889-4c37-a817-1af15e6935b1")
TYPE = UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
SECTORS = 256
ENTRY_COUNT = 128
ENTRY_SIZE = 128


@dataclass(frozen=True)
class Entry:
    slot: int
    id: UUID
    first: int
    last: int
    name: str
    attrs: int = 0
    type_id: UUID = TYPE


FIRST = Entry(1, UUID("09c17e25-3b36-4c10-885f-29ad238c5a95"), 64, 100, "root")
SECOND = Entry(2, UUID("32e63331-7584-41d4-852b-8c0185ca684f"), 120, 160, "evidence", 1 << 63)
THIRD = Entry(4, UUID("5e9b3379-08de-4c87-945c-323f477c8fb7"), 180, 200, "spare")
BEFORE = [FIRST, SECOND]
AFTER = [replace(FIRST, slot=3, first=70, name="root-v2"), THIRD]


def geometry(sector):
    span = ENTRY_COUNT * ENTRY_SIZE // sector
    return 2, SECTORS - 1 - span, 2 + span, SECTORS - 2 - span


def update_header_crc(image, sector, lba):
    start = sector * lba
    size, = struct.unpack_from("<I", image, start + 12)
    struct.pack_into("<I", image, start + 16, 0)
    struct.pack_into("<I", image, start + 16, crc32(image[start:start + size]))


def make_image(parts, sector=512, backup_parts=None):
    primary_array, backup_array, first_usable, last_usable = geometry(sector)
    image = bytearray(sector * SECTORS)
    # Protective MBR. The boot indicator stays at zero.
    image[447:450] = b"\x00\x02\x00"
    image[450:454] = b"\xee\xff\xff\xff"
    struct.pack_into("<II", image, 454, 1, SECTORS - 1)
    image[510:512] = b"\x55\xaa"
    copies = ((1, SECTORS - 1, primary_array, parts),
              (SECTORS - 1, 1, backup_array, parts if backup_parts is None else backup_parts))
    for lba, alternate, table, entries in copies:
        table_bytes = bytearray(ENTRY_COUNT * ENTRY_SIZE)
        for entry in entries:
            offset = (entry.slot - 1) * ENTRY_SIZE
            struct.pack_into("<16s16sQQQ72s", table_bytes, offset, entry.type_id.bytes_le,
                             entry.id.bytes_le, entry.first, entry.last, entry.attrs,
                             entry.name.encode("utf-16-le"))
        image[table * sector:table * sector + len(table_bytes)] = table_bytes
        struct.pack_into("<8sIIIIQQQQ16sQIII", image, sector * lba,
                         b"EFI PART", 0x10000, 92, 0, 0, lba, alternate, first_usable,
                         last_usable, DISK.bytes_le, table, ENTRY_COUNT, ENTRY_SIZE, crc32(table_bytes))
        update_header_crc(image, sector, lba)
    return image


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sector-size", type=int, choices=(512, 4096), default=512)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sector = args.sector_size
    before = make_image(BEFORE, sector)
    damaged = bytearray(before)
    damaged[sector + 16] ^= 1
    for name, image in (("before", before), ("after", make_image(AFTER, sector)),
                        ("damaged-primary", damaged), ("divergent", make_image(BEFORE, sector, AFTER))):
        (args.output / f"{name}.img").write_bytes(image)


if __name__ == "__main__":
    main()
