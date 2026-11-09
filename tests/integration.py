"""Check the built CLI against an independent byte-level GPT fixture generator."""
from binascii import crc32
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
from make_images import (AFTER, BEFORE, FIRST, SECOND, ENTRY_COUNT, ENTRY_SIZE,
                         SECTORS, geometry, make_image, update_header_crc)

runtime, binary = sys.argv[1:]
checks = 0


def check(condition, detail):
    global checks
    if not condition:
        raise AssertionError(detail)
    checks += 1


def invoke(*args, status=0):
    proc = subprocess.run([runtime, binary, *map(str, args)], capture_output=True,
                          encoding="utf-8", timeout=20)
    check(proc.returncode == status, (args, proc.returncode, proc.stderr, proc.stdout[:300]))
    if status == 2:
        check(proc.stderr.startswith("gptguard:") and not proc.stdout, proc.stderr)
        return None
    check(not proc.stderr, proc.stderr)
    return json.loads(proc.stdout)


def issue(report, copy, code, slot=None):
    group = report["protectiveMbrIssues"] if copy == "mbr" else report[copy]["issues"]
    check({"code": code, "slot": slot} in group, (code, slot, group))


def copy_write(image, sector, lba, offset, layout, value):
    struct.pack_into(layout, image, sector * lba + offset, value)
    update_header_crc(image, sector, lba)


with TemporaryDirectory() as tmp:
    first = Path(tmp) / "first.img"
    second = Path(tmp) / "second.img"
    for sector in (512, 4096):
        flags = ("--sector-size", str(sector))
        baseline = make_image(BEFORE, sector)
        first.write_bytes(baseline)
        pristine = invoke("inspect", first, *flags)
        check(pristine["healthy"] and pristine["gptStatus"] == "consistent", pristine)
        check(pristine["sectorSize"] == sector and pristine["totalSectors"] == SECTORS, pristine)
        for copy, lba, table in (("primary", 1, geometry(sector)[0]),
                                 ("backup", SECTORS - 1, geometry(sector)[1])):
            observed = pristine[copy]
            table_bytes = baseline[sector * table:sector * table + ENTRY_COUNT * ENTRY_SIZE]
            check(observed["header"]["arrayCrc"] == crc32(table_bytes), copy)
            check(observed["arraySha256"] == sha256(table_bytes).hexdigest(), copy)
            check(observed["header"]["currentLba"] == lba and observed["valid"], copy)
            check([part["id"] for part in observed["partitions"]] == [str(p.id) for p in BEFORE], copy)
            check(observed["partitions"][1]["attributesHex"] == "8000000000000000", copy)
        check(first.read_bytes() == baseline, "audit changed the source image")
        second.write_bytes(make_image(AFTER, sector))
        changed = invoke("compare", first, second, *flags, "--fail-on-change", status=4)["comparison"]
        by_id = {p["id"]: p for p in changed["partitions"]}
        check(changed["changed"] and not changed["diskFields"] and len(by_id) == 3, changed)
        check(by_id[str(FIRST.id)]["fields"] == ["slot", "extent", "name"], changed)
        check(by_id[str(SECOND.id)]["kind"] == "removed", changed)
        check({p["kind"] for p in by_id.values()} == {"removed", "added", "modified"}, changed)
        check(invoke("compare", first, second, *flags)["comparison"]["changed"], changed)
        check(not invoke("compare", first, first, *flags, "--fail-on-change")["comparison"]["changed"],
              "no-op compare")

        def inspect(data):
            first.write_bytes(data)
            return invoke("inspect", first, *flags, status=3)

        for lba, expected in ((1, "backup-only"), (SECTORS - 1, "primary-only")):
            damaged = bytearray(baseline)
            damaged[lba * sector + 16] ^= 1
            report = inspect(damaged)
            check(report["gptStatus"] == expected, report)
            issue(report, "primary" if lba == 1 else "backup", "header.crc32")

        split = make_image(BEFORE, sector, AFTER)
        report = inspect(split)
        check(report["gptStatus"] == "divergent" and report["copyDifferences"] == ["entry-array"], report)
        check(invoke("compare", first, second, *flags, status=3)["comparison"] is None, report)
        split = bytearray(baseline)
        backup = SECTORS - 1
        split[backup * sector + 56] ^= 1
        update_header_crc(split, sector, backup)
        check(inspect(split)["copyDifferences"] == ["disk-id"], "disk ID disagreement")

        damaged = bytearray(baseline)
        damaged[510] = 0
        damaged[466] = 0x83
        report = inspect(damaged)
        check(report["gptStatus"] == "consistent" and not report["healthy"], report)
        issue(report, "mbr", "mbr.signature")
        issue(report, "mbr", "mbr.non-protective-entry", 2)
        damaged = bytearray(baseline)
        struct.pack_into("<I", damaged, 458, 1)
        issue(inspect(damaged), "mbr", "mbr.protective-range", 1)

        for field, layout, value, expected in (
            (8, "<I", 0x20000, "header.revision"),
            (20, "<I", 1, "header.reserved"),
            (24, "<Q", 4, "header.copy-locations"),
            (48, "<Q", SECTORS - 1, "header.usable-range"),
            (72, "<Q", 2**64 - 1, "array.location"),
            (80, "<I", 2**32 - 1, "array.geometry"),
            (84, "<I", 129, "array.geometry"),
        ):
            damaged = bytearray(baseline)
            copy_write(damaged, sector, 1, field, layout, value)
            issue(inspect(damaged), "primary", expected)
        damaged = bytearray(baseline)
        struct.pack_into("<I", damaged, sector + 12, 91)
        issue(inspect(damaged), "primary", "header.size")
        damaged[sector] = 0
        damaged[(SECTORS - 1) * sector] = 0
        check(inspect(damaged)["gptStatus"] == "unreadable", "no readable header")

        # A short entry array can fit while leaving inadequate reserved space.
        damaged = bytearray(baseline)
        copy_write(damaged, sector, 1, 80, "<I", 1)
        copy_write(damaged, sector, 1, 88, "<I", crc32(damaged[2 * sector:2 * sector + ENTRY_SIZE]))
        report = inspect(damaged)
        check(report["gptStatus"] == "divergent" and report["primary"]["valid"], report)
        copy_write(damaged, sector, 1, 40, "<Q", 3)
        issue(inspect(damaged), "primary", "header.usable-range")

        damaged = bytearray(baseline)
        entry = 2 * sector
        damaged[entry + 56:entry + 58] = b"\x00\xd8"
        report = inspect(damaged)
        issue(report, "primary", "array.crc32")
        issue(report, "primary", "partition.invalid-utf16", 1)

        nested = [replace(FIRST, last=180), replace(SECOND, first=80, last=90, id=FIRST.id),
                  replace(SECOND, slot=3, first=100, last=105, id=UUID(int=0)),
                  replace(SECOND, slot=4, first=5, last=50)]
        report = inspect(make_image(nested, sector))
        issue(report, "primary", "partition.duplicate-id", 2)
        issue(report, "primary", "partition.empty-id", 3)
        issue(report, "primary", "partition.overlap", 3)
        issue(report, "primary", "partition.outside-usable-range", 4)

        rng = random.Random(0x475054 + sector)
        for index in range(6):
            parts = [replace(FIRST, slot=slot, first=start, last=start + 4,
                             id=UUID(int=rng.getrandbits(128)), attrs=rng.getrandbits(64),
                             name=f"disk-{index}-\u03a9-{slot}")
                     for slot, start in zip(rng.sample(range(1, 129), 8), range(45, 205, 20))]
            first.write_bytes(make_image(parts, sector))
            rows = invoke("inspect", first, *flags)["primary"]["partitions"]
            for got, part in zip(rows, sorted(parts, key=lambda item: item.slot), strict=True):
                want = dict(slot=part.slot, typeId=str(part.type_id), id=str(part.id),
                            firstLba=part.first, lastLba=part.last, name=part.name,
                            attributesHex=f"{part.attrs:016x}")
                check(got == want, (got, want))

    first.write_bytes(b"\0" * 1023)
    invoke("inspect", first, status=2)
    invoke("inspect", second, "--sector-size", "1024", status=2)
    invoke("inspect", second, "--fail-on-change", status=2)
    invoke("inspect", second, "--sector-size", "4096", "--sector-size", "4096", status=2)
    invoke("inspect", Path(tmp) / "missing.img", status=2)

print(f"{checks} independent checks across 512-byte and 4096-byte GPT disk images")
