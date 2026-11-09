using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace GptGuard;

internal sealed class ImageReader(Stream image, int sectorSize)
{
    private const uint MaxEntries = 16_384;
    private const int MaxArrayBytes = 16 * 1024 * 1024;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);

    public AuditReport Audit()
    {
        if (!image.CanSeek || sectorSize is not (512 or 4096))
            throw new InvalidDataException("A seekable image and 512-byte or 4096-byte sectors are required.");
        long size = image.Length;
        if (size % sectorSize != 0 || size / sectorSize < 6)
            throw new InvalidDataException("Image size must be a whole number of sectors, with at least six sectors.");

        ulong sectors = (ulong)(size / sectorSize);
        ulong last = sectors - 1;
        List<Issue> protective = CheckMbr(Read(0, sectorSize), last);
        TableCopy primary = ReadCopy(1, last, true);
        TableCopy backup = ReadCopy(last, last, false);
        List<string> differences = primary.Valid && backup.Valid ? CompareCopies(primary, backup) : [];
        string status = (primary.Valid, backup.Valid, differences.Count) switch
        {
            (true, true, 0) => "consistent",
            (true, true, _) => "divergent",
            (true, false, _) => "primary-only",
            (false, true, _) => "backup-only",
            _ => "unreadable"
        };
        if (image.Length != size)
            throw new IOException("Image length changed during inspection.");
        return new(sectorSize, sectors, status, status == "consistent" && protective.Count == 0,
                   protective, differences, primary, backup);
    }

    private static List<Issue> CheckMbr(ReadOnlySpan<byte> sector, ulong last)
    {
        List<Issue> issues = [];
        if (U16(sector, 510) != 0xaa55)
            issues.Add(new("mbr.signature"));
        int protective = 0;
        for (int slot = 0; slot < 4; slot++)
        {
            ReadOnlySpan<byte> entry = sector.Slice(446 + 16 * slot, 16);
            if (entry[4] == 0xee)
            {
                protective++;
                if (entry[0] != 0 || U32(entry, 8) != 1 || U32(entry, 12) != Math.Min(last, uint.MaxValue))
                    issues.Add(new("mbr.protective-range", slot + 1));
            }
            else if (entry.ContainsAnyExcept((byte)0))
                issues.Add(new("mbr.non-protective-entry", slot + 1));
        }
        if (protective != 1)
            issues.Add(new("mbr.protective-count"));
        return issues;
    }

    private TableCopy ReadCopy(ulong location, ulong last, bool primary)
    {
        byte[] sector = Read(location, sectorSize);
        List<Issue> issues = [];
        if (!sector.AsSpan(0, 8).SequenceEqual("EFI PART"u8))
            return new(location, null, null, [], [new("header.signature")]);

        var header = new GptHeader(
            U32(sector, 8), U32(sector, 12), U32(sector, 16), U64(sector, 24), U64(sector, 32),
            U64(sector, 40), U64(sector, 48), new Guid(sector.AsSpan(56, 16)),
            U64(sector, 72), U32(sector, 80), U32(sector, 84), U32(sector, 88));
        if (header.Revision != 0x00010000)
            issues.Add(new("header.revision"));
        if (U32(sector, 20) != 0)
            issues.Add(new("header.reserved"));
        if (header.HeaderSize < 92 || header.HeaderSize > sectorSize)
            issues.Add(new("header.size"));
        else
        {
            sector.AsSpan(16, 4).Clear();
            if (Crc32.Compute(sector.AsSpan(0, (int)header.HeaderSize)) != header.HeaderCrc)
                issues.Add(new("header.crc32"));
        }
        if (header.CurrentLba != location || header.AlternateLba != (primary ? last : 1UL))
            issues.Add(new("header.copy-locations"));
        if (header.DiskId == Guid.Empty)
            issues.Add(new("header.empty-disk-id"));

        bool usable = header.FirstUsableLba >= 2 && header.LastUsableLba < last &&
                      header.FirstUsableLba <= header.LastUsableLba;
        if (!usable)
            issues.Add(new("header.usable-range"));

        ulong bytes = (ulong)header.EntryCount * header.EntrySize;
        if (header.EntryCount is 0 or > MaxEntries || header.EntrySize < 128 ||
            !uint.IsPow2(header.EntrySize) || bytes > MaxArrayBytes)
        {
            issues.Add(new("array.geometry"));
            return new(location, header, null, [], issues);
        }

        ulong span = (bytes + (uint)sectorSize - 1) / (uint)sectorSize;
        ulong start = header.EntryLba;
        bool inRange = start >= 2 && start < last && span <= last - start;
        bool outsideUsable = usable && (primary ? inRange && start + span <= header.FirstUsableLba
                                                 : start > header.LastUsableLba);
        if (!inRange || !outsideUsable)
        {
            issues.Add(new("array.location"));
            return new(location, header, null, [], issues);
        }

        byte[] entries = Read(start, (int)bytes);
        if (Crc32.Compute(entries) != header.ArrayCrc)
            issues.Add(new("array.crc32"));
        string digest = Convert.ToHexStringLower(SHA256.HashData(entries));
        return new(location, header, digest, ReadPartitions(entries, header, issues), issues);
    }

    private static List<Partition> ReadPartitions(byte[] entries, GptHeader header, List<Issue> issues)
    {
        List<Partition> partitions = [];
        HashSet<Guid> ids = [];
        int entrySize = (int)header.EntrySize;
        for (int offset = 0, slot = 1; offset < entries.Length; offset += entrySize, slot++)
        {
            ReadOnlySpan<byte> entry = entries.AsSpan(offset, entrySize);
            var type = new Guid(entry[..16]);
            if (type == Guid.Empty)
                continue;

            var id = new Guid(entry.Slice(16, 16));
            if (id == Guid.Empty)
                issues.Add(new("partition.empty-id", slot));
            else if (!ids.Add(id))
                issues.Add(new("partition.duplicate-id", slot));

            ulong first = U64(entry, 32);
            ulong last = U64(entry, 40);
            if (first > last || first < header.FirstUsableLba || last > header.LastUsableLba)
                issues.Add(new("partition.outside-usable-range", slot));
            string attributes = U64(entry, 48).ToString("x16", CultureInfo.InvariantCulture);

            ReadOnlySpan<byte> label = entry.Slice(56, 72);
            int length = 0;
            while (length < label.Length && U16(label, length) != 0)
                length += 2;
            string name = "";
            try
            {
                name = StrictUtf16.GetString(label[..length]);
            }
            catch (DecoderFallbackException)
            {
                issues.Add(new("partition.invalid-utf16", slot));
            }
            partitions.Add(new(slot, type, id, first, last, attributes, name));
        }

        // Sort intervals, then track the furthest end. Nested extents still
        // overlap even if the immediately preceding extent ends earlier.
        ulong? furthest = null;
        foreach (Partition partition in partitions
            .Where(partition => partition.FirstLba <= partition.LastLba)
            .OrderBy(partition => partition.FirstLba).ThenBy(partition => partition.Slot))
        {
            if (furthest.HasValue && partition.FirstLba <= furthest.Value)
                issues.Add(new("partition.overlap", partition.Slot));
            furthest = Math.Max(furthest.GetValueOrDefault(), partition.LastLba);
        }
        return partitions;
    }

    private static List<string> CompareCopies(TableCopy primary, TableCopy backup)
    {
        GptHeader a = primary.Header!;
        GptHeader b = backup.Header!;
        List<string> fields = [];
        if (a.DiskId != b.DiskId) fields.Add("disk-id");
        if (a.FirstUsableLba != b.FirstUsableLba || a.LastUsableLba != b.LastUsableLba) fields.Add("usable-range");
        if (a.Revision != b.Revision || a.HeaderSize != b.HeaderSize) fields.Add("header-format");
        if (a.EntryCount != b.EntryCount || a.EntrySize != b.EntrySize) fields.Add("entry-geometry");
        if (primary.ArraySha256 != backup.ArraySha256) fields.Add("entry-array");
        return fields;
    }

    private byte[] Read(ulong sector, int length)
    {
        image.Position = checked((long)sector * sectorSize);
        byte[] bytes = new byte[length];
        image.ReadExactly(bytes);
        return bytes;
    }

    private static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]);
    private static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
    private static ulong U64(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]);
}
