namespace GptGuard;

internal sealed record Issue(string Code, int? Slot = null);

internal sealed record GptHeader(
    uint Revision, uint HeaderSize, uint HeaderCrc, ulong CurrentLba, ulong AlternateLba,
    ulong FirstUsableLba, ulong LastUsableLba, Guid DiskId, ulong EntryLba,
    uint EntryCount, uint EntrySize, uint ArrayCrc);

internal sealed record Partition(
    int Slot, Guid TypeId, Guid Id, ulong FirstLba, ulong LastLba,
    string AttributesHex, string Name);

internal sealed record TableCopy(
    ulong Location, GptHeader? Header, string? ArraySha256,
    IReadOnlyList<Partition> Partitions, IReadOnlyList<Issue> Issues)
{
    public bool Valid => Issues.Count == 0;
}

internal sealed record AuditReport(
    int SectorSize, ulong TotalSectors, string GptStatus, bool Healthy,
    IReadOnlyList<Issue> ProtectiveMbrIssues, IReadOnlyList<string> CopyDifferences,
    TableCopy Primary, TableCopy Backup);
