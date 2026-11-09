namespace GptGuard;

internal sealed record PartitionChange(
    string Kind, Guid Id, IReadOnlyList<string> Fields, Partition? Before, Partition? After);

internal sealed record Comparison(
    IReadOnlyList<string> DiskFields, IReadOnlyList<PartitionChange> Partitions)
{
    public bool Changed => DiskFields.Count != 0 || Partitions.Count != 0;
}

internal static class LayoutComparison
{
    public static Comparison Compare(AuditReport before, AuditReport after)
    {
        GptHeader a = before.Primary.Header!;
        GptHeader b = after.Primary.Header!;
        List<string> diskFields = [];
        if (a.DiskId != b.DiskId) diskFields.Add("disk-id");
        if (before.TotalSectors != after.TotalSectors) diskFields.Add("disk-size");
        if (a.FirstUsableLba != b.FirstUsableLba || a.LastUsableLba != b.LastUsableLba)
            diskFields.Add("usable-range");
        if (a.HeaderSize != b.HeaderSize || a.Revision != b.Revision) diskFields.Add("header-format");
        if (a.EntryCount != b.EntryCount || a.EntrySize != b.EntrySize) diskFields.Add("entry-geometry");

        Dictionary<Guid, Partition> oldParts = before.Primary.Partitions.ToDictionary(partition => partition.Id);
        Dictionary<Guid, Partition> newParts = after.Primary.Partitions.ToDictionary(partition => partition.Id);
        List<PartitionChange> changes = [];
        foreach (Guid id in oldParts.Keys.Union(newParts.Keys).Order())
        {
            oldParts.TryGetValue(id, out Partition? oldPart);
            newParts.TryGetValue(id, out Partition? newPart);
            if (oldPart is null)
            {
                changes.Add(new("added", id, [], null, newPart));
                continue;
            }
            if (newPart is null)
            {
                changes.Add(new("removed", id, [], oldPart, null));
                continue;
            }

            List<string> fields = [];
            if (oldPart.Slot != newPart.Slot) fields.Add("slot");
            if (oldPart.TypeId != newPart.TypeId) fields.Add("type-id");
            if (oldPart.FirstLba != newPart.FirstLba || oldPart.LastLba != newPart.LastLba)
                fields.Add("extent");
            if (oldPart.AttributesHex != newPart.AttributesHex) fields.Add("attributes");
            if (oldPart.Name != newPart.Name) fields.Add("name");
            if (fields.Count != 0)
                changes.Add(new("modified", id, fields, oldPart, newPart));
        }
        return new(diskFields, changes);
    }
}
