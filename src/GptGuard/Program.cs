using System.Text.Json;

namespace GptGuard;

internal static class Program
{
    private const string Help = """
        gptguard inspect IMAGE [--sector-size 512|4096]
        gptguard compare BEFORE AFTER [--sector-size 512|4096] [--fail-on-change]

        Output is JSON. Exit 0 is success, 2 is a usage or input error,
        3 is an unhealthy image, and 4 is a requested layout-change gate.
        """;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static int Main(string[] args)
    {
        if (args is ["--help"] or ["-h"])
        {
            Console.WriteLine(Help);
            return 0;
        }
        if (args is ["--version"])
        {
            Console.WriteLine(typeof(Program).Assembly.GetName().Version?.ToString(3) + "-preview");
            return 0;
        }

        try
        {
            bool compare = args.Length > 0 && args[0] == "compare";
            int required = compare ? 3 : 2;
            if (args.Length < required || (!compare && args[0] != "inspect")
                || args[1].StartsWith("--", StringComparison.Ordinal)
                || (compare && args[2].StartsWith("--", StringComparison.Ordinal)))
                throw new ArgumentException(Help);

            int sectorSize = 512;
            bool seenSector = false;
            bool gate = false;
            for (int index = required; index < args.Length; index++)
            {
                if (args[index] == "--sector-size" && !seenSector && index + 1 < args.Length
                    && args[index + 1] is "512" or "4096")
                {
                    seenSector = true;
                    sectorSize = args[++index] == "512" ? 512 : 4096;
                }
                else if (args[index] == "--fail-on-change" && compare && !gate)
                    gate = true;
                else
                    throw new ArgumentException("Invalid, incomplete, or repeated option. See --help.");
            }

            AuditReport before = Inspect(args[1], sectorSize);
            if (!compare)
            {
                Write(before);
                return before.Healthy ? 0 : 3;
            }

            AuditReport after = Inspect(args[2], sectorSize);
            if (!before.Healthy || !after.Healthy)
            {
                Write(new { before, after, comparison = (Comparison?)null });
                return 3;
            }

            Comparison result = LayoutComparison.Compare(before, after);
            Write(new { before, after, comparison = result });
            return gate && result.Changed ? 4 : 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
                                     or InvalidDataException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"gptguard: {error.Message}");
            return 2;
        }
    }

    private static AuditReport Inspect(string path, int sectorSize)
    {
        using var image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return new ImageReader(image, sectorSize).Audit();
    }

    private static void Write<T>(T value) => Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));
}
