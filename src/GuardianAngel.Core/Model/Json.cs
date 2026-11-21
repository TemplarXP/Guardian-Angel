using System.Text.Json;
using System.Text.Json.Serialization;

namespace GuardianAngel.Core.Model;

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32,
    };

    public static JsonElement ToElement<T>(T value) => JsonSerializer.SerializeToElement(value, Options);
    public static T? FromElement<T>(JsonElement e) => e.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
        ? default
        : e.Deserialize<T>(Options);

    public static T? FromElement<T>(JsonElement? e) => e is null ? default : FromElement<T>(e.Value);
}
