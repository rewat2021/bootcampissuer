using Newtonsoft.Json;

namespace IssuerAPI.Models
{
    public class VcTypeMetaModel
    {
    }

    // ============================================================
    // 1. Models
    // ============================================================

    public record VctTypeMetadata
    {
        [JsonProperty("vct")]
        public required string Vct { get; init; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string? Name { get; init; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string? Description { get; init; }

        [JsonProperty("extends", NullValueHandling = NullValueHandling.Ignore)]
        public string? Extends { get; init; }

        [JsonProperty("display", NullValueHandling = NullValueHandling.Ignore)]
        public List<DisplayMetadata>? Display { get; init; }

        [JsonProperty("claims", NullValueHandling = NullValueHandling.Ignore)]
        public List<ClaimMetadata>? Claims { get; init; }
    }

    public record DisplayMetadata
    {
        [JsonProperty("lang")]
        public required string Lang { get; init; }

        [JsonProperty("name")]
        public required string Name { get; init; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string? Description { get; init; }

        [JsonProperty("rendering", NullValueHandling = NullValueHandling.Ignore)]
        public RenderingMetadata? Rendering { get; init; }
    }

    public record RenderingMetadata
    {
        [JsonProperty("simple", NullValueHandling = NullValueHandling.Ignore)]
        public SimpleRendering? Simple { get; init; }
    }

    public record SimpleRendering
    {
        [JsonProperty("logo", NullValueHandling = NullValueHandling.Ignore)]
        public LogoMetadata? Logo { get; init; }

        [JsonProperty("background_color", NullValueHandling = NullValueHandling.Ignore)]
        public string? BackgroundColor { get; init; }

        [JsonProperty("text_color", NullValueHandling = NullValueHandling.Ignore)]
        public string? TextColor { get; init; }
    }

    public record LogoMetadata
    {
        [JsonProperty("uri")]
        public required string Uri { get; init; }

        [JsonProperty("alt_text", NullValueHandling = NullValueHandling.Ignore)]
        public string? AltText { get; init; }
    }

    public record ClaimMetadata
    {
        /// <summary>JSON path เช่น ["student_id"] หรือ ["address", "city"]</summary>
        [JsonProperty("path")]
        public required List<string> Path { get; init; }  // เปลี่ยนจาก List<object>

        [JsonProperty("display", NullValueHandling = NullValueHandling.Ignore)]
        public List<ClaimDisplayMetadata>? Display { get; init; }

        [JsonProperty("mandatory", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Mandatory { get; init; }

        [JsonProperty("sd", NullValueHandling = NullValueHandling.Ignore)]
        public bool? Sd { get; init; }
    }

    public record ClaimDisplayMetadata
    {
        [JsonProperty("lang")]
        public required string Lang { get; init; }

        [JsonProperty("label")]
        public required string Label { get; init; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string? Description { get; init; }
    }
}
