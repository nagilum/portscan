using System.Text.Json.Serialization;

namespace portscan
{
    internal class PortEntry
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }
    }
}