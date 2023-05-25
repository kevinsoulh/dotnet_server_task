using Core.Arango.Linq.Attributes;

namespace server;

[CollectionProperty(CollectionName = "Users")]
public class User : ArangoDocument
{
    public string? Name { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
}