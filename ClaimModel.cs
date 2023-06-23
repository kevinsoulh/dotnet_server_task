using Core.Arango.Linq.Attributes;

namespace server;

[CollectionProperty(CollectionName = "Claims")]
public class ClaimModel : ArangoDocument
{
    public string? UserId { get; set; }
    public string? VehicleVin { get; set; }
    public string? Make { get; set; }
    public string? Model { get; set; }
    public int? Year { get; set; }
    public int? Mileage { get; set; }
    public string? RegistrationNumber { get; set; }
    public string? Description { get; set; }
    public string? DateOfDiscovery { get; set; }
    public bool Status { get; set; }
}