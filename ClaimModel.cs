using Core.Arango.Linq.Attributes;

namespace server;

[CollectionProperty(CollectionName = "Claims")]
public class ClaimModel : ArangoDocument
{
    public string? UserId { get; set; }
    public int? VehicleVin { get; set; }
    public string? Make { get; set; }
    public string? Model { get; set; }
    public string? Year { get; set; }
    public string? Mileage { get; set; }
    public int? RegistrationNumber { get; set; }
    public string? Description { get; set; }
    public string? DateOfDiscovery { get; set; }
    
    public string? Invoices { get; set; }
}