using System.Security.Claims;
using System.Web;
using Bogus;
using Core.Arango;
using Core.Arango.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace server.Controllers;
[ApiController]
[Route("api/v1/claims")]

public class ClaimController : ControllerBase
{
    private readonly ArangoContext _arangoContext;

    public ClaimController(ArangoContext arangoContext)
    {
        _arangoContext = arangoContext;
    }

    [Authorize]
    [HttpGet("get-claims")]
    public async Task<IActionResult> GetClaims()
    {
        try
        {
            var userId = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
        
            var claims = await _arangoContext.Query<ClaimModel>("_system").Where(x => x.UserId == userId).ToListAsync();

            return Ok(claims);
        }
        catch (Exception e)
        {
            return BadRequest("An error has occurred: " + e);
        }
    }

    [Authorize]
    [HttpPost("store-claim")]
    public async Task<IActionResult> Store([FromBody] ClaimModel request)
    {
        try
        {
            if (request is { VehicleVin: null, Make: null, Model: null, Year: null, Mileage: null, RegistrationNumber: null, Description: null, DateOfDiscovery: null })
            {
                return BadRequest("Please provide all required information");
            }
            
            await _arangoContext.Document.CreateAsync("_system", "Claims", new
            {
                Key = Guid.NewGuid(),
                UserId = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value,
                VehicleVin = request.VehicleVin,
                Make = request.Make,
                Model = request.Model,
                Year = request.Year,
                Mileage = request.Mileage,
                RegistrationNumber = request.RegistrationNumber,
                Description = request.Description,
                DateOfDiscovery = request.DateOfDiscovery,
                Status = request.Status
            });

            return Ok(new {message = "Claim registered successfully"});
        }
        catch (Exception e)
        {
            return BadRequest("There was an error registering you new claim: " + e);
        }
    }

    [Authorize]
    [HttpPut("update-claim")]
    public async Task<IActionResult> Update([FromBody] ClaimModel claim)
    {
        try
        {
            await _arangoContext.Document.UpdateAsync("_system", "Claims", claim);
            
            return Ok(new {message = "Claim updated successfully"});
        }
        catch (Exception e)
        {
            return BadRequest("There was an error updating your claim: " + e);
        }
    }

    [Authorize]
    [HttpDelete("delete-claim/{claimId}")]
    public async Task<IActionResult> Delete(string claimId)
    {
        try
        {
            var decodedClaimId = HttpUtility.UrlDecode(claimId);
            
            await _arangoContext.Query<ClaimModel>("_system").Where(x => x.Id == decodedClaimId).Remove().In<ClaimModel>().Select(x => x.Key).ToListAsync();

            return Ok(new {message = "Claim deleted successfully"});
        }
        catch (Exception e)
        {
            return BadRequest("There was an error deleting your claim: " + e);
        }
    }

    [Authorize]
    [HttpPost("generate-claims")]
    public async Task<IActionResult> GenerateClaims()
    {
        try
        {
            var faker = new Faker<ClaimModel>()
                .RuleFor(c => c.VehicleVin, f => f.Vehicle.Vin())
                .RuleFor(c => c.Make, f => f.Vehicle.Manufacturer())
                .RuleFor(c => c.Model, f => f.Vehicle.Model())
                .RuleFor(c => c.Year, f => new Random().Next(1950, DateTime.Now.Year + 1))
                .RuleFor(c => c.Mileage, f => f.Random.Number(10000, 100000))
                .RuleFor(c => c.RegistrationNumber, f => GenerateRandomRegistrationNumber())
                .RuleFor(c => c.Description, f => f.Lorem.Sentence())
                .RuleFor(c => c.DateOfDiscovery, f => f.Date.Past().ToString("yyyy-MM-dd"))
                .RuleFor(c => c.Status, f => f.Random.Bool());

            var userId = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

            var claims = faker.Generate(10);

            foreach (var claim in claims)
            {
                claim.Key = Guid.NewGuid();
                claim.UserId = userId;
                await _arangoContext.Document.CreateAsync("_system", "Claims", claim);
            }

            return Ok(new { message = "Claims generated successfully" });
        }
        catch (Exception e)
        {
            return BadRequest("There was an error generating claims: " + e);
        }
    }

    private string GenerateRandomRegistrationNumber()
    {
        const string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var random = new Random();

        var letterPart = new string(Enumerable.Repeat(letters, 5)
            .Select(s => s[random.Next(s.Length)]).ToArray()).ToUpper();

        var numberPart = random.Next(100, 1000).ToString();

        return letterPart + numberPart;
    }
}