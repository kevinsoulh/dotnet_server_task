using System.Security.Claims;
using System.Web;
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
                return BadRequest("Please provide all requested information");
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
                DateOfDiscovery = request.DateOfDiscovery
            });

            return Ok(new {message = "Claim registered successfully"});
        }
        catch (Exception e)
        {
            return BadRequest("There was an error registering you new claim: " + e);
        }
    }

    [Authorize]
    [HttpPut("update-claim/{claimId}")]
    public async Task<IActionResult> Update([FromBody] ClaimModel claim, [FromRoute] string claimId)
    {
        try
        {
            var decodedClaimId = HttpUtility.UrlDecode(claimId);
        
            if (decodedClaimId != claim.Id)
            {
                return BadRequest("Id can't be changed");
            }
            
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
}