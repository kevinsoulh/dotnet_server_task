using System.Text;
using Core.Arango;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace server.Controllers;
[ApiController]
[Route("api/v1/auth")]

public class AuthController : ControllerBase
{
    private readonly ArangoContext _arangoContext;

    public record SignInRequest(string Email, string Password);

    private new record Response(bool IsSuccess, string Message);
    private record UserClaim(string Type, string Value);

    public AuthController(ArangoContext arangoContext) {
        _arangoContext = arangoContext;
    }
    
    //login method
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> SignInAsync([FromBody] SignInRequest request)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest("Please provide both email and password.");
        }
        
        const string emailCheckerQuery = "FOR user IN Users FILTER user.Email == @Email RETURN { _id: user._id, name: user.Name, email: user.Email, password: user.Password }";
        var bindEmailCheckerVars = new Dictionary<string, object?>
        {
            { "Email", request.Email },
        };
        var emailChecker = (await _arangoContext.Query.ExecuteAsync<User>("_system", emailCheckerQuery, bindEmailCheckerVars)).FirstOrDefault();

        const string passwordQuery = "FOR user IN Users FILTER user.Email == @Email && user.Password == @Password RETURN { _id: user._id, name: user.Name, email: user.Email }";
        var bindPasswordVars = new Dictionary<string, object?>
        {
            { "Email", emailChecker?.Email },
            { "Password", emailChecker?.Password }
        };
        var user = (await _arangoContext.Query.ExecuteAsync<User>("_system", passwordQuery, bindPasswordVars)).FirstOrDefault();

        if (user?.Email != request.Email)
        {
            return Unauthorized(new Response(false, "Invalid email address"));
        }

        if (!VerifyPassword(request.Password, emailChecker?.Password))
        {
            return Unauthorized(new Response(false, "invalid password"));
        }

        var claims = new List<Claim>
        {
            new Claim(type: ClaimTypes.NameIdentifier, value: user?.Id ?? string.Empty),
            new Claim(type: ClaimTypes.Name, value: user?.Name ?? string.Empty),
            new Claim(type: ClaimTypes.Email, value: user?.Email ?? string.Empty),
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(43200),
            }
        );
        
        return Ok(new Response(true, "Signed in successfully"));
    }
    
    //logout method
    [Authorize]
    [HttpPost("logout")]
    public async Task SignOutAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Authorize]
    [HttpGet("get-users")]
    public async Task<IActionResult> GetUsers()
    {
        var userClaims = User.Claims.Select(x => new UserClaim(x.Type, x.Value)).ToList();

        return Ok(userClaims);
    }
    
    /*[Authorize]
    [HttpGet("self")]
    public async Task<IActionResult> GetSelf()
    {
        var email = User.Claims.First(x => x.Type == ClaimTypes.Email).Value;
        

        return Ok(userClaims);
    }*/
    
    private static bool VerifyPassword(string password, string? hashedPassword)
    {
        return hashedPassword != null && hashedPassword.Equals(Hash(password));
    }

    [HttpGet("jane_doe")]
    public async Task InsertJaneDoe()
    {
        await _arangoContext.Document.CreateAsync("_system", "Users", new
        {
            Key = Guid.NewGuid(),
            Name = "Jane Doe",
            Email = "janedoe@gmail.com",
            Password = Hash("test"),
            Token = CreateToken()
        });
    }
    
    private static string Hash(string? password, string salt = "")
    {
        // Generate a 128-bit salt using a sequence of
        // cryptographically strong random bytes.
        var saltBytes = Encoding.ASCII.GetBytes(salt);; // divide by 8 to convert bits to bytes

        // derive a 256-bit subkey (use HMACSHA256 with 100,000 iterations)
        var hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password!,
            salt: saltBytes,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        return hash;
    }
    
    private static string CreateToken()
    {
        const string allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_+-=|;:,.<>?";
        var random = new Random();
        var token = new string(Enumerable.Repeat(allowedChars, 45).Select(s => s[random.Next(s.Length)]).ToArray());

        return token;
    }
}