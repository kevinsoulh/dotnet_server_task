using System.Text;
using Core.Arango;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Core.Arango.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace server.Controllers;
[ApiController]
[Route("api/v1/auth")]

public class AuthController : ControllerBase
{
    private readonly ArangoContext _arangoContext;

    private new record Response(bool IsSuccess, string Message);
    private record UserClaim(string Type, string Value);
    
    public class SignInRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    public AuthController(ArangoContext arangoContext) {
        _arangoContext = arangoContext;
    }
    
    
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> SignInAsync([FromBody] SignInRequest request)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized(new Response(false, "Please provide both email and password."));
        }

        var user = (await _arangoContext.Query<User>("_system").Where(x => x.Email == request.Email).ToListAsync()).FirstOrDefault();

        if (user?.Email != request.Email)
        {
            return Unauthorized(new Response(false, "Invalid email address"));
        }

        if (!VerifyPassword(request.Password, user?.Password))
        {
            return Unauthorized(new Response(false, "invalid password"));
        }

        var claims = new List<Claim>
        {
            new Claim(type: ClaimTypes.NameIdentifier, value: user?.Id ?? string.Empty),
            new Claim(type: ClaimTypes.Hash, value: (user?.Key).ToString() ?? string.Empty),
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
    
    
    [Authorize]
    [HttpGet("logout")]
    public async Task<IActionResult> SignOutAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Ok(new {message = "Logged out successfully"});
    }

    [Authorize]
    [HttpGet("get-self-auth")]
    public Task<IActionResult> GetSelfAuth()
    {
        var userClaims = User.Claims.Select(x => new UserClaim(x.Type, x.Value)).ToList();

        return Task.FromResult<IActionResult>(Ok(userClaims));
    }

    private static bool VerifyPassword(string password, string? hashedPassword)
    {
        return hashedPassword != null && hashedPassword.Equals(Hash(password));
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
}