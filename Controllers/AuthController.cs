using System.Security.Cryptography;
using System.Text;
using Core.Arango;
using Core.Arango.Linq;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace server.Controllers;
[ApiController]
[Route("api/v1/auth")]

public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    
    private readonly IConfiguration _config;
    private readonly ArangoContext _arangoContext;

    public AuthController(ILogger<AuthController> logger, ArangoContext arangoContext, IConfiguration config) {
        _logger = logger;
        _arangoContext = arangoContext;
        _config = config;
    }
    
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest("Please provide both email and password.");
        }
    
        const string query = "FOR user IN Users FILTER user.Email == @Email && user.Password == @Password RETURN user";
        var bindVars = new Dictionary<string, object?>
        {
            { "Email", request.Email },
            { "Password", Hash(request.Password) }
        };
    
        var user = await _arangoContext.Query.ExecuteAsync<User>("_system", query, bindVars);
        if (user == null || !user.Any())
        {
            return Unauthorized("Invalid email or password.");
        }

        if (!VerifyPassword(request.Password, user.FirstOrDefault()?.Password))
        {
            return Unauthorized("Invalid email or password.");
        }

        var tokenString = GenerateJwtToken(user.FirstOrDefault());
    
        // save token in the database
        const string updateQuery = "FOR user IN Users FILTER user.Email == @Email UPDATE { _key: user._key, Token: @Token } IN Users";
        var updateBindVars = new Dictionary<string, object?>
        {
            { "Email", request.Email },
            { "Token", tokenString }
        };
        await _arangoContext.Query.ExecuteAsync<object>("_system", updateQuery, updateBindVars);

        return Ok(new { Token = tokenString });
    }

    
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromHeader] LogoutRequest request)
    {
        const string query = "FOR user IN Users FILTER user.Token == @Token UPDATE { _key: user._key, Token: @Token } IN Users";
        var logoutBindVars = new Dictionary<string, object?>
        {
            { "Token", request.Token }
        };
        
        var result = await _arangoContext.Query.ExecuteAsync<User>("_system", query, logoutBindVars);
            
        if (result == null) return BadRequest("There was an error while attempting to logout"); 

        return Ok("Successfully logged out");
    }
    
    private static bool VerifyPassword(string password, string? hashedPassword)
    {
        // Your password verification logic here
        return Hash(password) == hashedPassword;
    }
    
    private string GenerateJwtToken(User? user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_config["Jwt:Secret"] ?? string.Empty);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user?.Name ?? string.Empty)
            }),
            Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["Jwt:ExpireMinutes"])),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /*[HttpPost("login")]
    public async Task<dynamic?> Login([FromBody] LoginRequest request)
    {
        //var email = bool.Parse((await _arangoContext.Query.ExecuteAsync<string>("_system", $"FOR u IN Users RETURN u.Email == {request.Email}")).First());
        //var password = bool.Parse((await _arangoContext.Query.ExecuteAsync<string>("_system", $"FOR u IN Users RETURN u.Password = {request.Password}")).First());

        if (request.Email == null || request.Password == null) return null;
        
        var requestUser = await _arangoContext.Query.ExecuteAsync<User>("_system", $"FOR user IN Users FILTER user.Email == {request.Email} RETURN user");
        
        if (requestUser == null) return BadRequest("There was an error while attempting to login");
        
        var user = requestUser.First();
        
        var hash = Hash(request.Password);

        if (request.Email != user.Email?.ToString())
        {
            return BadRequest($"Email '{request.Email}' not found.");
        }

        if (hash != user.Password?.ToString())
        {
            return BadRequest("Password incorrect."); 
        }
        
        return user;
    }*/

    /*[HttpGet("logout")]
    public async Task<dynamic?> Logout([FromHeader] LogoutRequest request)
    {
        if (request.Token == null) return null;

        return "Successfully logged out";
    }*/

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

    public class LoginRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
    }

    public class LogoutRequest
    {
        public string? Token { get; set; }
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