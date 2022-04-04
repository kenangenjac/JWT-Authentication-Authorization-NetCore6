using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using JWT_NetCore6.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;

namespace JWT_NetCore6.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User User = new();
        private readonly IConfiguration _configuration;

        /// <summary>
        /// DI for injecting configuration to access appsettings.json
        /// </summary>
        /// <param name="configuration"></param>
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Method to register a user and create a passwordHash and passwordSalt
        /// </summary>
        /// <param name="request"></param>
        /// <returns>User object</returns>
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            
            User.Username = request.Username;
            User.PasswordHash = passwordHash;
            User.PasswordSalt = passwordSalt;

            return Ok(User);
        }

        /// <summary>
        /// Login method that returns a JWT
        /// </summary>
        /// <param name="request"></param>patr
        /// <returns>string value</returns>
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (User.Username != request.Username)
            {
                return BadRequest("User not found");
            }

            if (!VerifyPasswordHash(request.Password, User.PasswordHash, User.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            string token = CreateToken(User);
            return Ok(token);
        }

        /// <summary>
        /// Method to create a JSON Web Token
        /// </summary>
        /// <param name="user"></param>
        /// <returns>string value</returns>
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                // claims are properties that are describing the user that is being authenticated 
                // and they can store userId or userEmail, username etc.
                // they are contained in the token and can be read on the client side
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Role, "Admin"),
            };

            // accessing token key in appsettings.json
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            // creating signing credentials 
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // defining the payload of the JWT
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );

            // creating the JWT
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }



        /// <summary>
        /// Method to create a passwordHash and a passwordSalt for a registered user
        /// </summary>
        /// <param name="password"></param>
        /// <param name="passwordHash"></param>
        /// <param name="passwordSalt"></param>
        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        /// <summary>
        /// Method that hashes the provided password from request and check weather it corresponds to the provided passwordHash of a user
        /// </summary>
        /// <param name="password"></param>
        /// <param name="passwordHash"></param>
        /// <param name="passwordSalt"></param>
        /// <returns>bool value</returns>
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
