using Google.Apis.Auth;
using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SignupAndLoginAPI.DTOs;
using SignupAndLoginAPI.Models;
using SignupAndLoginAPI.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace SignupAndLoginAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly FirestoreService _firestore;
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config, FirestoreService firestore)
        {
            _config = config;
            _firestore = firestore;
        }


        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody] SignupDto dto)
        {
            if (dto.Password != dto.ConfirmPassword)
            {
                ModelState.AddModelError("ConfirmPassword", "Passwords do not match.");
                return ValidationProblem(ModelState);
            }

            if (await _firestore.GetUserByEmailAsync(dto.Email) != null)
            {
                ModelState.AddModelError("Email", "Email already exists.");
                return ValidationProblem(ModelState);
            }

            if (await _firestore.GetUserByUsernameAsync(dto.Username) != null)
            {
                ModelState.AddModelError("Username", "Username already exists.");
                return ValidationProblem(ModelState);
            }

            var passwordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            var newUser = new User
            {
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                Username = dto.Username,
                PhoneNumber = dto.PhoneNumber,
                Email = dto.Email,
                PasswordHash = passwordHash
            };

            await _firestore.AddUserAsync(newUser);

            return Ok(new
            {
                Message = "Signup successful",
                UserId = newUser.Id,
                newUser.FirstName,
                newUser.LastName,
                newUser.Username,
                newUser.PhoneNumber,
                newUser.Email
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto dto)
        {

            var user = await _firestore.GetUserByUsernameOrEmailAsync(dto.UsernameOrEmail);
            
            if (user == null)
            {
                ModelState.AddModelError("UsernameOrEmail", "Invalid username or email.");
                return ValidationProblem(ModelState);
            }
            else if (user.Username != dto.UsernameOrEmail)
            {
                if (user.Email != dto.UsernameOrEmail)
                {
                    ModelState.AddModelError("UsernameOrEmail", "Username or Email is required");
                    return ValidationProblem(ModelState);
                }

            }

            if (dto.Password == null)
            {
                ModelState.AddModelError("Password", "Inavlid Password");
                return ValidationProblem(ModelState);
            }
            else if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
            {
                ModelState.AddModelError("Password", "Password is required");
                return ValidationProblem(ModelState);
            }

            var claims = new[]
             {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims: claims,
                expires: DateTime.Now.AddHours(2),
                signingCredentials: creds
            );
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                username = user.Username
            });
            
            //catch
            //{
            //    //// For now just success, later return JWT
            //    return Ok(new { message = "Login successful", username = user.Username });
            //    ////return Redirect($"https://electionui-814747071660.us-central1.run.app/home?msg=success&&email={user.Username}"); 
            //}
        }


        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            var clientId = _config["GoogleAuth:ClientId"];
            var redirectUri = _config["GoogleAuth:RedirectUri"];

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
            {
                return StatusCode(500, "GoogleAuth settings are missing in configuration.");
            }

            var url = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                      $"response_type=code&" +
                      $"client_id={clientId}&" +
                      $"redirect_uri={redirectUri}&" +
                      $"scope=openid%20email%20profile";

            return Redirect(url);
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback(string code)
        {
            var clientId = _config["GoogleAuth:ClientId"];
            var clientSecret = _config["GoogleAuth:ClientSecret"];
            var redirectUri = _config["GoogleAuth:RedirectUri"];

            using var client = new HttpClient();
            var tokenResponse = await client.PostAsync("https://oauth2.googleapis.com/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
            {"code", code},
            {"client_id", clientId},
            {"client_secret", clientSecret},
            {"redirect_uri", redirectUri},
            {"grant_type", "authorization_code"}
                }));

            var payload = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
            var idToken = payload.GetProperty("id_token").GetString();

            // Decode the token
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(idToken);
            var email = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;

            // 🔥 Your custom redirect to Blazor
            var jwtString = handler.WriteToken(jwt);
            return Redirect($":https://electionui-814747071660.us-central1.run.app/google-redirect?token={jwtString}");
        }

    }


}



