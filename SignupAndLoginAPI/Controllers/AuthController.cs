using Google.Cloud.Firestore;
using Microsoft.AspNetCore.Mvc;
using SignupAndLoginAPI.DTOs;
using SignupAndLoginAPI.Models;
using SignupAndLoginAPI.Services;
using System.Text;

namespace SignupAndLoginAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly FirestoreService _firestore;

        public AuthController(FirestoreService firestore)
        {
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
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _firestore.GetUserByUsernameOrEmailAsync(dto.UsernameOrEmail);
            if (user == null)
                return Unauthorized(new { error = "Invalid username or email." });

            // ✅ Verify hashed password
            if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized(new { error = "Invalid password." });

            // For now just success, later return JWT
            return Ok(new { message = "Login successful", username = user.Username });
        }
    }
}

