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
                return BadRequest("Passwords do not match.");

            var existingUser = await _firestore.GetUserByEmailAsync(dto.Email);
            if (existingUser != null)
                return BadRequest("Email already exists.");
            var existingusername = await _firestore.GetUserByEmailAsync(dto.Username);
            if (existingusername != null)
                return BadRequest("Username already exists.");

            var passwordHash = Convert.ToBase64String(
                Encoding.UTF8.GetBytes(dto.Password)
            );

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
    }
}
