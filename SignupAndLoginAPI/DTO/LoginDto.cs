using System.ComponentModel.DataAnnotations;

namespace SignupAndLoginAPI.DTOs
{
    public class LoginDto
    {
        [Required]
        [MinLength(3, ErrorMessage = "Username or Email is Required")]
        public string UsernameOrEmail { get; set; } = string.Empty;

        [Required]
        [MinLength(2, ErrorMessage = "Password is required.")]
        public string Password { get; set; } = string.Empty;
    }
}
