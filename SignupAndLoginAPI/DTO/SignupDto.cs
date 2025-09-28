using System.ComponentModel.DataAnnotations;

namespace SignupAndLoginAPI.DTOs
{
    public class SignupDto
    {
        [Required]
        [MinLength(3, ErrorMessage = "FirstName must be at least 3 characters long.")]
        public string FirstName { get; set; } = string.Empty;
        [Required]
        [MinLength(3, ErrorMessage = "LastName must be at least 3 characters long.")]
        public string LastName { get; set; } = string.Empty;
        [Required]
        [MinLength(6, ErrorMessage = "Username must be at least 6 characters long.")]
        [RegularExpression(@"^(?=.*\d)(?=.*[\W_]).+$",
        ErrorMessage = "Username must include at least one number and one special character.")]
        public string Username { get; set; } = string.Empty;
        [Required]
        [Range(1000000000, 9999999999, ErrorMessage = "Phone number must be a 10-digit number.")]
        public long PhoneNumber { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
