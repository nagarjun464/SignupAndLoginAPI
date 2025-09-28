namespace SignupAndLoginAPI.DTOs
{
    public class SignupDto
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public int PhoneNumber { get; set; } 
        public string Email { get; set; } = string.Empty;

        // Security
        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
