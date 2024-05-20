namespace AngularAuthWebApi.Models.DTO
{
    public record ResetEmailDTO
    {
        public string Email { get; set; }
        public string EmailToken { get; set; }
        public string NewPassword { get; set; }
        public string ConfrimPassword { get; set; } 
    }
}
