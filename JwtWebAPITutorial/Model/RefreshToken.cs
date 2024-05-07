namespace JwtWebAPITutorial.Model
{
    public class RefreshToken
    {
        //public string TokenID { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime Expires { get; set; } = DateTime.UtcNow.AddDays(1);
    }
}
