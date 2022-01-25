namespace TMF.Auth0.FGA.WebApp.Authorization
{
    public class FgaCredentials
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Audience { get; set; }
        public string GrantType { get; set; }
    }
}
