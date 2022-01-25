using JorgeSerrano.Json;
using Microsoft.Identity.Web;
using System.Net.Http.Headers;
using System.Text.Json;

namespace TMF.Auth0.FGA.WebApp.Authorization
{
    public class FgaAuthorizationHandler
    {
        private readonly HttpClient _httpClient;
        private readonly IHttpContextAccessor _context;
        private readonly IConfiguration _configuration;

        public FgaAuthorizationHandler(HttpClient httpClient,
                                    IHttpContextAccessor context,
                                    IConfiguration configuration)
        {
            _httpClient = httpClient;
            _context = context;
            _configuration = configuration;
        }

        public async Task<bool> CheckIfActionAllowedAsync(string relation)
        {
            var userId = _context.HttpContext.User.FindFirst(ClaimConstants.NameIdentifierId).Value;

            var verificationRequest = new VerificationRequest
            {
                TupleKey = new TupleKey
                {
                    Object = "prescription:p-1234",
                    Relation = relation,
                    User = userId
                }
            };

            var accessToken = await GetTokenAsync();
            if (accessToken != null)
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var options = new JsonSerializerOptions { PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy() };

                var response = await _httpClient.PostAsJsonAsync(_configuration.GetValue<string>("Auth0FgaConfiguration:VerificationEndpoint"),
                                                                 verificationRequest,
                                                                 options);
                var responseBody = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    var authorizationVerificationResponse = JsonSerializer.Deserialize<AuthorizationVerificationResponse>(responseBody, options);
                    return authorizationVerificationResponse.Allowed;
                }
            }

            return false;
        }

        private async Task<string> GetTokenAsync()
        {
            var fgaCredentials = new FgaCredentials
            {
                ClientId = _configuration.GetValue<string>("Auth0FgaConfiguration:ClientId"),
                ClientSecret = _configuration.GetValue<string>("Auth0FgaConfiguration:ClientSecret"),
                Audience = _configuration.GetValue<string>("Auth0FgaConfiguration:Audience"),
                GrantType = _configuration.GetValue<string>("Auth0FgaConfiguration:GrantType")
            };
            var options = new JsonSerializerOptions { PropertyNamingPolicy = new JsonSnakeCaseNamingPolicy() };

            var response = await _httpClient.PostAsJsonAsync(_configuration.GetValue<string>("Auth0FgaConfiguration:TokenEndpoint"),
                                                             fgaCredentials,
                                                             options);
            var responseBody = await response.Content.ReadAsStringAsync();

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody, options);
            return tokenResponse?.AccessToken;
        }
    }
}
