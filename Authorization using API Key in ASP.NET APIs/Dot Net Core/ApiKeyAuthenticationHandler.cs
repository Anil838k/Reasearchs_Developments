namespace JWT_R_N_D.Lib
{
    using System.Net;
    // ApiKeyAuthenticationHandler.cs
    using System.Security.Claims;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;

    public class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private const string ApiKeyHeader = "Authorization";

        public ApiKeyAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(ApiKeyHeader, out var apiKey))
            {
                Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await Context.Response.WriteAsync("API key is missing");
                return AuthenticateResult.Fail("API key is missing");
            }

            // Replace the logic below with your own key validation logic
            if (!IsValidApiKey(apiKey))
            {
                // Set a custom response message
                Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await Context.Response.WriteAsync("Invalid API key");
                return AuthenticateResult.Fail("Invalid API key");
            }

            var claims = new[] { new Claim(ClaimTypes.Name, "api_user") };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private bool IsValidApiKey(string apiKey)
        {
            // Implement your API key validation logic here
            // For example, check against a list of valid keys in your database
            return apiKey == "your_valid_api_key";
        }
    }

}
