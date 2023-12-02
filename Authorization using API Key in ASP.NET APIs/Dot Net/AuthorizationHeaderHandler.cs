using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Web;
using System.Security.Claims;
using System.Net;
using System.Web.Http.Results;

namespace WebApplication1.lib
{
    public class AuthorizationHeaderHandler
     : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            IEnumerable<string> apiKeyHeaderValues = null;
            if (request.Headers.TryGetValues("Authorization", out apiKeyHeaderValues))
            {
                var apiKeyHeaderValue = apiKeyHeaderValues.First();
                if (IsValidApiKey(apiKeyHeaderValue))
                {

                    var usernameClaim = new Claim(ClaimTypes.Name, "api_user");
                    var identity = new ClaimsIdentity(new[] { usernameClaim }, "ApiKey");
                    var principal = new ClaimsPrincipal(identity);

                    HttpContext.Current.User = principal;
                }
                else
                {
                    var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                    {
                        Content = new StringContent("Invalid API key"),
                        RequestMessage = request
                    };

                    return Task.FromResult(response);
                }



            }
            else
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("API key is missing"),
                    RequestMessage = request
                };

                return Task.FromResult(response);
            }

            return base.SendAsync(request, cancellationToken);
        }


        private bool IsValidApiKey(string apiKey)
        {
            // Implement your API key validation logic here
            // For example, check against a list of valid keys in your database
            return apiKey == "your_valid_api_key";
        }
    }
}