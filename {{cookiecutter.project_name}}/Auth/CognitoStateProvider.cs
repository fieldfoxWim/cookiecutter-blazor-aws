using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;

namespace {{cookiecutter.project_name}}.Auth
{
    public class CognitoStateProvider : AuthenticationStateProvider
    {
        private readonly ProtectedLocalStorage ProtectedLocalStorage;
        private readonly IConfiguration Configuration;
        public CognitoStateProvider(ProtectedLocalStorage protectedSessionStore, IConfiguration configuration)
        {
            ProtectedLocalStorage = protectedSessionStore;
            Configuration = configuration;
        }

        public RsaSecurityKey SigningKey(string Key, string Expo)
        {
            return new RsaSecurityKey(new RSAParameters()
            {
                Modulus = Base64UrlEncoder.DecodeBytes(Key),
                Exponent = Base64UrlEncoder.DecodeBytes(Expo)
            });
        }

        public async override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var value = await ProtectedLocalStorage.GetAsync<string>("token");
                var token = value.Value;
                var userDetails = await ProtectedLocalStorage.GetAsync<string>("user");

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Configuration["AWS:JwtKey"];
                var e = Configuration["AWS:JwtExponent"];

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidIssuer = string.Format("https://cognito-idp.{0}.amazonaws.com/{1}", Configuration["AWS:Region"], Configuration["AWS:UserPoolId"]),
                    ValidAudience = Configuration["AWS:UserPoolClientId"],
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = SigningKey(key, e),
                    ValidateLifetime = true,
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var username = jwtToken.Claims.First(x => x.Type == "username").Value;

                //jwtToken.Claims.ToList().ForEach(i => Console.WriteLine(i));

                var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Email, userDetails.Value), }, "user");

                var user = new ClaimsPrincipal(identity);

                return await Task.FromResult(new AuthenticationState(user));
            }
            catch (Exception)
            {
                await ProtectedLocalStorage.DeleteAsync("token");
                return await Task.FromResult(new AuthenticationState(new ClaimsPrincipal()));
            }

        }

        internal void Verify(object? state)
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public void Notify()
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}