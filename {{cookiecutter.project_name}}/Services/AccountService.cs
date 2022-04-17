using Amazon;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using {{cookiecutter.project_name}}.Auth;

namespace {{cookiecutter.project_name}}.Services
{
    public class AccountService : IAccountService
    {
        private readonly AuthenticationStateProvider AuthenticationStateProvider;
        private readonly ProtectedLocalStorage ProtectedLocalStorage;

        private readonly IConfiguration Configuration;

        private Timer? validationTimer;

        public AccountService(ProtectedLocalStorage protectedSessionStore, AuthenticationStateProvider authenticationStateProvider, IConfiguration configuration)
        {
            AuthenticationStateProvider = authenticationStateProvider;
            ProtectedLocalStorage = protectedSessionStore;
            Configuration = configuration;
        }

        public async Task<CognitoAWSCredentials> GetCredentials()
        {
            var idToken = await ProtectedLocalStorage.GetAsync<string>("id_token");
            var credentials = new CognitoAWSCredentials(Configuration["AWS:IdentityPoolId"], RegionEndpoint.GetBySystemName(Configuration["AWS:region"]));
            credentials.AddLogin(
                string.Format("cognito-idp.{0}.amazonaws.com/{1}", Configuration["AWS:Region"], Configuration["AWS:UserPoolId"]),
                idToken.Value);
            return credentials;
        }

        public async Task<bool> LoginAsync(string userId, string password)
        {
            try
            {
                AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.GetBySystemName(Configuration["AWS:Region"]));

                CognitoUserPool userPool = new CognitoUserPool(Configuration["AWS:UserPoolId"], Configuration["AWS:UserPoolClientId"], provider, Configuration["AWS:UserPoolClientSecret"]);
                var user = new CognitoUser(userId, Configuration["AWS:UserPoolClientId"], userPool, provider, Configuration["AWS:UserPoolClientSecret"]);
                InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
                {
                    Password = password
                };

                AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);

                if (authResponse.AuthenticationResult == null)
                {
                    return false;
                }

                var userDetails = await user.GetUserDetailsAsync();
                //userDetails.UserAttributes.ToList().ForEach(i => Console.WriteLine("{0}:{1}", i.Name, i.Value));
                await ProtectedLocalStorage.SetAsync("user", userDetails.UserAttributes.Where(u => u.Name == "email").Select(u => u.Value).SingleOrDefault());

                var token = authResponse.AuthenticationResult.AccessToken;
                var idToken = authResponse.AuthenticationResult.IdToken;

                await ProtectedLocalStorage.SetAsync("token", token);
                await ProtectedLocalStorage.SetAsync("id_token", idToken);

                ((CognitoStateProvider)AuthenticationStateProvider).Notify();

                validationTimer = new Timer(
                    ((CognitoStateProvider)AuthenticationStateProvider).Verify,
                    null,
                    TimeSpan.Zero,
                    TimeSpan.FromSeconds(300)
                );

                return true;
            }
            catch (System.Exception)
            {
                return false;
            }
        }

        public async Task<bool> LogoutAsync(string userId)
        {
            AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.GetBySystemName(Configuration["AWS:Region"]));

            CognitoUserPool userPool = new CognitoUserPool(Configuration["AWS:UserPoolId"], Configuration["AWS:UserPoolClientId"], provider, Configuration["AWS:UserPoolClientSecret"]);
            CognitoUser user = new CognitoUser(userId, Configuration["AWS:UserPoolClientId"], userPool, provider);
            user.SignOut();

            await ProtectedLocalStorage.DeleteAsync("token");
            ((CognitoStateProvider)AuthenticationStateProvider).Notify();

            if (validationTimer != null) validationTimer.Dispose();
            return true;
        }
    }
}