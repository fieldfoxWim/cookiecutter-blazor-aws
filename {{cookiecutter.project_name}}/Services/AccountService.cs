using Amazon;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using {{cookiecutter.project_name}}.Auth;
using {{cookiecutter.project_name}}.Shared.Models;

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

         public async Task<LoginState> LoginAsync(string userId, string password, string? newPassword = null, string? confirmationCode = null)
        {
            var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.GetBySystemName(Configuration["AWS:Region"]));

            var userPool = new CognitoUserPool(Configuration["AWS:UserPoolId"], Configuration["AWS:UserPoolClientId"], provider, Configuration["AWS:UserPoolClientSecret"]);
            var user = new CognitoUser(userId, Configuration["AWS:UserPoolClientId"], userPool, provider, Configuration["AWS:UserPoolClientSecret"]);
                
            try
            {
                InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
                {
                    Password = password
                };

                AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);

                if (authResponse.AuthenticationResult == null)
                {
                    Console.WriteLine(authResponse.ChallengeName);
                    if (authResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    {
                        if (string.IsNullOrEmpty(newPassword)) return LoginState.NEW_PASSWORD_REQUIRED;
                        
                        authResponse = await user.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest()
                        {
                            SessionID = authResponse.SessionID,
                            NewPassword = newPassword
                        }).ConfigureAwait(false);
                    }
                    else if (authResponse.ChallengeName == ChallengeNameType.SMS_MFA)
                    {
                        Console.WriteLine("Enter the MFA Code sent to your device:");
                    }
                    else
                    {
                        return LoginState.FAILED;
                        Console.WriteLine("Unrecognized authentication challenge.");
                    }
                    
                }

                var userDetails = await user.GetUserDetailsAsync();
                //userDetails.UserAttributes.ToList().ForEach(i => Console.WriteLine("{0}:{1}", i.Name, i.Value));
                await ProtectedLocalStorage.SetAsync("user", userDetails.UserAttributes.Where(u => u.Name == "email").Select(u => u.Value).SingleOrDefault());

                return await FinishLogin(authResponse);
                
            }
            catch(PasswordResetRequiredException e)
            {
                if(string.IsNullOrEmpty(confirmationCode)) return LoginState.PASSWORD_RESET_REQUIRED;

                await user.ConfirmForgotPasswordAsync(confirmationCode, newPassword);

                return await this.LoginAsync(userId, newPassword);
            }
            catch (System.Exception e)
            {
                Console.WriteLine("Could not login {0}", e);
                return LoginState.FAILED;
            }
        }

        private async Task<LoginState> FinishLogin(AuthFlowResponse authResponse) 
        {
            var token = authResponse.AuthenticationResult.AccessToken;
            var idToken = authResponse.AuthenticationResult.IdToken;

            System.Console.WriteLine("Token expires in {0}", authResponse.AuthenticationResult.ExpiresIn);

            await ProtectedLocalStorage.SetAsync("token", token);
            await ProtectedLocalStorage.SetAsync("id_token", idToken);

            ((CognitoStateProvider)AuthenticationStateProvider).Notify();

            validationTimer = new Timer(
                ((CognitoStateProvider)AuthenticationStateProvider).Verify,
                null,
                TimeSpan.Zero,
                TimeSpan.FromSeconds(300)
            );

            return LoginState.SUCCESFUL;
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