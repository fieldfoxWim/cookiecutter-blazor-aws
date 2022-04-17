using Amazon.CognitoIdentity;

namespace {{cookiecutter.project_name}}.Services
{
    public interface IAccountService
    {
        Task<bool> LoginAsync(string userId, string password);
        Task<bool> LogoutAsync(string userId);

        Task<CognitoAWSCredentials> GetCredentials();
    }
}