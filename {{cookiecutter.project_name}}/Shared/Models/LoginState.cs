namespace {{cookiecutter.project_name}}.Shared.Models
{
    public enum LoginState
    {
        UNKNOWN,
        SUCCESFUL,
        NEW_PASSWORD_REQUIRED,
        PASSWORD_RESET_REQUIRED,
        FAILED
    }
}