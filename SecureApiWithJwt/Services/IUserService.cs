using SecureApiWithJwt.Models;

namespace SecureApiWithJwt.Services
{
    public interface IUserService
    {
        Task<AuthenticationModel> Register(RegisterModel model);
        Task<AuthenticationModel> Login(LoginModel model);
        Task<string> AddRole(AddRoleModel model);
    }
}
