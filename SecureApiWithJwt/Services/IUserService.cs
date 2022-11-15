using SecureApiWithJwt.Models;

namespace SecureApiWithJwt.Services
{
    public interface IUserService
    {
        Task<AuthenticationModel> Register(RegisterModel model);
        Task<AuthenticationModel> Login(LoginModel model);
        Task<string> AddUserToRole(AddUserToRoleModel model);
        Task<string> AddNewRole(AddNewRoleModel model);
        Task<List<UserInfoDto>> GetAllUsers();
        Task<List<RoleUserDto>> GetAllRoles();
        Task<string> RemoveUser(string userId);
        Task<string> RemoveRole(string roleName);
        Task<string> RemoveUserFromRole(AddUserToRoleModel model);
    }
}
