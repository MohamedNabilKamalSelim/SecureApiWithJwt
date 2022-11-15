using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureApiWithJwt.Constants;
using SecureApiWithJwt.Helpers;
using SecureApiWithJwt.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureApiWithJwt.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<AuthenticationModel> Register(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthenticationModel { Message = "This email is already exists!" };

            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthenticationModel { Message = "This Username is already exists!" };

            var user = new ApplicationUser 
            { 
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach(var error in result.Errors)
                    errors += $"{error.Description},";
            }
            await _userManager.AddToRoleAsync(user, Roles.User.ToString());

            var jwtSecurityToken = await CreateJwtToken(user);

            return new AuthenticationModel{
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { Roles.User.ToString() },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName
            };
        }

        public async Task<AuthenticationModel> Login(LoginModel model)
        {
            var authenticationModel = new AuthenticationModel();

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authenticationModel.Message = "Email or Password is incorrect!";
                return authenticationModel;
            }

            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);

            authenticationModel.IsAuthenticated = true;
            authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authenticationModel.Email = user.Email;
            authenticationModel.UserName = user.UserName;
            authenticationModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authenticationModel.Roles = rolesList.ToList();

            return authenticationModel;
        }

        public async Task<string> AddUserToRole(AddUserToRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.RoleName))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.RoleName))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.RoleName);


            return result.Succeeded ? string.Empty : "Someting went wrong";
        }

        public async Task<string> AddNewRole(AddNewRoleModel model)
        {
            var role = await _roleManager.FindByNameAsync(model.RoleName);

            if (role is not null)
                return "This role is already exists!";

            var result = await _roleManager.CreateAsync(new IdentityRole( model.RoleName.Trim() ));

            return result.Succeeded ? string.Empty : "Someting went wrong";

        }

        public async Task<List<UserInfoDto>> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();

            List<UserInfoDto> usersDto = new List<UserInfoDto>();
            foreach (var user in users)
            {
                var userDto = await MapAppUserToUserDto(user);
                usersDto.Add(userDto);
            }
            return usersDto;
        }

        //public async Task<List<UserInfoDto>> GetAllUsers()
        //{
        //    return await _userManager.Users.Select( user => new UserInfoDto
        //    {
        //        FirstName = user.FirstName,
        //        LastName = user.LastName,
        //        Email = user.Email,
        //        UserName = user.UserName,
        //        Roles = _userManager.GetRolesAsync(user).Result
        //    }).ToListAsync();
        //}

        public async Task<List<RoleUserDto>> GetAllRoles()
        {
            var roles = await _roleManager.Roles.Select(role => new RoleUserDto
            {
                RoleName = role.Name,
            }).ToListAsync();

            foreach (var role in roles)
            {
                IEnumerable<ApplicationUser> users = await _userManager.GetUsersInRoleAsync(role.RoleName);

                role.UsersInRole = new List<UserInfoDto>();

                foreach (var user in users)
                    role.UsersInRole.Add(await MapAppUserToUserDto(user)); 
            }

            return roles;
        }

        private async Task<UserInfoDto> MapAppUserToUserDto(ApplicationUser user)
        {
            var userDto = new UserInfoDto();
            userDto.UserId = user.Id;
            userDto.FirstName = user.FirstName;
            userDto.LastName = user.LastName;
            userDto.Email = user.Email;
            userDto.UserName = user.UserName;
            userDto.Roles = await _userManager.GetRolesAsync(user);
            return userDto;
        }

        //public async Task<List<RoleUserDto>> GetAllRoles()
        //{
        //    return await _roleManager.Roles.Select(role => new RoleUserDto
        //    {
        //        RoleName = role.Name,
        //        UsersInRole = _userManager.GetUsersInRoleAsync(role.Name).Result
        //    }).ToListAsync();
        //}

        public async Task<string> RemoveUser(string userId)
        {
            var user =await _userManager.FindByIdAsync(userId);

            if (user is null)
                return "Invalid User ID";

            var result = await _userManager.DeleteAsync(user);

            return result.Succeeded ? string.Empty : "Someting went wrong";
        }

        public async Task<string> RemoveRole(string roleName)
        {
            var role = await _roleManager.FindByNameAsync(roleName);

            if (role is null)
                return "Role is not exists!";

            var result = await _roleManager.DeleteAsync(role);

            return result.Succeeded ? string.Empty : "Someting went wrong";
        }

        public async Task<string> RemoveUserFromRole(AddUserToRoleModel model)
        {
            var role = await _roleManager.FindByNameAsync(model.RoleName);

            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || role is null)
                return "Invalid User or Role";

            var result = await _userManager.RemoveFromRoleAsync(user, role.Name);

            return result.Succeeded ? string.Empty : "Someting went wrong";
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
