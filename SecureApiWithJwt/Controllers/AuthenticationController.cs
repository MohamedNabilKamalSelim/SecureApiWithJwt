using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SecureApiWithJwt.Constants;
using SecureApiWithJwt.Models;
using SecureApiWithJwt.Services;

namespace SecureApiWithJwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthenticationController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await _userService.GetAllUsers());
        }

        [HttpGet("GetAllRoles")]
        public async Task<IActionResult> GetAllRoles()
        {
            return Ok(await _userService.GetAllRoles());
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _userService.Register(model);

            if(!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _userService.Login(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result);
        }

        [HttpPost("addUserToRole")]
        public async Task<IActionResult> AddUserToRole([FromBody] AddUserToRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _userService.AddUserToRole(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }

        [HttpPost("AddNewRole")]
        public async Task<IActionResult> AddNewRole([FromBody] AddNewRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _userService.AddNewRole(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }

        [HttpDelete("DeleteUser")]
        public async Task<IActionResult> DeleteUser([FromQuery] string userId)
        {
            if (string.IsNullOrEmpty(userId))
                return BadRequest("Invalid user ID");

            var result = await _userService.RemoveUser(userId);

            return !string.IsNullOrEmpty(result) ? BadRequest(result) : Ok(userId);
        }

        [HttpDelete("DeleteRole")]
        public async Task<IActionResult> DeleteRole([FromQuery] string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
                return BadRequest("Invalid role name!");

            var result = await _userService.RemoveRole(roleName);

            return !string.IsNullOrEmpty(result) ? BadRequest(result) : Ok(roleName);
        }

        [HttpDelete("DeleteUserFromRole")]
        public async Task<IActionResult> DeleteUserFromRole([FromBody] AddUserToRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _userService.RemoveUserFromRole(model);

            return !string.IsNullOrEmpty(result) ? BadRequest(result) : Ok(model);
        }
    }
}
