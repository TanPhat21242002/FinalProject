using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoAuthenticatorAPI.Dtos;
using MongoAuthenticatorAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace MongoAuthenticatorAPI.Controllers
{
    [ApiController]
    [Route("api/v1/authenticate")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

		private readonly IConfiguration _config;

		public AuthenticationController(IConfiguration config, UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _config = config;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] UserDTO user)
        {
            var result = await RegisterAsync(user);

            return result.Success ? Ok(result) : BadRequest(result.Message);

        }

        private async Task<RegisterResponse> RegisterAsync(UserDTO user)
        {
            try
            {
                var userExists = await _userManager.FindByEmailAsync(user.Email);
                if (userExists != null)
                    return new RegisterResponse { Message = "User already exists", Success = false };

                userExists = new ApplicationUser
                {
                    FullName = user.FullName,
                    Email = user.Email,
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                    UserName = user.Email,

                };

                var createUserResult = await _userManager.CreateAsync(userExists, user.Password);
                if (!createUserResult.Succeeded)
                    return new RegisterResponse { Message = $"Create user failed {createUserResult?.Errors?.First()?.Description}", Success = false };
                //user is created...
                //then add user to a role...

                /*var addUserToRoleResult = await _userManager.AddToRoleAsync(userExists, "USER");
                if (!addUserToRoleResult.Succeeded)
                    return new RegisterResponse { Message = $"Create user succeeded but could not add user to role {addUserToRoleResult?.Errors?.First()?.Description}", Success = false };
*/
                //all is still well..
                return new RegisterResponse
                {
                    Success = true,
                    Message = "User registered successfully"
                };



            }
            catch (Exception ex)
            {
                return new RegisterResponse { Message = ex.Message, Success = false };
            }
        }

        [HttpPost]
        [Route("login")]
        [ProducesResponseType((int)HttpStatusCode.OK, Type = typeof(LoginResponse))]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await LoginAsync(request);

            return result.Success ? Ok(result) : BadRequest(result.Message);


        }

        private async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user is null)
                    return new LoginResponse { Message = "Invalid email/password", Success = false };

                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
                if (!result.Succeeded)
                    return new LoginResponse { Message = "Invalid email/password", Success = false };

                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role,"USER"),
            };
                /*var roles = await _userManager.GetRolesAsync(user);
                var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x));
                claims.AddRange(roleClaims);*/

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1swek3u4uo2u4a6e"));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.Now.AddMinutes(30);

                var token = new JwtSecurityToken(
					issuer: _config["Jwt:Issuer"],
                    audience: _config["Jwt:Audience"],
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds
                    );

                return new LoginResponse
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    Message = "Login Successful",
                    Email = user?.Email,
                    Success = true,
                    UserId = user?.Id.ToString()
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return new LoginResponse { Success = false, Message = ex.Message };
            }


        }
    }
}

