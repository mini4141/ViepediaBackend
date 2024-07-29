using AuthService.DTO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService.Services.AuthService _authService;

        public AuthController(AuthService.Services.AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            _authService.Register(request.Username, request.Password);
            return Ok();
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            try
            {
                var token = _authService.Login(request.Username, request.Password);
                return Ok(new { Token = token });
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPost("validate")]
        public IActionResult Validate([FromBody] ValidateRequest request)
        {
            try
            {
                var principal = _authService.ValidateToken(request.Token);
                return Ok(principal.Claims.Select(c => new { c.Type, c.Value }));
            }
            catch (SecurityTokenException)
            {
                return Unauthorized();
            }
        }
    }

}
