using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using Kitpymes.Core.Security.Authentication.JsonWebToken;

namespace Tests.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JsonWebTokenController(IJsonWebTokenService jsonWebTokenService) : ControllerBase
    {
        private readonly IJsonWebTokenService _jsonWebTokenService = jsonWebTokenService;
        private static readonly string[] values = ["value1", "value2"];

        [HttpPost("login")]
        public IActionResult Login()
        {
            var jsonWebTokenResult = _jsonWebTokenService
                .Create(new List<Claim> { new (ClaimTypes.Name, "Carlos"), new (ClaimTypes.Email, "carlos@gmail.com") });

            return Ok(jsonWebTokenResult);
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("values")]
        public IActionResult Get() => Ok(values);
    }
}
