using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using Kitpymes.Core.Security.Authentication.JsonWebToken;
using Microsoft.AspNetCore.Http;
using Kitpymes.Core.Api.ApiSession;
using System;
using Kitpymes.Core.Shared.Extensions;
using System.Linq;

namespace Tests.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JsonWebTokenController(IJsonWebTokenService jsonWebTokenService) : ControllerBase
    {
        private readonly IJsonWebTokenService _jsonWebTokenService = jsonWebTokenService;

        [HttpPost("login")]
        public IActionResult Login()
        {
            var userSession = new UserSession
            {
                Email = "test@email.com",
                Id = Guid.NewGuid().ToString(),
                Permissions = new List<string> { "Create", "Edit" },
                Role = "Admin",
            }.ToSerialize();

            var jsonWebTokenResult = _jsonWebTokenService
                .Create(new Claim(ApiSession.UserClaimType, userSession));

            return Ok(jsonWebTokenResult);
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("data")]
        public IActionResult GetData()
        {
            var claimsPrincipal = HttpContext.User;

            var userSession = claimsPrincipal.ToGet<UserSession>(ApiSession.UserClaimType);

            return Ok(new
            {
                UserSession = userSession,
                ClaimsPrincipal = new
                {
                    Claims = claimsPrincipal.Claims.Select(s => new
                    {
                        s.Type,
                        s.Value
                    }).ToList(),

                    claimsPrincipal.Identity
                },
            });
        }
    }
}
