namespace Kitpymes.Core.Security.Tests.Authentication
{
    using Kitpymes.Core.Security;
    using Kitpymes.Core.Security.Authentication;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.TestHost;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    [TestClass]
    public class AnonymousEndpointTest
    {
        private static readonly string PrivateKey;

        private static readonly string PublicKey;

        static AnonymousEndpointTest()
        {
            using var rsa = RSA.Create(2048);
            PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        private static string CreateToken(DateTime notBefore, DateTime expires, string? privateKey = null)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey ?? PrivateKey), out _);

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("sub", "ana") }),
                NotBefore = notBefore,
                Expires = expires,
                IssuedAt = notBefore,
                // Sin caché de firmadores: IdentityModel reutilizaría el de la misma clave con un RSA ya liberado.
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa) { CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false } }, SecurityAlgorithms.RsaSha256),
            };

            return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(descriptor);
        }

        private static string CreateExpiredToken()
            => CreateToken(DateTime.UtcNow.AddMinutes(-20), DateTime.UtcNow.AddMinutes(-10));

        private static string CreateOtherKeyToken()
        {
            using var other = RSA.Create(2048);

            return CreateToken(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(10), Convert.ToBase64String(other.ExportRSAPrivateKey()));
        }

        private static async Task<WebApplication> StartAppAsync()
        {
            var privateKey = PrivateKey;
            var publicKey = PublicKey;

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();

            builder.Services.LoadSecurity(sec => sec
                .WithAuthentication(auth => auth.WithJsonWebToken(options =>
                    options.WithEnabled().WithPrivateKey(privateKey).WithPublicKey(publicKey)))
                .WithAuthorization(new global::Kitpymes.Core.Security.Authorization.Settings.AuthorizationSettings()));

            var app = builder.Build();
            app.UseRouting();
            app.LoadSecurity();
            app.MapGet("/publico", () => "ok").AllowAnonymous();
            app.MapGet("/privado", () => "ok").RequireAuthorization();

            await app.StartAsync();

            return app;
        }

        private static async Task<HttpResponseMessage> GetAsync(WebApplication app, string path, string? bearer)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);

            if (bearer is not null)
            {
                request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {bearer}");
            }

            return await app.GetTestClient().SendAsync(request);
        }

        [TestMethod]
        public async Task PublicEndpoint_WithoutToken_Returns_Ok()
        {
            await using var app = await StartAppAsync();

            using var response = await GetAsync(app, "/publico", null);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public async Task PublicEndpoint_WithInvalidToken_Returns_Ok()
        {
            // Una ruta [AllowAnonymous] no pide usuario: un token mal formado o caducado en la cabecera no debe tumbarla.
            await using var app = await StartAppAsync();

            using var response = await GetAsync(app, "/publico", "no-es-un-token");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public async Task PublicEndpoint_WithExpiredOrOtherKeyToken_Returns_Ok()
        {
            await using var app = await StartAppAsync();

            using var expired = await GetAsync(app, "/publico", CreateExpiredToken());
            using var otherKey = await GetAsync(app, "/publico", CreateOtherKeyToken());

            Assert.AreEqual(HttpStatusCode.OK, expired.StatusCode);
            Assert.AreEqual(HttpStatusCode.OK, otherKey.StatusCode);
        }

        [TestMethod]
        public async Task PrivateEndpoint_WithValidToken_Returns_Ok()
        {
            await using var app = await StartAppAsync();

            using var response = await GetAsync(app, "/privado", CreateToken(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(10)));

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public async Task PrivateEndpoint_WithExpiredToken_Throws_WithExpires()
        {
            // El mensaje es el de ToDetails(AuthenticationFailedContext), como en la 2.6.2: el de IdentityModel y la caducidad.
            await using var app = await StartAppAsync();

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => GetAsync(app, "/privado", CreateExpiredToken()));

            StringAssert.StartsWith(exception.Message, "IDX10223");
            StringAssert.Contains(exception.Message, " | Expires: ");
        }

        [TestMethod]
        public async Task PrivateEndpoint_WithOtherKeyToken_Throws_WithSignatureError()
        {
            await using var app = await StartAppAsync();

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => GetAsync(app, "/privado", CreateOtherKeyToken()));

            StringAssert.StartsWith(exception.Message, "IDX10");
            Assert.IsFalse(exception.Message.Contains("Expires:", StringComparison.Ordinal), exception.Message);
        }

        [TestMethod]
        public async Task PrivateEndpoint_WithInvalidToken_Throws_WithTokenError()
        {
            // En una ruta que pide usuario sigue saliendo UnauthorizedAccessException con el error del token, como antes.
            await using var app = await StartAppAsync();

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => GetAsync(app, "/privado", "no-es-un-token"));

            StringAssert.StartsWith(exception.Message, "IDX14100");
        }

        [TestMethod]
        public async Task PrivateEndpoint_WithoutToken_Throws_DefaultMessage()
        {
            await using var app = await StartAppAsync();

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => GetAsync(app, "/privado", null));

            Assert.AreEqual("invalid_token: This request requires a valid JWT access token to be provided", exception.Message);
        }
    }
}
