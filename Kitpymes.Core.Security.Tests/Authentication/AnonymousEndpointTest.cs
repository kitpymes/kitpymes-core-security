namespace Kitpymes.Core.Security.Tests.Authentication
{
    using Kitpymes.Core.Security;
    using Kitpymes.Core.Security.Authentication;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.TestHost;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Net;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    [TestClass]
    public class AnonymousEndpointTest
    {
        private static async Task<WebApplication> StartAppAsync()
        {
            using var rsa = RSA.Create(2048);
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

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
    }
}
