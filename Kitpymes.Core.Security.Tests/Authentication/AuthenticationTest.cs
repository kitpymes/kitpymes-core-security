using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Authentication.Cookies;
using Kitpymes.Core.Security.Authentication.Cookies.Extensions;
using Kitpymes.Core.Security.Authentication.Cookies.Settings;
using Kitpymes.Core.Security.Authentication.JsonWebToken;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Extensions;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Security.Authentication.OAuth.Settings;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Kitypmes.Core.Security.Tests
{
    [TestClass]
    public class AuthenticationTest
    {
        private const string DefaultTokenError = "invalid_token: This request requires a valid JWT access token to be provided";

        private static (string PrivateKey, string PublicKey) CreateKeys()
        {
            using RSA rsa = RSA.Create();

            return (Convert.ToBase64String(rsa.ExportRSAPrivateKey()), Convert.ToBase64String(rsa.ExportRSAPublicKey()));
        }

        #region JwtBearerChallengeContext.ToDetails

        private static JwtBearerChallengeContext CreateChallengeContext()
            => new(new DefaultHttpContext(), new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), new JwtBearerOptions(), new AuthenticationProperties());

        [TestMethod]
        public void ChallengeContext_ToDetails_WithoutError_Returns_DefaultMessage()
        {
            Assert.AreEqual(DefaultTokenError, CreateChallengeContext().ToDetails());
        }

        [TestMethod]
        public void ChallengeContext_ToDetails_WithError_Returns_ErrorAndDescription()
        {
            var context = CreateChallengeContext();
            context.Error = "invalid_token";
            context.ErrorDescription = "La firma no es válida";
            context.AuthenticateFailure = new SecurityTokenInvalidLifetimeException("sin fecha");

            Assert.AreEqual("invalid_token | La firma no es válida", context.ToDetails());
        }

        [TestMethod]
        public void ChallengeContext_ToDetails_WithInvalidLifetime_Adds_Expires()
        {
            var expires = new DateTime(2026, 11, 24, 10, 30, 0, DateTimeKind.Utc);
            var context = CreateChallengeContext();
            context.Error = "invalid_token";
            context.ErrorDescription = "d";
            context.AuthenticateFailure = new SecurityTokenInvalidLifetimeException("caducado") { Expires = expires };

            Assert.AreEqual($"invalid_token | d | Expires: {expires:G}", context.ToDetails());
        }

        [TestMethod]
        public void ChallengeContext_ToDetails_WithExpired_Adds_Expires()
        {
            var expires = new DateTime(2026, 11, 24, 10, 30, 0, DateTimeKind.Utc);
            var context = CreateChallengeContext();
            context.Error = "invalid_token";
            context.ErrorDescription = "d";
            context.AuthenticateFailure = new SecurityTokenExpiredException("caducado") { Expires = expires };

            Assert.AreEqual($"invalid_token | d | Expires: {expires:G}", context.ToDetails());
        }

        [TestMethod]
        public void ChallengeContext_ToDetails_WithOtherFailure_Returns_ErrorAndDescription()
        {
            var context = CreateChallengeContext();
            context.Error = "invalid_token";
            context.ErrorDescription = "d";
            context.AuthenticateFailure = new InvalidOperationException("otro");

            Assert.AreEqual("invalid_token | d", context.ToDetails());
        }

        #endregion JwtBearerChallengeContext.ToDetails

        #region AuthenticationFailedContext.ToDetails

        private static AuthenticationFailedContext CreateFailedContext(Exception? exception)
            => new(new DefaultHttpContext(), new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), new JwtBearerOptions()) { Exception = exception! };

        [TestMethod]
        public void FailedContext_ToDetails_WithoutException_Returns_DefaultMessage()
        {
            Assert.AreEqual(DefaultTokenError, CreateFailedContext(null).ToDetails());
        }

        [TestMethod]
        public void FailedContext_ToDetails_WithException_Returns_Message()
        {
            Assert.AreEqual("otro", CreateFailedContext(new InvalidOperationException("otro")).ToDetails());
            Assert.AreEqual("sin fecha", CreateFailedContext(new SecurityTokenInvalidLifetimeException("sin fecha")).ToDetails());
        }

        [TestMethod]
        public void FailedContext_ToDetails_WithInvalidLifetime_Adds_Expires()
        {
            var expires = new DateTime(2026, 11, 24, 10, 30, 0, DateTimeKind.Utc);

            var details = CreateFailedContext(new SecurityTokenInvalidLifetimeException("caducado") { Expires = expires }).ToDetails();

            Assert.AreEqual($"caducado | Expires: {expires:G}", details);
        }

        [TestMethod]
        public void FailedContext_ToDetails_WithExpired_Adds_Expires()
        {
            var expires = new DateTime(2026, 11, 24, 10, 30, 0, DateTimeKind.Utc);

            var details = CreateFailedContext(new SecurityTokenExpiredException("caducado") { Expires = expires }).ToDetails();

            Assert.AreEqual($"caducado | Expires: {expires:G}", details);
        }

        #endregion AuthenticationFailedContext.ToDetails

        #region JsonWebToken

        private static IServiceProvider LoadJsonWebToken(Action<JsonWebTokenOptions>? extra = null)
        {
            var (privateKey, publicKey) = CreateKeys();

            var services = new ServiceCollection();
            services.AddLogging();

            services.LoadSecurity(sec => sec.WithAuthentication(auth => auth.WithJsonWebToken(options =>
            {
                options.WithEnabled().WithPrivateKey(privateKey).WithPublicKey(publicKey);
                extra?.Invoke(options);
            })));

            return services.BuildServiceProvider();
        }

        [TestMethod]
        public void LoadJsonWebToken_Configures_Schemes_And_HttpContextAccessor()
        {
            var provider = LoadJsonWebToken(x => x.WithScheme("Autenticar", "Desafiar"));

            var options = provider.GetRequiredService<IOptions<Microsoft.AspNetCore.Authentication.AuthenticationOptions>>().Value;

            Assert.AreEqual("Autenticar", options.DefaultScheme);
            Assert.AreEqual("Autenticar", options.DefaultAuthenticateScheme);
            Assert.AreEqual("Desafiar", options.DefaultChallengeScheme);
            Assert.IsNotNull(provider.GetService<IHttpContextAccessor>());
        }

        [TestMethod]
        public void LoadJsonWebToken_Configures_JwtBearer_FromSettings()
        {
            var provider = LoadJsonWebToken(x => x
                .WithRequireHttpsMetadata(false)
                .WithSaveToken(false)
                .WithIncludeErrorDetails(false)
                .WithValidateLifetime(false)
                .WithRequireExpirationTime(false)
                .WithIssuer("https://emisor")
                .WithAudience("https://audiencia"));

            var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
            var parameters = options.TokenValidationParameters;

            Assert.IsFalse(options.RequireHttpsMetadata);
            Assert.IsFalse(options.SaveToken);
            Assert.IsFalse(options.IncludeErrorDetails);
            Assert.IsFalse(parameters.ValidateLifetime);
            Assert.IsFalse(parameters.RequireExpirationTime);
            Assert.IsTrue(parameters.ValidateIssuerSigningKey);
            Assert.IsTrue(parameters.ValidateIssuer);
            Assert.AreEqual("https://emisor", parameters.ValidIssuer);
            Assert.IsTrue(parameters.ValidateAudience);
            Assert.AreEqual("https://audiencia", parameters.ValidAudience);
            Assert.AreEqual(TimeSpan.Zero, parameters.ClockSkew);

            var key = (RsaSecurityKey)parameters.IssuerSigningKey;
            Assert.IsFalse(key.CryptoProviderFactory.CacheSignatureProviders);
            Assert.AreNotSame(CryptoProviderFactory.Default, key.CryptoProviderFactory);
        }

        [TestMethod]
        public void LoadJsonWebToken_WithDefaults_DoesNotValidate_IssuerOrAudience()
        {
            var provider = LoadJsonWebToken();

            var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
            var parameters = options.TokenValidationParameters;

            Assert.IsTrue(options.RequireHttpsMetadata);
            Assert.IsTrue(options.SaveToken);
            Assert.IsTrue(options.IncludeErrorDetails);
            Assert.IsTrue(parameters.ValidateLifetime);
            Assert.IsTrue(parameters.RequireExpirationTime);
            Assert.IsFalse(parameters.ValidateIssuer);
            Assert.IsFalse(parameters.ValidateAudience);

#if DEBUG
            Assert.IsTrue(Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII);
            Assert.IsTrue(Microsoft.IdentityModel.Logging.IdentityModelEventSource.LogCompleteSecurityArtifact);
#endif
        }

        [TestMethod]
        public void LoadJsonWebToken_LifetimeValidator_Accepts_Only_FutureExpiration()
        {
            var provider = LoadJsonWebToken();

            var parameters = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

            Assert.IsTrue(parameters.LifetimeValidator!(null, DateTime.UtcNow.AddMinutes(5), null!, parameters));
            Assert.IsFalse(parameters.LifetimeValidator!(null, DateTime.UtcNow.AddMinutes(-5), null!, parameters));
        }

        [TestMethod]
        public async Task LoadJsonWebToken_Challenge_And_AuthenticationFailed_Throw_Unauthorized()
        {
            var provider = LoadJsonWebToken();

            var events = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).Events;

            var challenge = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.OnChallenge(CreateChallengeContext()));
            Assert.AreEqual(DefaultTokenError, challenge.Message);

            var failed = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.OnAuthenticationFailed(CreateFailedContext(new InvalidOperationException("otro"))));
            Assert.AreEqual("otro", failed.Message);
        }

        [TestMethod]
        public void JsonWebTokenService_Get_Passing_NullOrEmpty_Throws()
        {
            var service = new JsonWebTokenService(new JsonWebTokenSettings());

            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => service.Get(null));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => service.Get(string.Empty));
        }

        [TestMethod]
        public void JsonWebTokenService_Create_WithoutPrivateKey_Throws()
        {
            var service = new JsonWebTokenService(new JsonWebTokenSettings());

            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => service.Create(new[] { new Claim("a", "b") }));
        }

        [TestMethod]
        public void JsonWebTokenService_Create_Passing_OneClaim_Returns_TokenWithIt()
        {
            var (privateKey, _) = CreateKeys();
            var service = new JsonWebTokenService(new JsonWebTokenSettings { PrivateKey = privateKey });

            var token = service.Create(new Claim("rol", "Admin")).Token;

            Assert.AreEqual("Admin", service.Get(token).Claims["rol"]);
        }

        #endregion JsonWebToken

        #region LoadAuthentication

        [TestMethod]
        public void LoadSecurity_Passing_OAuthEnabled_Throws_NotImplemented()
        {
            var settings = new AuthenticationSettings { OAuthSettings = new OAuthSettings { Enabled = true } };

            Assert.ThrowsExactly<NotImplementedException>(() => new ServiceCollection().LoadSecurity(sec => sec.WithAuthentication(settings)));
        }

        [TestMethod]
        public void LoadSecurity_Passing_AuthenticationWithNothingEnabled_Registers_Nothing()
        {
            var services = new ServiceCollection();

            services.LoadSecurity(sec => sec.WithAuthentication(new AuthenticationSettings
            {
                JsonWebTokenSettings = new JsonWebTokenSettings(),
                CookiesSettings = new CookiesSettings(),
                OAuthSettings = new OAuthSettings(),
            }));

            Assert.IsFalse(services.Any(x => x.ServiceType == typeof(IJsonWebTokenService)));
            Assert.IsFalse(services.Any(x => x.ServiceType == typeof(ICookiesService)));
        }

        [TestMethod]
        public void SecurityOptions_WithAuthentication_Enables_It()
        {
            var options = new SecurityOptions().WithAuthentication(new AuthenticationSettings());

            Assert.AreEqual(true, options.SecuritySettings.AuthenticationSettings!.Enabled);
        }

        [TestMethod]
        public void SecurityOptions_WithAuthentication_FromConfiguration_Reads_Section()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:Issuer"] = "https://emisor",
                    ["SecuritySettings:AuthenticationSettings:CookiesSettings:CookieName"] = "galleta",
                })
                .Build();

            var options = new SecurityOptions().WithAuthentication(configuration);

            Assert.AreEqual(true, options.SecuritySettings.AuthenticationSettings!.Enabled);
            Assert.AreEqual("https://emisor", options.SecuritySettings.AuthenticationSettings.JsonWebTokenSettings!.Issuer);
        }

        [TestMethod]
        public void AuthenticationOptions_FromConfiguration_Reads_JsonWebToken_And_Cookies()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:Issuer"] = "https://emisor",
                    ["SecuritySettings:AuthenticationSettings:CookiesSettings:CookieName"] = "galleta",
                })
                .Build();

            var options = new Kitpymes.Core.Security.Authentication.AuthenticationOptions()
                .WithJsonWebToken(configuration)
                .WithCookies(configuration);

            Assert.AreEqual("https://emisor", options.AuthenticationSettings.JsonWebTokenSettings!.Issuer);
            Assert.AreEqual("galleta", options.AuthenticationSettings.CookiesSettings!.CookieName);
        }

        [TestMethod]
        public void AuthenticationOptions_FromConfiguration_WithoutSection_Throws()
        {
            var configuration = new ConfigurationBuilder().Build();
            var options = new Kitpymes.Core.Security.Authentication.AuthenticationOptions();

            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => options.WithJsonWebToken(configuration));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => options.WithCookies(configuration));
        }

        [TestMethod]
        public void AuthenticationOptions_WithCookies_Passing_Options_Stores_Settings()
        {
            var options = new Kitpymes.Core.Security.Authentication.AuthenticationOptions()
                .WithCookies(x => x.WithEnabled().WithCookieName("galleta"));

            Assert.AreEqual(true, options.AuthenticationSettings.CookiesSettings!.Enabled);
            Assert.AreEqual("galleta", options.AuthenticationSettings.CookiesSettings.CookieName);
        }

        #endregion LoadAuthentication

        #region Options

        [TestMethod]
        public void JsonWebTokenOptions_Stores_Every_Value()
        {
            var settings = new JsonWebTokenOptions()
                .WithEnabled(false)
                .WithScheme("A", "B")
                .WithRequireHttpsMetadata(false)
                .WithRequireExpirationTime(false)
                .WithSaveToken(false)
                .WithIncludeErrorDetails(false)
                .WithValidateLifetime(false)
                .WithExpire(1, 2, 3, 4)
                .WithPublicKey("pub")
                .WithPrivateKey("priv")
                .WithIssuer("iss")
                .WithAudience("aud")
                .JsonWebTokenSettings;

            Assert.AreEqual(false, settings.Enabled);
            Assert.AreEqual("A", settings.AuthenticateScheme);
            Assert.AreEqual("B", settings.ChallengeScheme);
            Assert.AreEqual(false, settings.RequireHttpsMetadata);
            Assert.AreEqual(false, settings.RequireExpirationTime);
            Assert.AreEqual(false, settings.SaveToken);
            Assert.AreEqual(false, settings.IncludeErrorDetails);
            Assert.AreEqual(false, settings.ValidateLifetime);
            Assert.AreEqual(1, settings.Expire.Days);
            Assert.AreEqual(2, settings.Expire.Hours);
            Assert.AreEqual(3, settings.Expire.Minutes);
            Assert.AreEqual(4, settings.Expire.Seconds);
            Assert.AreEqual("pub", settings.PublicKey);
            Assert.AreEqual("priv", settings.PrivateKey);
            Assert.AreEqual("iss", settings.Issuer);
            Assert.AreEqual("aud", settings.Audience);
        }

        [TestMethod]
        public void CookiesOptions_Stores_Every_Value()
        {
            var settings = new CookiesOptions()
                .WithEnabled()
                .WithScheme("Galletas")
                .WithCookieName("galleta")
                .WithExpire(1, 2, 3, 4)
                .WithSlidingExpiration(false)
                .WithHttpOnly(false)
                .WithLoginPath("/entrar")
                .WithLogoutPath("/salir")
                .WithAccessDeniedPath("/denegado")
                .WithReturnUrlParameter("volver")
                .CookiesSettings;

            Assert.AreEqual(true, settings.Enabled);
            Assert.AreEqual("Galletas", settings.AuthenticateScheme);
            Assert.AreEqual("galleta", settings.CookieName);
            Assert.AreEqual(1, settings.Expire.Days);
            Assert.AreEqual(2, settings.Expire.Hours);
            Assert.AreEqual(3, settings.Expire.Minutes);
            Assert.AreEqual(4, settings.Expire.Seconds);
            Assert.AreEqual(false, settings.SlidingExpiration);
            Assert.AreEqual(false, settings.HttpOnly);
            Assert.AreEqual("/entrar", settings.LoginPath);
            Assert.AreEqual("/salir", settings.LogoutPath);
            Assert.AreEqual("/denegado", settings.AccessDeniedPath);
            Assert.AreEqual("volver", settings.ReturnUrlParameter);
        }

        #endregion Options

        #region Cookies

        private static IServiceProvider LoadCookies(IServiceCollection services)
        {
            services.AddLogging();

            services.LoadSecurity(sec => sec.WithAuthentication(auth => auth.WithCookies(x => x
                .WithEnabled()
                .WithCookieName("galleta")
                .WithExpire(1, 2, 3, 4)
                .WithSlidingExpiration(false)
                .WithHttpOnly(false)
                .WithLoginPath("/entrar")
                .WithLogoutPath("/salir")
                .WithAccessDeniedPath("/denegado")
                .WithReturnUrlParameter("volver"))));

            return services.BuildServiceProvider();
        }

        [TestMethod]
        public void LoadCookies_Configures_Cookie_FromSettings()
        {
            var services = new ServiceCollection();
            var provider = LoadCookies(services);

            var options = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);

            Assert.AreEqual("galleta", options.Cookie.Name);
            Assert.IsFalse(options.Cookie.HttpOnly);
            Assert.AreEqual(SameSiteMode.Strict, options.Cookie.SameSite);
            Assert.AreEqual(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
            Assert.AreEqual(new TimeSpan(1, 2, 3, 4), options.ExpireTimeSpan);
            Assert.AreEqual(new PathString("/entrar"), options.LoginPath);
            Assert.AreEqual(new PathString("/salir"), options.LogoutPath);
            Assert.AreEqual(new PathString("/denegado"), options.AccessDeniedPath);
            Assert.AreEqual("volver", options.ReturnUrlParameter);
            Assert.IsFalse(options.SlidingExpiration);

            var authentication = provider.GetRequiredService<IOptions<Microsoft.AspNetCore.Authentication.AuthenticationOptions>>().Value;
            Assert.AreEqual(CookieAuthenticationDefaults.AuthenticationScheme, authentication.DefaultScheme);

            Assert.IsNotNull(provider.GetService<IHttpContextAccessor>());
            Assert.IsInstanceOfType<CookiesService>(services.GetAuthCookies());
        }

        [TestMethod]
        public void LoadCookies_InDevelopment_Allows_Http()
        {
            var environment = new Mock<IWebHostEnvironment>();
            environment.SetupGet(x => x.EnvironmentName).Returns("Development");

            var services = new ServiceCollection();
            services.AddSingleton(environment.Object);

            var provider = LoadCookies(services);

            var options = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);

            Assert.AreEqual(CookieSecurePolicy.None, options.Cookie.SecurePolicy);
        }

        [TestMethod]
        public void LoadCookies_InProduction_Requires_Https()
        {
            var environment = new Mock<IWebHostEnvironment>();
            environment.SetupGet(x => x.EnvironmentName).Returns("Production");

            var services = new ServiceCollection();
            services.AddSingleton(environment.Object);

            var provider = LoadCookies(services);

            var options = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(CookieAuthenticationDefaults.AuthenticationScheme);

            Assert.AreEqual(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
        }

        [TestMethod]
        public void LoadCookies_Keeps_Existing_HttpContextAccessor()
        {
            var accessor = new HttpContextAccessor();
            var services = new ServiceCollection();
            services.AddSingleton<IHttpContextAccessor>(accessor);

            LoadCookies(services);

            Assert.AreEqual(1, services.Count(x => x.ServiceType == typeof(IHttpContextAccessor)));
        }

        [TestMethod]
        public void GetAuthCookies_WithoutCookies_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new ServiceCollection().GetAuthCookies());
        }

        [TestMethod]
        public async Task CookiesService_SignIn_And_SignOut_Use_Scheme_And_Properties()
        {
            var httpContext = new DefaultHttpContext();
            var accessor = new Mock<IHttpContextAccessor>();
            accessor.SetupGet(x => x.HttpContext).Returns(httpContext);

            var authentication = new Mock<IAuthenticationService>();
            ClaimsPrincipal? principal = null;
            AuthenticationProperties? properties = null;

            authentication
                .Setup(x => x.SignInAsync(httpContext, "Galletas", It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>((_, _, p, props) => { principal = p; properties = props; })
                .Returns(Task.CompletedTask);

            var service = new CookiesService(new CookiesSettings { AuthenticateScheme = "Galletas" }, authentication.Object, accessor.Object);

            await service.SignInAsync(new[] { new Claim(ClaimTypes.Name, "ana") }, x => x.IsPersistent = true);

            Assert.IsNotNull(principal);
            Assert.AreEqual("ana", principal.Identity!.Name);
            Assert.AreEqual("Galletas", principal.Identity.AuthenticationType);
            Assert.IsTrue(properties!.IsPersistent);

            await service.SignOutAsync();

            authentication.Verify(x => x.SignOutAsync(httpContext, "Galletas", properties), Times.Once);
        }

        [TestMethod]
        public async Task CookiesService_WithoutHttpContext_Throws()
        {
            var accessor = new Mock<IHttpContextAccessor>();
            var authentication = new Mock<IAuthenticationService>();

            var service = new CookiesService(new CookiesSettings(), authentication.Object, accessor.Object);

            await Assert.ThrowsExactlyAsync<global::Kitpymes.Core.Shared.Util.SharedException>(() => service.SignInAsync(new[] { new Claim("a", "b") }));
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(() => service.SignOutAsync());

            authentication.VerifyNoOtherCalls();
        }

        #endregion Cookies

        #region CustomCookieAuthenticationEvents

        private static CookieValidatePrincipalContext CreateValidateContext(ICookiesService cookiesService, params Claim[] claims)
        {
            var services = new ServiceCollection();
            services.AddSingleton(cookiesService);

            var httpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
            var scheme = new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(CookieAuthenticationHandler));

            return new CookieValidatePrincipalContext(httpContext, scheme, new CookieAuthenticationOptions(), new AuthenticationTicket(principal, scheme.Name));
        }

        [TestMethod]
        public async Task ValidatePrincipal_WithoutLastUpdated_Rejects_And_SignsOut()
        {
            var cookiesService = new Mock<ICookiesService>();
            var context = CreateValidateContext(cookiesService.Object);

            await new CustomCookieAuthenticationEvents(new HttpContextAccessor()).ValidatePrincipal(context);

            Assert.IsNull(context.Principal);
            cookiesService.Verify(x => x.SignOutAsync(), Times.Once);
        }

        [TestMethod]
        public async Task ValidatePrincipal_WithLastUpdated_Keeps_Principal()
        {
            var cookiesService = new Mock<ICookiesService>();
            var context = CreateValidateContext(cookiesService.Object, new Claim("LastUpdated", "2026-11-24"));

            await new CustomCookieAuthenticationEvents(new HttpContextAccessor()).ValidatePrincipal(context);

            Assert.IsNotNull(context.Principal);
            cookiesService.Verify(x => x.SignOutAsync(), Times.Never);
        }

        [TestMethod]
        public async Task ValidatePrincipal_Passing_Null_Throws()
        {
            await Assert.ThrowsExactlyAsync<global::Kitpymes.Core.Shared.Util.SharedException>(() => new CustomCookieAuthenticationEvents(new HttpContextAccessor()).ValidatePrincipal(null!));
        }

        private static RedirectContext<CookieAuthenticationOptions> CreateRedirectContext(HttpContext httpContext)
            => new(httpContext, new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(CookieAuthenticationHandler)), new CookieAuthenticationOptions(), new AuthenticationProperties(), "/denegado");

        [TestMethod]
        public async Task RedirectToAccessDenied_WithUser_Throws_WithUsername()
        {
            var httpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "ana-test") }, "Test")),
            };

            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            StringAssert.Contains(exception.Message, "AccessDeniedDateTime");
            StringAssert.Contains(exception.Message, "\"Username\"");
            StringAssert.Contains(exception.Message, "ana-test");
        }

        [TestMethod]
        public async Task RedirectToAccessDenied_WithoutUser_Throws_WithoutUsername()
        {
            var httpContext = new DefaultHttpContext();

            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            StringAssert.Contains(exception.Message, "AccessDeniedDateTime");
            Assert.IsFalse(exception.Message.Contains("\"Username\"", StringComparison.Ordinal));
        }

        #endregion CustomCookieAuthenticationEvents
    }
}
