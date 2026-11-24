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
                .WithAudience("https://audiencia")
                .WithClockSkew(5));

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
            Assert.AreEqual(TimeSpan.FromSeconds(5), parameters.ClockSkew);

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
            Assert.AreEqual(TimeSpan.FromSeconds(60), parameters.ClockSkew);

#if DEBUG
            Assert.IsTrue(Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII);
            Assert.IsTrue(Microsoft.IdentityModel.Logging.IdentityModelEventSource.LogCompleteSecurityArtifact);
#endif
        }

        [TestMethod]
        public void LoadJsonWebToken_Uses_IdentityModel_LifetimeValidation()
        {
            // Hasta la 2.5.1 había un LifetimeValidator propio que sólo miraba exp y pasaba por encima de ValidateLifetime.
            var provider = LoadJsonWebToken();

            var parameters = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

            Assert.IsNull(parameters.LifetimeValidator);
        }

        [TestMethod]
        public async Task LoadJsonWebToken_Challenge_Throws_Unauthorized_WithAuthenticationFailedDetails()
        {
            // Desde la 2.6.3 OnAuthenticationFailed no lanza (tumbaba las rutas públicas): guarda el error y lo lanza el desafío.
            var provider = LoadJsonWebToken();

            var events = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).Events;

            var challenge = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.OnChallenge(CreateChallengeContext()));
            Assert.AreEqual(DefaultTokenError, challenge.Message);

            var httpContext = new DefaultHttpContext();
            var failedContext = new AuthenticationFailedContext(httpContext, new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), new JwtBearerOptions()) { Exception = new InvalidOperationException("otro") };

            var failed = events.OnAuthenticationFailed(failedContext);
            Assert.IsTrue(failed.IsCompletedSuccessfully);
            Assert.IsNull(failedContext.Result);

            var challengeContext = new JwtBearerChallengeContext(httpContext, new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), new JwtBearerOptions(), new AuthenticationProperties());
            var afterFailure = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.OnChallenge(challengeContext));
            Assert.AreEqual("otro", afterFailure.Message);
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

        private static TokenValidationParameters GetValidationParameters(string privateKey, string publicKey, Action<JsonWebTokenOptions>? extra = null)
        {
            var services = new ServiceCollection();

            services.LoadSecurity(sec => sec.WithAuthentication(auth => auth.WithJsonWebToken(options =>
            {
                options.WithEnabled().WithPrivateKey(privateKey).WithPublicKey(publicKey);
                extra?.Invoke(options);
            })));

            return services.BuildServiceProvider()
                .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
                .Get(JwtBearerDefaults.AuthenticationScheme)
                .TokenValidationParameters;
        }

        private static string CreateToken(string privateKey, DateTime notBefore, DateTime expires)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("sub", "ana") }),
                NotBefore = notBefore,
                Expires = expires,
                IssuedAt = notBefore,
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
            };

            return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(descriptor);
        }

        private static async Task<bool> IsValidAsync(string token, TokenValidationParameters parameters)
            => (await ValidateAsync(token, parameters)).IsValid;

        private static Task<TokenValidationResult> ValidateAsync(string token, TokenValidationParameters parameters)
            => new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().ValidateTokenAsync(token, parameters);

        [TestMethod]
        public async Task JsonWebToken_Validation_Accepts_CurrentToken()
        {
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey);

            var token = CreateToken(privateKey, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10));

            Assert.IsTrue(await IsValidAsync(token, parameters));
        }

        [TestMethod]
        public async Task JsonWebToken_Validation_Rejects_NotYetValidToken()
        {
            // nbf en el futuro: el token todavía no vale.
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey);

            var token = CreateToken(privateKey, DateTime.UtcNow.AddMinutes(10), DateTime.UtcNow.AddMinutes(20));

            var result = await ValidateAsync(token, parameters);

            Assert.IsFalse(result.IsValid);
            Assert.IsInstanceOfType<SecurityTokenNotYetValidException>(result.Exception);
        }

        [TestMethod]
        public async Task JsonWebToken_Validation_Rejects_ExpiredToken()
        {
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey);

            var token = CreateToken(privateKey, DateTime.UtcNow.AddMinutes(-20), DateTime.UtcNow.AddMinutes(-10));

            var result = await ValidateAsync(token, parameters);

            Assert.IsFalse(result.IsValid);
            Assert.IsInstanceOfType<SecurityTokenExpiredException>(result.Exception);
        }

        [TestMethod]
        public async Task JsonWebToken_Validation_WithValidateLifetimeFalse_Accepts_ExpiredToken()
        {
            // WithValidateLifetime(false) desactiva la comprobación de las fechas.
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey, x => x.WithValidateLifetime(false));

            var token = CreateToken(privateKey, DateTime.UtcNow.AddMinutes(-20), DateTime.UtcNow.AddMinutes(-10));

            Assert.IsTrue(await IsValidAsync(token, parameters));
        }

        [TestMethod]
        [DataRow(30, true)]
        [DataRow(120, false)]
        public async Task JsonWebToken_Validation_WithDefaultClockSkew_NotYetValid(int secondsAhead, bool expected)
        {
            // Margen por defecto de 60 s: un token que empieza a valer dentro de 30 s ya vale (el reloj del emisor puede ir
            // adelantado); uno que empieza dentro de 2 minutos, no.
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey);

            var token = CreateToken(privateKey, DateTime.UtcNow.AddSeconds(secondsAhead), DateTime.UtcNow.AddMinutes(20));

            var result = await ValidateAsync(token, parameters);

            Assert.AreEqual(expected, result.IsValid);

            if (!expected)
            {
                Assert.IsInstanceOfType<SecurityTokenNotYetValidException>(result.Exception);
            }
        }

        [TestMethod]
        [DataRow(30, true)]
        [DataRow(120, false)]
        public async Task JsonWebToken_Validation_WithDefaultClockSkew_Expired(int secondsAgo, bool expected)
        {
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey);

            var token = CreateToken(privateKey, DateTime.UtcNow.AddMinutes(-20), DateTime.UtcNow.AddSeconds(-secondsAgo));

            var result = await ValidateAsync(token, parameters);

            Assert.AreEqual(expected, result.IsValid);

            if (!expected)
            {
                Assert.IsInstanceOfType<SecurityTokenExpiredException>(result.Exception);
            }
        }

        [TestMethod]
        public async Task JsonWebToken_Validation_WithClockSkewZero_Rejects_TokenStartingSoon()
        {
            var (privateKey, publicKey) = CreateKeys();
            var parameters = GetValidationParameters(privateKey, publicKey, x => x.WithClockSkew(0));

            var token = CreateToken(privateKey, DateTime.UtcNow.AddSeconds(30), DateTime.UtcNow.AddMinutes(20));

            var result = await ValidateAsync(token, parameters);

            Assert.IsFalse(result.IsValid);
            Assert.IsInstanceOfType<SecurityTokenNotYetValidException>(result.Exception);
        }

        [TestMethod]
        public void JsonWebTokenOptions_WithClockSkew_Negative_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new JsonWebTokenOptions().WithClockSkew(-1));
        }

        [TestMethod]
        public void JsonWebTokenSettings_ClockSkewSeconds_Ignores_Negative()
        {
            var settings = new JsonWebTokenSettings { ClockSkewSeconds = -5 };

            Assert.AreEqual(JsonWebTokenSettings.DefaultClockSkewSeconds, settings.ClockSkewSeconds);

            settings.ClockSkewSeconds = 0;

            Assert.AreEqual(0, settings.ClockSkewSeconds);
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

            // No se comprueba con qué AuthenticationProperties cierra la sesión: hoy reutiliza las del último inicio
            // de sesión, guardadas en un singleton (fallo anotado en el Pendiente de security.md).
            authentication.Verify(x => x.SignOutAsync(httpContext, "Galletas", It.IsAny<AuthenticationProperties>()), Times.Once);
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

        [TestMethod]
        public async Task CookiesService_TwoParallelRequests_DoNotShare_AuthenticationProperties()
        {
            // El servicio es un singleton. Hasta la 2.5.0 guardaba las AuthenticationProperties del último SignInAsync,
            // de cualquier petición, y el SignOutAsync de otra petición las usaba: aquí, Ana cerraba sesión con las de Beto.
            var accessor = new HttpContextAccessor();
            var authentication = new Mock<IAuthenticationService>();
            var signOuts = new System.Collections.Concurrent.ConcurrentDictionary<HttpContext, AuthenticationProperties?>();

            authentication
                .Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Returns(Task.CompletedTask);
            authentication
                .Setup(x => x.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, AuthenticationProperties>((context, _, properties) => signOuts[context] = properties)
                .Returns(Task.CompletedTask);

            var service = new CookiesService(new CookiesSettings(), authentication.Object, accessor);

            var contextAna = new DefaultHttpContext();
            var contextBeto = new DefaultHttpContext();
            var anaSignedIn = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var betoSignedIn = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            async Task RequestAna()
            {
                accessor.HttpContext = contextAna;
                await service.SignInAsync(new[] { new Claim(ClaimTypes.Name, "ana") }, x => x.RedirectUri = "/ana");
                anaSignedIn.SetResult();
                await betoSignedIn.Task;
                await service.SignOutAsync();
            }

            async Task RequestBeto()
            {
                await anaSignedIn.Task;
                accessor.HttpContext = contextBeto;
                await service.SignInAsync(new[] { new Claim(ClaimTypes.Name, "beto") }, x => x.RedirectUri = "/beto");
                betoSignedIn.SetResult();
                await service.SignOutAsync();
            }

            await Task.WhenAll(Task.Run(RequestAna), Task.Run(RequestBeto));

            Assert.AreEqual(2, signOuts.Count);
            Assert.AreNotEqual("/beto", signOuts[contextAna]?.RedirectUri);
            Assert.AreNotEqual("/ana", signOuts[contextBeto]?.RedirectUri);
            Assert.IsNull(signOuts[contextAna]);
            Assert.IsNull(signOuts[contextBeto]);
        }

        [TestMethod]
        public async Task CookiesService_Uses_AuthenticationService_Of_The_Request()
        {
            // IAuthenticationService es scoped: hasta la 2.5.0 se usaba siempre el del registro, sacado de un contenedor
            // temporal y compartido por todas las peticiones. Ahora se usa el de la petición.
            var requestAuthentication = new Mock<IAuthenticationService>();
            var registeredAuthentication = new Mock<IAuthenticationService>();

            var requestServices = new ServiceCollection();
            requestServices.AddSingleton(requestAuthentication.Object);

            var httpContext = new DefaultHttpContext { RequestServices = requestServices.BuildServiceProvider() };
            var accessor = new Mock<IHttpContextAccessor>();
            accessor.SetupGet(x => x.HttpContext).Returns(httpContext);

            var service = new CookiesService(new CookiesSettings(), registeredAuthentication.Object, accessor.Object);

            await service.SignInAsync(new[] { new Claim(ClaimTypes.Name, "ana") });
            await service.SignOutAsync();

            requestAuthentication.Verify(x => x.SignInAsync(httpContext, CookieAuthenticationDefaults.AuthenticationScheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Once);
            requestAuthentication.Verify(x => x.SignOutAsync(httpContext, CookieAuthenticationDefaults.AuthenticationScheme, It.IsAny<AuthenticationProperties>()), Times.Once);
            registeredAuthentication.VerifyNoOtherCalls();
        }

        [TestMethod]
        public async Task CookiesService_RequestWithoutAuthenticationService_Throws()
        {
            // Con contenedor de petición y sin IAuthenticationService no se usa en silencio el del registro.
            var httpContext = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() };
            var accessor = new Mock<IHttpContextAccessor>();
            accessor.SetupGet(x => x.HttpContext).Returns(httpContext);
            var registeredAuthentication = new Mock<IAuthenticationService>();

            var service = new CookiesService(new CookiesSettings(), registeredAuthentication.Object, accessor.Object);

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => service.SignInAsync(new[] { new Claim(ClaimTypes.Name, "ana") }));
            registeredAuthentication.VerifyNoOtherCalls();
        }

        [TestMethod]
        public void LoadCookies_Registers_CookiesService_PerRequest()
        {
            // Hasta la 2.5.2 era un singleton creado al registrar, con un IAuthenticationService de un contenedor temporal.
            var services = new ServiceCollection();
            var provider = LoadCookies(services);

            Assert.AreEqual(ServiceLifetime.Scoped, services.Single(x => x.ServiceType == typeof(ICookiesService)).Lifetime);

            using var scope1 = provider.CreateScope();
            using var scope2 = provider.CreateScope();

            var first = scope1.ServiceProvider.GetRequiredService<ICookiesService>();

            Assert.AreSame(first, scope1.ServiceProvider.GetRequiredService<ICookiesService>());
            Assert.AreNotSame(first, scope2.ServiceProvider.GetRequiredService<ICookiesService>());
        }

        [TestMethod]
        public void LoadCookies_CookiesService_Resolves_With_ValidateScopes()
        {
            // Con la validación de ámbitos de Development, un servicio por petición se resuelve dentro de un ámbito.
            var services = new ServiceCollection();
            LoadCookies(services);

            using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
            using var scope = provider.CreateScope();

            Assert.IsInstanceOfType<CookiesService>(scope.ServiceProvider.GetRequiredService<ICookiesService>());
            Assert.ThrowsExactly<InvalidOperationException>(() => provider.GetRequiredService<ICookiesService>());
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
            // Las comillas del valor salen escapadas (\u0022) en el JSON; el nombre en texto plano lo prueba WithPlainTextNameClaim.
            var httpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "\"ana-test\"") }, "Test")),
            };

            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            StringAssert.Contains(exception.Message, "AccessDeniedDateTime");
            StringAssert.Contains(exception.Message, "\"Username\"");
            StringAssert.Contains(exception.Message, "ana-test");

            // User, como en la 2.6.1, sale del nombre leído como JSON: sin comillas.
            using var json = System.Text.Json.JsonDocument.Parse(exception.Message);
            Assert.AreEqual("ana-test", json.RootElement.GetProperty("User").GetString());
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

        [TestMethod]
        public async Task RedirectToAccessDenied_WithPlainTextNameClaim_Throws_Unauthorized()
        {
            // Hasta la 2.6.1, con el nombre en texto plano (como lo pone ASP.NET Core) lanzaba JsonException:
            // HttpContext.ToDetails de Shared deserializa los valores de las claims como JSON.
            var httpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "ana-texto") }, "Test")),
            };
            httpContext.Request.Path = "/privado";

            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            StringAssert.Contains(exception.Message, "ana-texto");
            StringAssert.Contains(exception.Message, "/privado");
        }

        [TestMethod]
        public async Task RedirectToAccessDenied_WithoutUser_DoesNotLeak_ServerUserName()
        {
            // Hasta la 2.6.1, sin usuario, el mensaje llevaba Environment.UserName del servidor.
            var httpContext = new DefaultHttpContext();
            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            Assert.IsFalse(exception.Message.Contains($"\"{Environment.UserName}\"", StringComparison.Ordinal), exception.Message);
            StringAssert.Contains(exception.Message, "\"Anonymous\"");
        }

        [TestMethod]
        public async Task RedirectToAccessDenied_Keeps_Details_Shape()
        {
            var httpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "josé") }, "Test")),
            };
            httpContext.Request.Scheme = "https";
            httpContext.Request.Host = new HostString("app.test");
            httpContext.Request.Path = "/privado";
            httpContext.Request.Headers.UserAgent = "agente-test";

            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor { HttpContext = httpContext });

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(httpContext)));

            using var json = System.Text.Json.JsonDocument.Parse(exception.Message);
            var root = json.RootElement;
            Assert.AreEqual("josé", root.GetProperty("User").GetString());
            Assert.AreEqual("agente-test", root.GetProperty("UserAgent")[0].GetString());
            Assert.AreEqual("https://app.test/privado", root.GetProperty("Request").GetString());
            Assert.AreEqual("josé", root.GetProperty("OptionalData").GetProperty("Username")[0].GetString());
            Assert.AreEqual(1, root.GetProperty("OptionalData").GetProperty("AccessDeniedDateTime").GetArrayLength());
        }

        [TestMethod]
        public async Task RedirectToAccessDenied_WithoutHttpContext_Throws_Unauthorized()
        {
            // Hasta la 2.6.1, sin HttpContext lanzaba SharedException al serializar un nulo.
            var events = new CustomCookieAuthenticationEvents(new HttpContextAccessor());

            var exception = await Assert.ThrowsExactlyAsync<UnauthorizedAccessException>(() => events.RedirectToAccessDenied(CreateRedirectContext(new DefaultHttpContext())));

            using var json = System.Text.Json.JsonDocument.Parse(exception.Message);
            Assert.AreEqual("Anonymous", json.RootElement.GetProperty("User").GetString());
            Assert.IsFalse(json.RootElement.TryGetProperty("Request", out _));
        }

        #endregion CustomCookieAuthenticationEvents
    }
}
