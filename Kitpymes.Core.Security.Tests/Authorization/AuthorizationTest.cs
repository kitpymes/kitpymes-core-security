using Kitpymes.Core.Api.ApiSession;
using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Authorization;
using Kitpymes.Core.Security.Authorization.Requirements;
using Kitpymes.Core.Security.Authorization.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Kitypmes.Core.Security.Tests
{
    [TestClass]
    public class AuthorizationTest
    {
        private static ClaimsPrincipal CreateUser(UserSession? user)
        {
            var claims = user is null
                ? new List<Claim>()
                : new List<Claim> { new Claim(ApiSession.UserClaimType, user.ToSerialize()) };

            return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
        }

        private static async Task<AuthorizationHandlerContext> HandleAsync(IAuthorizationHandler handler, IAuthorizationRequirement requirement, UserSession? user)
        {
            var context = new AuthorizationHandlerContext(new[] { requirement }, CreateUser(user), null);

            await handler.HandleAsync(context);

            return context;
        }

        #region RoleRequirement

        [TestMethod]
        public void RoleRequirement_Returns_Role()
        {
            Assert.AreEqual("Admin", new RoleRequirement("Admin").Role);
        }

        [TestMethod]
        public async Task RoleRequirementHandler_Passing_SameRole_Succeeds()
        {
            var context = await HandleAsync(new RoleRequirementHandler(), new RoleRequirement("Admin"), new UserSession { Role = "Admin" });

            Assert.IsTrue(context.HasSucceeded);
            Assert.IsFalse(context.HasFailed);
        }

        [TestMethod]
        public async Task RoleRequirementHandler_Passing_NoUser_Fails()
        {
            var context = await HandleAsync(new RoleRequirementHandler(), new RoleRequirement("Admin"), null);

            Assert.IsTrue(context.HasFailed);
            Assert.IsFalse(context.HasSucceeded);
            StringAssert.Contains(context.FailureReasons.Single().Message, "Necesita ingresar al sistema");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("User")]
        [DataRow("admin")]
        public async Task RoleRequirementHandler_Passing_OtherOrNoRole_Fails(string? role)
        {
            var context = await HandleAsync(new RoleRequirementHandler(), new RoleRequirement("Admin"), new UserSession { Role = role });

            Assert.IsTrue(context.HasFailed);
            Assert.IsFalse(context.HasSucceeded);
            StringAssert.Contains(context.FailureReasons.Single().Message, "no posee el rol requerido");
        }

        #endregion RoleRequirement

        #region PermissionRequirement

        [TestMethod]
        public void PermissionRequirement_Returns_Permission()
        {
            Assert.AreEqual("Users.Read", new PermissionRequirement("Users.Read").Permission);
        }

        [TestMethod]
        public async Task PermissionRequirementHandler_Passing_UserWithPermission_Succeeds()
        {
            var user = new UserSession { Permissions = new[] { "Users.Write", "Users.Read" } };

            var context = await HandleAsync(new PermissionRequirementHandler(), new PermissionRequirement("Users.Read"), user);

            Assert.IsTrue(context.HasSucceeded);
            Assert.IsFalse(context.HasFailed);
        }

        [TestMethod]
        public async Task PermissionRequirementHandler_Passing_NoUser_Fails()
        {
            var context = await HandleAsync(new PermissionRequirementHandler(), new PermissionRequirement("Users.Read"), null);

            Assert.IsTrue(context.HasFailed);
            Assert.IsFalse(context.HasSucceeded);
            StringAssert.Contains(context.FailureReasons.Single().Message, "Necesita ingresar al sistema");
        }

        [TestMethod]
        public async Task PermissionRequirementHandler_Passing_NoPermissions_Fails()
        {
            foreach (var permissions in new[] { null, Array.Empty<string>(), new[] { "Users.Write" } })
            {
                var context = await HandleAsync(new PermissionRequirementHandler(), new PermissionRequirement("Users.Read"), new UserSession { Permissions = permissions });

                Assert.IsTrue(context.HasFailed);
                Assert.IsFalse(context.HasSucceeded);
                StringAssert.Contains(context.FailureReasons.Single().Message, "No posee el permiso requerido");
            }
        }

        [TestMethod]
        public async Task RequirementHandlers_WithMalformedUserClaim_Fail()
        {
            // Hasta la 2.6.1, una claim de sesión que no es JSON hacía lanzar JsonException en el manejador (un 500)
            // en vez de denegar.
            var user = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ApiSession.UserClaimType, "no-es-json") }, "Test"));

            var roleContext = new AuthorizationHandlerContext(new[] { new RoleRequirement("Admin") }, user, null);
            await new RoleRequirementHandler().HandleAsync(roleContext);

            var permissionContext = new AuthorizationHandlerContext(new[] { new PermissionRequirement("Users.Read") }, user, null);
            await new PermissionRequirementHandler().HandleAsync(permissionContext);

            Assert.IsTrue(roleContext.HasFailed);
            Assert.IsTrue(permissionContext.HasFailed);
            StringAssert.Contains(roleContext.FailureReasons.Single().Message, "Necesita ingresar al sistema");
        }

        #endregion PermissionRequirement

        #region LoadAuthorization

        private static AuthorizationOptions GetOptions(IServiceCollection services)
            => services.BuildServiceProvider().GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        [TestMethod]
        public void LoadAuthorization_Passing_Null_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new ServiceCollection().LoadAuthorization(null));
        }

        [TestMethod]
        public void LoadAuthorization_Passing_Disabled_DoesNothing()
        {
            var services = new ServiceCollection();

            services.LoadAuthorization(new AuthorizationSettings { Enabled = false, Policies = new PoliciesSettings { Roles = new[] { "Admin" } } });

            Assert.AreEqual(0, services.Count);
        }

        [TestMethod]
        public void LoadAuthorization_Passing_Policies_Adds_Role_And_Permission_Policies_And_Handlers()
        {
            var services = new ServiceCollection();

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                Policies = new PoliciesSettings
                {
                    Roles = new[] { "Admin", "User" },
                    Permissions = new[] { "Users.Read" },
                },
            });

            var options = GetOptions(services);

            Assert.IsInstanceOfType<RoleRequirement>(options.GetPolicy("Admin")!.Requirements.Single());
            Assert.AreEqual("User", ((RoleRequirement)options.GetPolicy("User")!.Requirements.Single()).Role);
            Assert.AreEqual("Users.Read", ((PermissionRequirement)options.GetPolicy("Users.Read")!.Requirements.Single()).Permission);

            var handlers = services.BuildServiceProvider().GetServices<IAuthorizationHandler>().Select(x => x.GetType()).ToList();

            CollectionAssert.Contains(handlers, typeof(RoleRequirementHandler));
            CollectionAssert.Contains(handlers, typeof(PermissionRequirementHandler));
        }

        [TestMethod]
        public void LoadAuthorization_Passing_EmptyPolicies_Adds_None()
        {
            var services = new ServiceCollection();

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                Policies = new PoliciesSettings { Roles = Array.Empty<string>(), Permissions = null },
            });

            var options = GetOptions(services);

            Assert.IsNull(options.GetPolicy("Admin"));
        }

        [TestMethod]
        public void LoadAuthorization_Passing_RequireAuthenticatedUser_Sets_DefaultPolicy()
        {
            var services = new ServiceCollection();

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequireAuthenticatedUser = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            Assert.IsInstanceOfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(policy.Requirements.Single());
            Assert.AreEqual(0, policy.AuthenticationSchemes.Count);
        }

        [TestMethod]
        public void LoadAuthorization_Passing_RequiredSchemes_Adds_JsonWebTokenScheme_From_Configuration()
        {
            var services = new ServiceCollection();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthenticationSettings:Enabled"] = "true",
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:Enabled"] = "true",
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:AuthenticateScheme"] = "EsquemaTest",
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequiredSchemes = true, RequireAuthenticatedUser = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            CollectionAssert.AreEqual(new[] { "EsquemaTest" }, policy.AuthenticationSchemes.ToArray());
        }

        [TestMethod]
        [DataRow("false", "true")]
        [DataRow("true", "false")]
        public void LoadAuthorization_Passing_RequiredSchemes_WithoutJsonWebToken_Adds_NoScheme(string authenticationEnabled, string jsonWebTokenEnabled)
        {
            var services = new ServiceCollection();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthenticationSettings:Enabled"] = authenticationEnabled,
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:Enabled"] = jsonWebTokenEnabled,
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:AuthenticateScheme"] = "EsquemaTest",
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequiredSchemes = true, RequireAuthenticatedUser = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            Assert.AreEqual(0, policy.AuthenticationSchemes.Count);
        }

        private static IServiceCollection ServicesWithJsonWebTokenScheme(string jsonWebTokenEnabled = "true")
        {
            var services = new ServiceCollection();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthenticationSettings:Enabled"] = "true",
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:Enabled"] = jsonWebTokenEnabled,
                    ["SecuritySettings:AuthenticationSettings:JsonWebTokenSettings:AuthenticateScheme"] = "EsquemaTest",
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            return services;
        }

        [TestMethod]
        public void LoadAuthorization_Passing_OnlyRequiredSchemes_Requires_AuthenticatedUser_With_Scheme()
        {
            // Hasta la 2.6.0, con RequiredSchemes sola la política por defecto se quedaba sin requisitos y ASP.NET Core
            // lanzaba al resolver las opciones: la aplicación fallaba en la primera petición con [Authorize].
            var services = ServicesWithJsonWebTokenScheme();

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequiredSchemes = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            CollectionAssert.AreEqual(new[] { "EsquemaTest" }, policy.AuthenticationSchemes.ToArray());
            Assert.IsInstanceOfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(policy.Requirements.Single());
        }

        [TestMethod]
        public void LoadAuthorization_Passing_OnlyRequiredSchemes_WithoutJsonWebToken_Keeps_FrameworkDefaultPolicy()
        {
            // Sin esquema de JWT no hay nada que añadir: se queda la política por defecto de ASP.NET Core.
            var services = ServicesWithJsonWebTokenScheme(jsonWebTokenEnabled: "false");

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequiredSchemes = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            Assert.AreEqual(0, policy.AuthenticationSchemes.Count);
            Assert.IsInstanceOfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(policy.Requirements.Single());
        }

        private static AuthorizationPolicy AddCustomDefaultPolicy(IServiceCollection services)
        {
            // La aplicación ya tenía su propia política por defecto antes de LoadAuthorization.
            var custom = new AuthorizationPolicyBuilder("Cookies").RequireClaim("rol").Build();

            services.AddAuthorization(x => x.DefaultPolicy = custom);

            return custom;
        }

        [TestMethod]
        public void LoadAuthorization_WithCustomDefaultPolicy_RequireAuthenticatedUser_Replaces_It()
        {
            var services = ServicesWithJsonWebTokenScheme(jsonWebTokenEnabled: "false");
            AddCustomDefaultPolicy(services);

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequireAuthenticatedUser = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            Assert.IsInstanceOfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(policy.Requirements.Single());
        }

        [TestMethod]
        public void LoadAuthorization_WithCustomDefaultPolicy_OnlyRequiredSchemes_Keeps_Its_Requirements_And_Adds_Scheme()
        {
            var services = ServicesWithJsonWebTokenScheme();
            var custom = AddCustomDefaultPolicy(services);

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings { RequiredSchemes = true },
            });

            var policy = GetOptions(services).DefaultPolicy;

            // Conserva los requisitos y el esquema de la política de la aplicación, y añade el del JWT.
            CollectionAssert.AreEqual(custom.Requirements.ToArray(), policy.Requirements.ToArray());
            CollectionAssert.AreEquivalent(new[] { "Cookies", "EsquemaTest" }, policy.AuthenticationSchemes.ToArray());
        }

        [TestMethod]
        public void LoadAuthorization_WithCustomDefaultPolicy_WithoutRules_Keeps_It()
        {
            var services = ServicesWithJsonWebTokenScheme();
            var custom = AddCustomDefaultPolicy(services);

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings(),
            });

            Assert.AreSame(custom, GetOptions(services).DefaultPolicy);
        }

        [TestMethod]
        public void LoadAuthorization_Passing_DefaultPolicyWithoutRules_Keeps_FrameworkDefaultPolicy()
        {
            var services = new ServiceCollection();

            services.LoadAuthorization(new AuthorizationSettings
            {
                Enabled = true,
                DefaultPolicy = new DefaultPolicySettings(),
            });

            var expected = new AuthorizationOptions().DefaultPolicy;
            var policy = GetOptions(services).DefaultPolicy;

            Assert.AreEqual(expected.Requirements.Count, policy.Requirements.Count);
            Assert.IsInstanceOfType<Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement>(policy.Requirements.Single());
        }

        [TestMethod]
        public void SecurityOptions_WithAuthorization_Enables_It()
        {
            var settings = new AuthorizationSettings();

            var options = new SecurityOptions().WithAuthorization(settings);

            Assert.AreEqual(true, options.SecuritySettings.AuthorizationSettings!.Enabled);
        }

        [TestMethod]
        public void LoadSecurity_Passing_Authorization_Registers_Handlers()
        {
            var services = new ServiceCollection();

            services.LoadSecurity(sec => sec.WithAuthorization(new AuthorizationSettings()));

            var handlers = services.BuildServiceProvider().GetServices<IAuthorizationHandler>().Select(x => x.GetType()).ToList();

            CollectionAssert.Contains(handlers, typeof(RoleRequirementHandler));
        }

        [TestMethod]
        public void LoadSecurity_Passing_Policies_Uses_Configuration_And_Policies()
        {
            var services = new ServiceCollection();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:AuthorizationSettings:Enabled"] = "true",
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            services.LoadSecurity(new PoliciesSettings { Roles = new[] { "Admin" } });

            Assert.IsNotNull(GetOptions(services).GetPolicy("Admin"));
        }

        [TestMethod]
        public void LoadSecurity_Passing_Policies_WithoutAuthorizationSection_Creates_It_Disabled()
        {
            var services = new ServiceCollection();

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:PasswordSettings:Enabled"] = "false",
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            services.LoadSecurity(new PoliciesSettings { Roles = new[] { "Admin" } });

            Assert.IsFalse(services.Any(x => x.ServiceType == typeof(IAuthorizationHandler)));
        }

        [TestMethod]
        public void LoadSecurity_Passing_NoConfiguration_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new ServiceCollection().LoadSecurity(new PoliciesSettings { Roles = new[] { "Admin" } }));
        }

        #endregion LoadAuthorization

        #region ApplicationBuilder

        [TestMethod]
        public void ApplicationBuilder_LoadAuthorization_WithoutAuthorizationServices_Throws()
        {
            // UseAuthorization comprueba que AddAuthorization se llamó: si no se llama a UseAuthorization, no lanza.
            var application = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

            Assert.ThrowsExactly<InvalidOperationException>(() => application.LoadAuthorization());
        }

        [TestMethod]
        public void ApplicationBuilder_LoadSecurity_WithoutAuthorizationServices_Throws()
        {
            var application = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

            Assert.ThrowsExactly<InvalidOperationException>(() => application.LoadSecurity());
        }

        [TestMethod]
        public async Task ApplicationBuilder_LoadAuthentication_Adds_AuthenticationMiddleware()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddAuthentication();

            var provider = services.BuildServiceProvider();
            var application = new ApplicationBuilder(provider);

            var returned = application.LoadAuthentication();

            Assert.AreSame(application, returned);

            var context = new Microsoft.AspNetCore.Http.DefaultHttpContext { RequestServices = provider };

            await application.Build()(context);

            // El middleware de autenticación deja esta característica en la petición.
            Assert.IsNotNull(context.Features.Get<Microsoft.AspNetCore.Authentication.IAuthenticationFeature>());
        }

        #endregion ApplicationBuilder
    }
}
