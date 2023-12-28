// -----------------------------------------------------------------------
// <copyright file="AuthorizationCollectionExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization;

using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Security.Authorization.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Kitpymes.Core.Security.Authorization.Requirements;

/*
   Clase de extensión AuthorizationCollectionExtensions
   Contiene las extensiones de los servicios para la autorización
*/

/// <summary>
/// Clase de extensión <c>AuthorizationCollectionExtensions</c>.
/// Contiene las extensiones de los servicios para la autorización.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones de los servicios para la autorización.</para>
/// </remarks>
public static class AuthorizationCollectionExtensions
{
    /// <summary>
    /// Carga el servicio de autorización.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="settings">Configuración del servicio de autorización.</param>
    /// <returns>IServiceCollection.</returns>
    public static IServiceCollection LoadAuthorization(this IServiceCollection services, AuthorizationSettings? settings)
    {
        settings.ToThrowIfNullOrEmpty();

        if (settings.Enabled == true)
        {
            void Options(AuthorizationOptions x)
            {
                if (!settings.DefaultPolicy.ToIsNullOrEmpty())
                {
                    var builder = new AuthorizationPolicyBuilder();

                    if (settings.DefaultPolicy.RequiredSchemes == true)
                    {
                        var configuration = services.ToService<IConfiguration>();

                        var authenticationSettings = configuration?.GetSection(nameof(SecuritySettings))?.Get<SecuritySettings>()?.AuthenticationSettings;

                        if (authenticationSettings?.Enabled == true)
                        {
                            if (authenticationSettings.JsonWebTokenSettings?.Enabled == true)
                            {
                                var authenticateScheme = authenticationSettings.JsonWebTokenSettings.AuthenticateScheme
                                    .ToDefaultIfNullOrEmpty(JsonWebTokenSettings.DefaultAuthenticateScheme);

                                builder.AddAuthenticationSchemes(authenticateScheme);
                            }
                        }
                    }

                    if (settings.DefaultPolicy.RequireAuthenticatedUser == true)
                    {
                        builder.RequireAuthenticatedUser();
                    }

                    if (settings.HasDefaultPolicy)
                    {
                        x.DefaultPolicy = builder.Build();
                    }
                }

                if (!settings.Policies.ToIsNullOrEmpty())
                {
                    if (!settings.Policies.Roles.ToIsNullOrAny())
                    {
                        foreach (var role in settings.Policies.Roles)
                        {
                            x.AddPolicy(role, policy => policy.Requirements.Add(new RoleRequirement(role)));
                        }
                    }

                    if (!settings.Policies.Permissions.ToIsNullOrAny())
                    {
                        foreach (var permission in settings.Policies.Permissions)
                        {
                            x.AddPolicy(permission, policy => policy.Requirements.Add(new PermissionRequirement(permission)));
                        }
                    }
                }
            }

            services.AddAuthorization(Options);

            services.AddTransient<IAuthorizationHandler, RoleRequirementHandler>();
            services.AddTransient<IAuthorizationHandler, PermissionRequirementHandler>();
        }

        return services;
    }
}