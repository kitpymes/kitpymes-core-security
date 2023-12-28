// -----------------------------------------------------------------------
// <copyright file="SecurityServiceCollectionExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security;

using System;
using Kitpymes.Core.Shared.Extensions;
using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Encryptor.Extensions;
using Kitpymes.Core.Security.Password.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Kitpymes.Core.Security.Authorization;
using Kitpymes.Core.Security.Authorization.Settings;

/*
    Clase de extensión SecurityServiceCollectionExtensions
    Contiene las extensiones de los servicios de seguridad
*/

/// <summary>
/// Clase de extensión <c>SecurityServiceCollectionExtensions</c>.
/// Contiene las extensiones de los servicios de seguridad.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones de los servicios para la seguridad.</para>
/// </remarks>
public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Carga el servicio de seguridad.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="policies">Políticas de seguridad.</param>
    /// <returns>IServiceCollection | ArgumentException: si SecuritySettings es nulo.</returns>
    public static IServiceCollection LoadSecurity(this IServiceCollection services, PoliciesSettings? policies = null)
    {
        var configuration = services.ToService<IConfiguration>();

        var settings = configuration?.GetSection(nameof(SecuritySettings))?.Get<SecuritySettings>();

        if (!settings.ToIsNullOrEmpty() && !policies.ToIsNullOrEmpty())
        {
            settings.AuthorizationSettings ??= new AuthorizationSettings();

            settings.AuthorizationSettings.Policies = policies;
        }

        services.LoadSecurity(settings);

        return services;
    }

    /// <summary>
    /// Carga el servicio de seguridad.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="options">Configuración del servicio de seguridad.</param>
    /// <returns>IServiceCollection | ArgumentException: si SecuritySettings es nulo.</returns>
    public static IServiceCollection LoadSecurity(this IServiceCollection services, Action<SecurityOptions> options)
    {
        var settings = options.ToConfigureOrDefault().SecuritySettings;

        services.LoadSecurity(settings);

        return services;
    }

    /// <summary>
    /// Carga el servicio de seguridad.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="settings">Configuración del servicio de seguridad.</param>
    /// <returns>IServiceCollection | ArgumentException: si SecuritySettings es nulo.</returns>
    public static IServiceCollection LoadSecurity(this IServiceCollection services, SecuritySettings? settings)
    {
        settings.ToThrowIfNullOrEmpty();

        services.ToSettings<SecuritySettings>();

        if (settings.EncryptorSettings?.Enabled == true)
        {
            services.LoadEncryptor(settings.EncryptorSettings);
        }

        if (settings.PasswordSettings?.Enabled == true)
        {
            services.LoadPassword(settings.PasswordSettings);
        }

        if (settings.AuthenticationSettings?.Enabled == true)
        {
            services.LoadAuthentication(settings.AuthenticationSettings);
        }

        if (settings.AuthorizationSettings?.Enabled == true)
        {
            services.LoadAuthorization(settings.AuthorizationSettings);
        }

        return services;
    }
}
