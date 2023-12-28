// -----------------------------------------------------------------------
// <copyright file="AuthenticationServiceCollectionExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication;

using System;
using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Authentication.Cookies.Extensions;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Extensions;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/*
    Clase de extensión AuthenticationServiceCollectionExtensions
    Contiene las extensiones de los servicios para la autenticación
*/

/// <summary>
/// Clase de extensión <c>AuthenticationServiceCollectionExtensions</c>.
/// Contiene las extensiones de los servicios para la autenticación.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones para los servicios de autenticación.</para>
/// </remarks>
internal static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Carga el servicio de autenticación.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="configuration">Configuración del servicio de autenticación.</param>
    /// <returns>IServiceCollection | ArgumentException: si SecuritySettings o AuthenticationSettings es nulo.</returns>
    public static IServiceCollection LoadAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        var settings = configuration?
            .GetSection(nameof(SecuritySettings))?
                .GetSection(nameof(AuthenticationSettings))?
                    .Get<AuthenticationSettings>();

        return services.LoadAuthentication(settings);
    }

    /// <summary>
    /// Carga el servicio de autenticación.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="options">Configuración del servicio de autenticación.</param>
    /// <returns>IServiceCollection | ArgumentException: si AuthenticationSettings es nulo.</returns>
    public static IServiceCollection LoadAuthentication(this IServiceCollection services, Action<AuthenticationSettings> options)
    {
        var settings = options.ToConfigureOrDefault();

        return services.LoadAuthentication(settings);
    }

    /// <summary>
    /// Carga el servicio de autenticación.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="settings">Configuración del servicio de autenticación.</param>
    /// <returns>IServiceCollection | ArgumentException: si AuthenticationSettings es nulo.</returns>
    public static IServiceCollection LoadAuthentication(this IServiceCollection services, AuthenticationSettings? settings)
    {
        settings.ToThrowIfNullOrEmpty();

        if (settings.JsonWebTokenSettings?.Enabled == true)
        {
            services.LoadAuthJsonWebToken(settings.JsonWebTokenSettings);
        }

        if (settings.CookiesSettings?.Enabled == true)
        {
            services.LoadAuthCookies(settings.CookiesSettings);
        }

        if (settings.OAuthSettings?.Enabled == true)
        {
            // services.LoadOAuth(settings.OAuthSettings);
            throw new NotImplementedException();
        }

        return services;
    }
}