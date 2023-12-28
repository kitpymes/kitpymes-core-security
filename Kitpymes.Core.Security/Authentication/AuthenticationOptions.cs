// -----------------------------------------------------------------------
// <copyright file="AuthenticationOptions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication;

using System;
using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Authentication.Cookies.Settings;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.Extensions.Configuration;

/*
   Clase de configuración AuthenticationOptions
   Contiene las propiedades para la configuración de la autenticación
*/

/// <summary>
/// Clase de configuración <c>AuthenticationOptions</c>.
/// Contiene las propiedades para la configuración de la autenticación.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las propiedades para la autenticación.</para>
/// </remarks>
public class AuthenticationOptions
{
    /// <summary>
    /// Obtiene la configuración de la autenticación.
    /// </summary>
    public AuthenticationSettings AuthenticationSettings { get; private set; } = new AuthenticationSettings();

    #region JsonWebToken

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="configuration">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si JsonWebTokenSettings es nulo.</returns>
    public AuthenticationOptions WithJsonWebToken(IConfiguration configuration)
    {
        var settings = configuration?
            .GetSection($"{nameof(SecuritySettings)}:{nameof(AuthenticationSettings)}:{nameof(JsonWebTokenSettings)}")?
            .Get<JsonWebTokenSettings>();

        var config = settings.ToThrowIfNullOrEmpty(nameof(settings));

        return WithJsonWebToken(config);
    }

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="options">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si JsonWebTokenSettings es nulo.</returns>
    public AuthenticationOptions WithJsonWebToken(Action<JsonWebTokenOptions> options)
    => WithJsonWebToken(options.ToConfigureOrDefault().JsonWebTokenSettings);

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si JsonWebTokenSettings es nulo.</returns>
    public AuthenticationOptions WithJsonWebToken(JsonWebTokenSettings settings)
    {
        AuthenticationSettings.JsonWebTokenSettings = settings.ToThrowIfNullOrEmpty(nameof(settings));

        return this;
    }

    #endregion JsonWebToken

    #region Cookies

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="configuration">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si CookiesSettings es nulo.</returns>
    public AuthenticationOptions WithCookies(IConfiguration configuration)
    {
        var settings = configuration?
            .GetSection($"{nameof(SecuritySettings)}:{nameof(AuthenticationSettings)}:{nameof(CookiesSettings)}")?
            .Get<CookiesSettings>();

        var config = settings.ToThrowIfNullOrEmpty(nameof(settings));

        return WithCookies(config);
    }

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="options">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si CookiesSettings es nulo.</returns>
    public AuthenticationOptions WithCookies(Action<CookiesOptions> options)
    => WithCookies(options.ToConfigureOrDefault().CookiesSettings);

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>AuthenticationOptions | ArgumentException: si CookiesSettings es nulo.</returns>
    public AuthenticationOptions WithCookies(CookiesSettings settings)
    {
        AuthenticationSettings.CookiesSettings = settings.ToThrowIfNullOrEmpty(nameof(settings));

        return this;
    }

    #endregion Cookies
}
