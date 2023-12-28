// -----------------------------------------------------------------------
// <copyright file="SecurityOptions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security;

using System;
using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Security.Authorization;
using Kitpymes.Core.Security.Authorization.Settings;
using Kitpymes.Core.Security.Encryptor.Settings;
using Kitpymes.Core.Security.Password.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

/*
   Clase de configuración SecurityOptions
   Contiene las propiedades para la configuración de la seguridad
*/

/// <summary>
/// Clase de configuración <c>SecurityOptions</c>.
/// Contiene las propiedades para la configuración de la seguridad.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las propiedades para la configuración de la seguridad.</para>
/// </remarks>
public class SecurityOptions
{
    /// <summary>
    /// Obtiene la configuración de la seguridad.
    /// </summary>
    public SecuritySettings SecuritySettings { get; private set; } = new SecuritySettings();

    #region Encryptor

    /// <summary>
    /// Indica si se utilizara el servicio de encriptación.
    /// </summary>
    /// <param name="configuration">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si EncryptorSettings es nulo.</returns>
    public SecurityOptions WithEncryptor(IConfiguration configuration)
    {
        var settings = configuration?.GetSection(nameof(SecuritySettings))?.GetSection(nameof(EncryptorSettings))?.Get<EncryptorSettings>();

        var securityOptions = WithEncryptor(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio de encriptación.
    /// </summary>
    /// <param name="options">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si EncryptorSettings es nulo.</returns>
    public SecurityOptions WithEncryptor(Action<EncryptorOptions> options)
    {
        var settings = options.ToConfigureOrDefault().EncryptorSettings;

        var securityOptions = WithEncryptor(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio de encriptación.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si EncryptorSettings es nulo.</returns>
    public SecurityOptions WithEncryptor(EncryptorSettings? settings)
    {
        SecuritySettings.EncryptorSettings = settings.ToThrowIfNullOrEmpty(nameof(settings));

        return this;
    }

    #endregion Encryptor

    #region Authorization

    /// <summary>
    /// Indica si se utilizara el servicio de autorización.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>SecurityOptions.</returns>
    public SecurityOptions WithAuthorization(AuthorizationSettings? settings)
    {
        SecuritySettings.AuthorizationSettings = settings.ToThrowIfNullOrEmpty();

        SecuritySettings.AuthorizationSettings.Enabled = true;

        return this;
    }

    #endregion Authorization

    #region Authentication

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="configuration">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si AuthenticationSettings es nulo.</returns>
    public SecurityOptions WithAuthentication(IConfiguration configuration)
    {
        var settings = configuration?
            .GetSection(nameof(SecuritySettings))?
                .GetSection(nameof(AuthenticationSettings))?
                    .Get<AuthenticationSettings>();

        var securityOptions = WithAuthentication(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="options">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si AuthenticationSettings es nulo.</returns>
    public SecurityOptions WithAuthentication(Action<AuthenticationOptions> options)
    {
        var settings = options.ToConfigureOrDefault().AuthenticationSettings;

        var securityOptions = WithAuthentication(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio de autenticación.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si AuthenticationSettings es nulo.</returns>
    public SecurityOptions WithAuthentication(AuthenticationSettings? settings)
    {
        SecuritySettings.AuthenticationSettings = settings.ToThrowIfNullOrEmpty();

        SecuritySettings.AuthenticationSettings.Enabled = true;

        return this;
    }

    #endregion Authentication

    #region Password

    /// <summary>
    /// Indica si se utilizara el servicio para las contraseña.
    /// </summary>
    /// <param name="configuration">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si PasswordSettings es nulo.</returns>
    public SecurityOptions WithPassword(IConfiguration configuration)
    {
        var settings = configuration?
            .GetSection(nameof(SecuritySettings))?
                .GetSection(nameof(PasswordSettings))?
                    .Get<PasswordSettings>();

        var securityOptions = WithPassword(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio para las  contraseña.
    /// </summary>
    /// <param name="options">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si PasswordSettings es nulo.</returns>
    public SecurityOptions WithPassword(Action<PasswordOptions> options)
    {
        var settings = options.ToConfigureOrDefault().PasswordSettings;

        var securityOptions = WithPassword(settings);

        return securityOptions;
    }

    /// <summary>
    /// Indica si se utilizara el servicio para las contraseña.
    /// </summary>
    /// <param name="settings">Configuración del servicio.</param>
    /// <returns>SecurityOptions | ArgumentException: si PasswordSettings es nulo.</returns>
    public SecurityOptions WithPassword(PasswordSettings? settings)
    {
        SecuritySettings.PasswordSettings = settings.ToThrowIfNullOrEmpty();

        return this;
    }

    #endregion Password
}
