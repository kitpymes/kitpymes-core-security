// -----------------------------------------------------------------------
// <copyright file="SecuritySettings.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security;

using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Authorization;
using Kitpymes.Core.Security.Authorization.Settings;
using Kitpymes.Core.Security.Encryptor.Settings;
using Kitpymes.Core.Security.Password.Settings;
using Microsoft.AspNetCore.Authorization;

/*
   Clase de configuración SecuritySettings
   Contiene las propiedades para la configuración de la seguridad
*/

/// <summary>
/// Clase de configuración <c>SecuritySettings</c>.
/// Contiene las propiedades para la configuración de la seguridad.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las propiedades para la configuración de la seguridad.</para>
/// </remarks>
public class SecuritySettings
{
    /// <summary>
    /// Obtiene o establece la configuración de la encriptación.
    /// </summary>
    public EncryptorSettings? EncryptorSettings { get; set; }

    /// <summary>
    /// Obtiene o establece la configuración de la autenticación.
    /// </summary>
    public AuthenticationSettings? AuthenticationSettings { get; set; }

    /// <summary>
    /// Obtiene o establece la configuración de la contraseña.
    /// </summary>
    public PasswordSettings? PasswordSettings { get; set; }

    /// <summary>
    /// Obtiene o establece la configuración de la autorización.
    /// </summary>
    public AuthorizationSettings? AuthorizationSettings { get; set; }
}
