// -----------------------------------------------------------------------
// <copyright file="AuthorizationSettings.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Settings;

using System.Text.Json.Serialization;

/*
   Clase de configuración AuthorizationSettings
   Contiene las propiedades para la configuración de la autenticación
*/

/// <summary>
/// Clase de configuración <c>AuthorizationSettings</c>.
/// Contiene las propiedades para la configuración de la autenticación.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las propiedades para la autenticación.</para>
/// </remarks>
public class AuthorizationSettings
{
    /// <summary>
    /// Valor por defecto que indica si esta habilitado el servicio.
    /// </summary>
    public const bool DefaultEnabled = false;

    private bool _enabled = DefaultEnabled;

    /// <summary>
    /// Obtiene o establece un valor que indica el servicio esta habilitado.
    /// <para><strong>Default:</strong> <see cref="DefaultEnabled"/> = false.</para>
    /// </summary>
    public bool? Enabled
    {
        get => _enabled;
        set
        {
            if (value.HasValue)
            {
                _enabled = value.Value;
            }
        }
    }

    /// <summary>
    /// Obtiene un valor que indica si tiene una politica por defecto.
    /// </summary>
    public bool HasDefaultPolicy => DefaultPolicy?.RequiredSchemes == true || DefaultPolicy?.RequireAuthenticatedUser == true;

    /// <summary>
    /// Obtiene o establece la configuración para controlar el comportamiento de la autenticación con Json Web Token.
    /// </summary>
    public DefaultPolicySettings? DefaultPolicy { get; set; }

    /// <summary>
    /// Obtiene o establece la configuración para controlar el comportamiento de la autenticación con Cookies.
    /// </summary>
    [JsonIgnore]
    public PoliciesSettings? Policies { get; set; }
}
