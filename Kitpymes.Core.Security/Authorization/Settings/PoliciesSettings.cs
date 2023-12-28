// -----------------------------------------------------------------------
// <copyright file="PoliciesSettings.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Settings;

using System.Collections.Generic;

/*
    Clase para la configuración de la fecha de expiración PoliciesSettings
    Contiene los métodos para la configuración de la fecha de expiración
*/

/// <summary>
/// Clase para la configuración de la fecha de expiración <c>PoliciesSettings</c>.
/// Contiene los métodos para la configuración de la fecha de expiración.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todos los métodos para la configuración de la fecha de expiración.</para>
/// </remarks>
public class PoliciesSettings
{
    /// <summary>
    /// Obtiene o establece la politica de roles.
    /// </summary>
    public IEnumerable<string>? Roles { get; set; }

    /// <summary>
    /// Obtiene o establece la politica de permisos.
    /// </summary>
    public IEnumerable<string>? Permissions { get; set; }
}
