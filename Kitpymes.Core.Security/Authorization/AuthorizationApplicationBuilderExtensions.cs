// -----------------------------------------------------------------------
// <copyright file="AuthorizationApplicationBuilderExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication;

using Microsoft.AspNetCore.Builder;

/*
    Clase de extensión AuthorizationApplicationBuilderExtensions
    Contiene las extensiones de los servicios de las autenticación
*/

/// <summary>
/// Clase de extensión <c>AuthorizationApplicationBuilderExtensions</c>.
/// Contiene las extensiones de los servicios de las autenticación.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones de los servicios para la autenticación.</para>
/// </remarks>
public static class AuthorizationApplicationBuilderExtensions
{
    /// <summary>
    /// Carga el middlware para captar los errores de autenticación.
    /// </summary>
    /// <param name="application">Define una clase que proporciona los mecanismos para configurar la solicitud de una aplicación.</param>
    /// <returns>IApplicationBuilder.</returns>
    public static IApplicationBuilder LoadAuthorization(this IApplicationBuilder application)
    {
        application.UseAuthorization();

        return application;
    }
}
