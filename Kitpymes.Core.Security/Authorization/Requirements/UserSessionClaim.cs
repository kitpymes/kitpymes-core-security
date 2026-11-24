// -----------------------------------------------------------------------
// <copyright file="UserSessionClaim.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Requirements;

using System.Security.Claims;
using System.Text.Json;
using Kitpymes.Core.Api.ApiSession;
using Kitpymes.Core.Shared.Extensions;

/// <summary>
/// Lee la sesión del usuario de su claim.
/// </summary>
internal static class UserSessionClaim
{
    /// <summary>
    /// Obtiene la sesión del usuario guardada en la claim <see cref="ApiSession.UserClaimType"/>.
    /// </summary>
    /// <param name="user">Usuario de la petición.</param>
    /// <returns>La sesión, o null si no hay claim o su valor no es una sesión en JSON.</returns>
    public static UserSession? Get(ClaimsPrincipal user)
    {
        try
        {
            return user.ToGet<UserSession>(ApiSession.UserClaimType);
        }
        catch (JsonException)
        {
            // Una claim mal formada es una petición sin sesión válida: se deniega, no se lanza.
            return null;
        }
    }
}
