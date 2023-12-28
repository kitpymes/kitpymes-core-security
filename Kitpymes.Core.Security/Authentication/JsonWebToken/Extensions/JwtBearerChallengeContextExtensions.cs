// -----------------------------------------------------------------------
// <copyright file="JwtBearerChallengeContextExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.JsonWebToken.Extensions;

using System.Text;
using System.Text.Json;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

/*
   Clase de extensión JwtBearerChallengeContextExtensions
   Contiene las extensiones del contexto de JwtBearer
*/

/// <summary>
/// Clase de extensión <c>JwtBearerChallengeContextExtensions</c>.
/// Contiene las extensiones del contexto de JwtBearer.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones del contexto de JwtBearer.</para>
/// </remarks>
public static class JwtBearerChallengeContextExtensions
{
    /// <summary>
    /// Detalle del contexto.
    /// </summary>
    /// <param name="context">Contexto.</param>
    /// <returns>string.</returns>
    public static string ToDetails(this JwtBearerChallengeContext context)
    {
        var error = context.Error.ToIsNullOrEmpty() ? "invalid_token" : context.Error;

        var error_description = context.ErrorDescription.ToIsNullOrEmpty()
            ? "This request requires a valid JWT access token to be provided"
            : context.ErrorDescription;

        if (context.AuthenticateFailure?.GetType() == typeof(SecurityTokenExpiredException))
        {
            var authenticationException = context.AuthenticateFailure as SecurityTokenExpiredException;

            if (authenticationException?.Expires.ToIsNullOrEmpty() == false)
            {
                error_description = $"The JWT token expired on {authenticationException?.Expires.ToString("o")}";
            }
        }

        return new { error, error_description }.ToSerialize();
    }
}
