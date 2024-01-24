// -----------------------------------------------------------------------
// <copyright file="JwtBearerChallengeContextExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.JsonWebToken.Extensions;

using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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
    /// Mensaje con detalles del contexto.
    /// </summary>
    /// <param name="context">Contexto de tipo JwtBearerChallengeContext.</param>
    /// <returns>Mensaje de error.</returns>
    public static string ToDetails(this JwtBearerChallengeContext context)
    {
        var token_error = "invalid_token: This request requires a valid JWT access token to be provided";

        if (!context.Error.ToIsNullOrEmpty())
        {
            token_error = context.Error + " | " + context.ErrorDescription;

            if (context.AuthenticateFailure is SecurityTokenInvalidLifetimeException)
            {
                var authenticationException = context.AuthenticateFailure as SecurityTokenInvalidLifetimeException;

                if (authenticationException?.Expires.HasValue == true)
                {
                    token_error += $" | Expires: {authenticationException.Expires.Value:G}";
                }
            }
            else if (context.AuthenticateFailure is SecurityTokenExpiredException)
            {
                var authenticationException = context.AuthenticateFailure as SecurityTokenExpiredException;

                token_error += $" | Expires: {authenticationException?.Expires:G}";
            }
        }

        return token_error;
    }

    /// <summary>
    /// Mensaje con detalles del contexto.
    /// </summary>
    /// <param name="context">Contexto de tipo AuthenticationFailedContext.</param>
    /// <returns>Mensaje de error.</returns>
    public static string ToDetails(this AuthenticationFailedContext context)
    {
        var token_error = "invalid_token: This request requires a valid JWT access token to be provided";

        if (!context.Exception.ToIsNullOrEmpty())
        {
            token_error = context.Exception.Message;

            if (context.Exception is SecurityTokenInvalidLifetimeException)
            {
                var authenticationException = context.Exception as SecurityTokenInvalidLifetimeException;

                if (authenticationException?.Expires.HasValue == true)
                {
                    token_error += $" | Expires: {authenticationException.Expires.Value:G}";
                }
            }
            else if (context.Exception is SecurityTokenExpiredException)
            {
                var authenticationException = context.Exception as SecurityTokenExpiredException;

                token_error += $" | Expires: {authenticationException?.Expires:G}";
            }
        }

        return token_error;
    }
}
