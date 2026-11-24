// -----------------------------------------------------------------------
// <copyright file="RoleRequirement.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Requirements;

using System;
using System.Threading.Tasks;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Inicializa una nueva instancia de la clase <see cref="RoleRequirement"/>.
/// </summary>
/// <param name="role">Rol requerido.</param>
public class RoleRequirement(string role)
    : IAuthorizationRequirement
{
    /// <summary>
    /// Obtiene el rol.
    /// </summary>
    public string Role => role;
}

/// <summary>
/// Clase para la autorizacion por roles.
/// </summary>
public class RoleRequirementHandler : AuthorizationHandler<RoleRequirement>
{
    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleRequirement requirement)
    {
        var user = UserSessionClaim.Get(context.User);

        if (user.ToIsNullOrEmpty())
        {
            context.Fail(new AuthorizationFailureReason(this, "Necesita ingresar al sistema para la acción que desea realizar."));

            return Task.CompletedTask;
        }

        if (user.Role.ToIsNullOrEmpty() == true || user.Role != requirement.Role)
        {
            context.Fail(new AuthorizationFailureReason(this, "Su usuario no posee el rol requerido para la acción que desea realizar."));

            return Task.CompletedTask;
        }

        context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
