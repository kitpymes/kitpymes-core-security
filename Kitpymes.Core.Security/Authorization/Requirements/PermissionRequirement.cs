// -----------------------------------------------------------------------
// <copyright file="PermissionRequirement.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Requirements;

using System;
using System.Linq;
using System.Threading.Tasks;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Inicializa una nueva instancia de la clase <see cref="PermissionRequirement"/>.
/// </summary>
/// <param name="permission">Permiso requerido.</param>
public class PermissionRequirement(string permission)
    : IAuthorizationRequirement
{
    /// <summary>
    /// Obtiene el permiso.
    /// </summary>
    public string Permission => permission;
}

/// <summary>
/// Clase para la autorizacion por permisos.
/// </summary>
public class PermissionRequirementHandler : AuthorizationHandler<PermissionRequirement>
{
    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var user = UserSessionClaim.Get(context.User);

        if (user.ToIsNullOrEmpty())
        {
            context.Fail(new AuthorizationFailureReason(this, "Necesita ingresar al sistema para la acción que desea realizar."));

            return Task.CompletedTask;
        }

        if (user.Permissions.ToIsNullOrAny() == true || user.Permissions.Contains(requirement.Permission) == false)
        {
            context.Fail(new AuthorizationFailureReason(this, "No posee el permiso requerido para la acción que desea realizar."));

            return Task.CompletedTask;
        }

        context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
