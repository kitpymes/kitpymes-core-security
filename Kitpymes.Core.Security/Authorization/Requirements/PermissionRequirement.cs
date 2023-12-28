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
using Kitpymes.Core.Api.ApiSession;
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
    public string Permission { get; } = permission;
}

/// <summary>
/// Clase para la autorizacion por permisos.
/// </summary>
public class PermissionRequirementHandler : AuthorizationHandler<PermissionRequirement>
{
    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        context.ToThrowIfNullOrEmpty();

        requirement.ToThrowIfNullOrEmpty();

        var user = context.User.ToGet<UserSession>(nameof(UserSession));

        if (user.ToIsNullOrEmpty())
        {
            throw new UnauthorizedAccessException("Necesita ingresar al sistema para la acción que desea realizar.");
        }

        if (user.Permissions.ToIsNullOrAny() == true || user.Permissions.Contains(requirement.Permission) == false)
        {
            throw new UnauthorizedAccessException("Su usuario no posee el permiso requerido para la acción que desea realizar.");
        }

        context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
