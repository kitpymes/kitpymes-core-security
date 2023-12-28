// -----------------------------------------------------------------------
// <copyright file="RoleRequirement.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Requirements;

using System;
using System.Threading.Tasks;
using Kitpymes.Core.Api.ApiSession;
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
    public string Role { get; } = role;
}

/// <summary>
/// Clase para la autorizacion por roles.
/// </summary>
public class RoleRequirementHandler : AuthorizationHandler<RoleRequirement>
{
    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleRequirement requirement)
    {
        context.ToThrowIfNullOrEmpty();

        requirement.ToThrowIfNullOrEmpty();

        var user = context.User.ToGet<UserSession>(nameof(UserSession));

        if (user.ToIsNullOrEmpty())
        {
            throw new UnauthorizedAccessException("Necesita ingresar al sistema para la acción que desea realizar.");
        }

        if (user.Role.ToIsNullOrEmpty() == true || user.Role != requirement.Role)
        {
            throw new UnauthorizedAccessException("Su usuario no posee el rol requerido para la acción que desea realizar.");
        }

        context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
