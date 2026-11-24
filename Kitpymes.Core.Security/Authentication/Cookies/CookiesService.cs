// -----------------------------------------------------------------------
// <copyright file="CookiesService.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.Cookies;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Kitpymes.Core.Security.Authentication.Cookies.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/*
    Clase para autenticarse por medio de cookies CookiesService
    Contiene la funcionalidad para autenticarse por medio de cookies
*/

/// <summary>
/// Interfaz para el token de sesión <c>CookiesService</c>.
/// Contiene la funcionalidad para autenticarse por medio de cookies.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar toda la funcionalidad para autenticarse por medio de cookies.</para>
/// <para>Se registra como singleton, así que no guarda nada de una petición: cada llamada usa el <see cref="HttpContext"/>
/// y el <see cref="IAuthenticationService"/> de su petición.</para>
/// </remarks>
public class CookiesService : ICookiesService
{
    /// <summary>
    /// Inicializa una nueva instancia de la clase <see cref="CookiesService"/>.
    /// </summary>
    /// <param name="settings">Configuración de la autenticación.</param>
    /// <param name="authenticationService">Servicio para autenticarse; sólo se usa si la petición no tiene el suyo.</param>
    /// <param name="httpContextAccessor">Servicio para acceder al cotexto.</param>
    public CookiesService(CookiesSettings settings, IAuthenticationService authenticationService, IHttpContextAccessor httpContextAccessor)
    {
        CookiesSettings = settings;
        AuthenticationService = authenticationService;
        HttpContextAccessor = httpContextAccessor;
    }

    private CookiesSettings CookiesSettings { get; }

    private IAuthenticationService AuthenticationService { get; }

    private IHttpContextAccessor HttpContextAccessor { get; }

    /// <inheritdoc/>
    public async Task SignInAsync(IEnumerable<Claim> claims, Action<AuthenticationProperties>? options = null)
    {
        var httpContext = HttpContextAccessor.HttpContext.ToThrowIfNullOrEmpty();

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookiesSettings.AuthenticateScheme));

        var authenticationProperties = options.ToConfigureOrDefault();

        await GetAuthenticationService(httpContext).SignInAsync(
            httpContext,
            CookiesSettings.AuthenticateScheme,
            claimsPrincipal,
            authenticationProperties)
        .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task SignOutAsync()
    {
        var httpContext = HttpContextAccessor.HttpContext ?? throw new ArgumentNullException(nameof(HttpContextAccessor.HttpContext));

        await GetAuthenticationService(httpContext).SignOutAsync(
            httpContext,
            CookiesSettings.AuthenticateScheme,
            null).ConfigureAwait(false);
    }

    // IAuthenticationService es scoped: el de la petición, y el del registro sólo si la petición no tiene contenedor.
    private IAuthenticationService GetAuthenticationService(HttpContext httpContext)
        => httpContext.RequestServices?.GetService<IAuthenticationService>() ?? AuthenticationService;
}