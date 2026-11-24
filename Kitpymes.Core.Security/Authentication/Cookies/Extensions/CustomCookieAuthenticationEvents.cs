// -----------------------------------------------------------------------
// <copyright file="CustomCookieAuthenticationEvents.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.Cookies.Extensions;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Kitpymes.Core.Security.Authentication.Cookies;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/*
   Clase de eventos CustomCookieAuthenticationEvents
   Contiene los eventos de la autenticación por cookies
*/

/// <summary>
/// Clase de eventos <c>CustomCookieAuthenticationEvents</c>.
/// Contiene los eventos de la autenticación por cookies.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todos los eventos de la autenticación por cookies.</para>
/// </remarks>
/// <remarks>
/// Inicializa una nueva instancia de la clase <see cref="CustomCookieAuthenticationEvents"/>.
/// </remarks>
/// <param name="httpContextAccessor">Servicio para tener acceso al http context.</param>
public class CustomCookieAuthenticationEvents(IHttpContextAccessor httpContextAccessor)
    : CookieAuthenticationEvents
{
    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;

    /// <inheritdoc/>
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        context.ToThrowIfNullOrEmpty();

        var cookiesService = context.HttpContext.RequestServices.GetService<ICookiesService>()
            .ToThrowIfNullOrEmpty();

        var lastChanged = context?.Principal?.FindFirstValue("LastUpdated");

       // var userId = context?.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);

        // var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
        // || !userRepository.ValidateLastChanged(userId, lastChanged))
        if (string.IsNullOrEmpty(lastChanged))
        {
            context?.RejectPrincipal();

            await cookiesService.SignOutAsync().ConfigureAwait(false);
        }
    }

    ///// <inheritdoc/>
    // public override async Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    // {
    //    var binding = context.HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
    //    var tlsTokenBinding = binding == null ? null : Convert.ToBase64String(binding);
    //    var cookie = context.Options.CookieManager.GetRequestCookie(context.HttpContext, context.Options.Cookie.Name);
    //    if (cookie != null)
    //    {
    //        var ticket = context.Options.TicketDataFormat.Unprotect(cookie, tlsTokenBinding);

    // var expiresUtc = ticket.Properties.ExpiresUtc;
    //        var currentUtc = DateTime.UtcNow;
    //        if (expiresUtc != null && expiresUtc.Value < currentUtc)
    //        {
    //            context.RedirectUri += "&p1=yourparameter";
    //        }
    //    }

    // context.HttpContext.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
    // context.HttpContext.Response.Headers.Add("Access-Control-Allow-Methods", "POST, GET");

    // context.HttpContext.Response.Redirect(context.RedirectUri);

    // await Task.CompletedTask;
    // }

    /// <inheritdoc/>
    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        var httpContext = httpContextAccessor.HttpContext;

        var username = httpContext?.User?.Identity?.Name;

        var optionalData = new Dictionary<string, IEnumerable<object>>
        {
            { "AccessDeniedDateTime",  new[] { DateTime.UtcNow.ToLongDateString() } },
        };

        if (!username.ToIsNullOrEmpty())
        {
            optionalData.ToAddOrUpdate("Username", username);
        }

        return Task.FromException(new UnauthorizedAccessException(ToDetails(httpContext, username, optionalData).ToSerialize()));
    }

    // Los mismos campos que HttpContext.ToDetails de Shared 2.0.1, que no se usa: lee la claim del nombre como JSON
    // (lanza JsonException con el nombre en texto plano, que es como lo pone ASP.NET Core) y, sin usuario, pone en
    // User el del sistema operativo del servidor.
    private static Dictionary<string, object> ToDetails(HttpContext? httpContext, string? username, object optionalData)
    {
        var details = new Dictionary<string, object>
        {
            ["User"] = username.ToIsNullOrEmpty() ? "Anonymous" : username!,
        };

        if (httpContext is not null)
        {
            if (httpContext.ToTryIPv6(out var ip))
            {
                details["IP"] = ip!;
            }

            if (httpContext.Request.ToTryHeader("User-Agent", out var userAgents))
            {
                details["UserAgent"] = userAgents!;
            }

            if (httpContext.Request.ToTryContentType(out var contentType))
            {
                details["ContentType"] = contentType!;
            }

            details["Request"] = httpContext.Request.ToPath();
        }

        details["OptionalData"] = optionalData;

        return details;
    }
}
