// -----------------------------------------------------------------------
// <copyright file="JsonWebTokenServiceCollectionExtensions.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.JsonWebToken.Extensions;

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Kitpymes.Core.Security.Authentication.JsonWebToken;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

/*
   Clase de extensión JsonWebTokenServiceCollectionExtensions
   Contiene las extensiones de los servicios para la autenticación por token
*/

/// <summary>
/// Clase de extensión <c>JsonWebTokenServiceCollectionExtensions</c>.
/// Contiene las extensiones de los servicios para la autenticación por token.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todas las extensiones de los servicios para la autenticación por token.</para>
/// </remarks>
public static class JsonWebTokenServiceCollectionExtensions
{
    // Clave de HttpContext.Items donde OnAuthenticationFailed deja el error del token para OnChallenge.
    private static readonly object AuthenticationFailedDetailsKey = new object();

    /// <summary>
    /// Obtiene el servicio de autenticación por token.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <returns>IJsonWebTokenService | ArgumentException: si no se encuentra el servicio IJsonWebTokenProvider.</returns>
    public static IJsonWebTokenService GetAuthJsonWebToken(this IServiceCollection services)
        => services.ToRequiredService<IJsonWebTokenService>();

    /// <summary>
    /// Carga el servicio de autenticación por token.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="options">Configuración del servicio de tokens.</param>
    /// <returns>IServiceCollection | ArgumentException: si PrivateKey o PublicKey son nulas o vacias.</returns>
    internal static IServiceCollection LoadAuthJsonWebToken(this IServiceCollection services, Action<JsonWebTokenOptions> options)
        => services.LoadAuthJsonWebToken(options.ToConfigureOrDefault().JsonWebTokenSettings);

    /// <summary>
    /// Carga el servicio de autenticación por token.
    /// </summary>
    /// <param name="services">Colección de servicios.</param>
    /// <param name="settings">Configuración del servicio de tokens.</param>
    /// <returns>IServiceCollection | ArgumentException: si JsonWebTokenSettings es nulo.</returns>
    internal static IServiceCollection LoadAuthJsonWebToken(this IServiceCollection services, JsonWebTokenSettings settings)
    {
        settings.ToThrowIfNullOrEmpty();

        if (settings.Enabled == true)
        {
            var validPrivateKey = settings.PrivateKey.ToThrowIfNullOrEmpty();

            var validPublicKey = settings.PublicKey.ToThrowIfNullOrEmpty();
#if DEBUG
            IdentityModelEventSource.ShowPII = true;
            IdentityModelEventSource.LogCompleteSecurityArtifact = true;
#endif
            RSA algorithm = RSA.Create();

            algorithm.ImportRSAPublicKey(Convert.FromBase64String(validPublicKey), out _);

            var securityKey = new RsaSecurityKey(algorithm)
            {
                CryptoProviderFactory = new CryptoProviderFactory()
                {
                    CacheSignatureProviders = false,
                },
            };

            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = settings.AuthenticateScheme;

                    options.DefaultAuthenticateScheme = settings.AuthenticateScheme;

                    options.DefaultChallengeScheme = settings.ChallengeScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = settings.RequireHttpsMetadata!.Value;

                    options.SaveToken = settings.SaveToken!.Value;

                    options.IncludeErrorDetails = settings.IncludeErrorDetails!.Value;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = securityKey,

                        ValidateIssuer = !settings.Issuer.ToIsNullOrEmpty(),
                        ValidIssuer = settings.Issuer,

                        ValidateAudience = !settings.Audience.ToIsNullOrEmpty(),
                        ValidAudience = settings.Audience,

                        // Sin LifetimeValidator propio: el de IdentityModel mira nbf y exp, y respeta ValidateLifetime.
                        ValidateLifetime = settings.ValidateLifetime!.Value,

                        RequireExpirationTime = settings.RequireExpirationTime!.Value,

                        // Margen para el desfase de reloj entre servidores (por defecto 60 s; el de IdentityModel es 5 min).
                        ClockSkew = TimeSpan.FromSeconds(settings.ClockSkewSeconds!.Value),
                    };

                    // Los eventos que no se nombran se quedan con el comportamiento por defecto (no hacen nada).
                    // Un token inválido no lanza al autenticar: la autenticación corre en todas las peticiones y tumbaba
                    // también las rutas públicas ([AllowAnonymous]). Se guarda su error y se lanza en el desafío, que sólo
                    // ocurre en las rutas que piden usuario, con el mismo mensaje que antes.
                    options.Events = new JwtBearerEvents
                    {
                        OnChallenge = context => Task.FromException(new UnauthorizedAccessException(
                            context.HttpContext.Items.TryGetValue(AuthenticationFailedDetailsKey, out var details) && details is string message
                                ? message
                                : context.ToDetails())),
                        OnAuthenticationFailed = context =>
                        {
                            context.HttpContext.Items[AuthenticationFailedDetailsKey] = context.ToDetails();

                            // Sin Fail, JwtBearer relanza la excepción original cuando el fallo viene de su catch general
                            // (configuración, resolución de claves) en vez de devolver un fallo de autenticación.
                            context.Fail(context.Exception);

                            return Task.CompletedTask;
                        },
                    };
                });

            services.TryAddSingleton<IJsonWebTokenService>(new JsonWebTokenService(settings));
        }

        return services;
    }
}