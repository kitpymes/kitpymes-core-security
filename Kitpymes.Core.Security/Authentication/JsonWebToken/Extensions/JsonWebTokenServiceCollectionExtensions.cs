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

                        ValidateLifetime = settings.ValidateLifetime!.Value,
                        LifetimeValidator = (notBefore, expires, securityToken, validationParameters) => expires > DateTime.UtcNow,

                        RequireExpirationTime = settings.RequireExpirationTime!.Value,

                        // Establezca clockskew en cero para que los tokens caduquen exactamente a la hora de vencimiento del token (en lugar de 5 minutos más tarde)
                        ClockSkew = TimeSpan.Zero,
                    };

                    // Los eventos que no se nombran se quedan con el comportamiento por defecto (no hacen nada).
                    options.Events = new JwtBearerEvents
                    {
                        OnChallenge = context => Task.FromException(new UnauthorizedAccessException(context.ToDetails())),
                        OnAuthenticationFailed = context => Task.FromException(new UnauthorizedAccessException(context.ToDetails())),
                    };
                });

            services.TryAddSingleton<IJsonWebTokenService>(new JsonWebTokenService(settings));
        }

        return services;
    }
}