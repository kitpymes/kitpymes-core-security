// -----------------------------------------------------------------------
// <copyright file="JsonWebTokenService.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authentication.JsonWebToken;

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.IdentityModel.Tokens;

/*
    Clase para el token de sesión JsonWebTokenService
    Contiene los métodos para el token de sesión
*/

/// <summary>
/// Clase para el token de sesión <c>JsonWebTokenService</c>.
/// Contiene los métodos para el token de sesión.
/// </summary>
/// <remarks>
/// <para>En esta clase se pueden agregar todos los métodos para el token de sesión.</para>
/// </remarks>
/// <remarks>
/// Inicializa una nueva instancia de la clase <see cref="JsonWebTokenService"/>.
/// </remarks>
/// <param name="settings">Configuración para el token de sesión.</param>
public class JsonWebTokenService(JsonWebTokenSettings settings)
    : IJsonWebTokenService
{
    private JsonWebTokenSettings JsonWebTokenSettings => settings;

    /// <inheritdoc/>
    public GetJsonWebTokenResult Get(string? token)
    {
        token.ToThrowIfNullOrEmpty();

        var jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

        var result = new GetJsonWebTokenResult
        {
            Audiences = jwtSecurityToken.Audiences,
            Expire = jwtSecurityToken.ValidTo.ToString(System.Globalization.CultureInfo.CurrentCulture),
            Header = jwtSecurityToken.Header,
            Payload = jwtSecurityToken.Payload,
            Issuer = jwtSecurityToken.Issuer,
        };

        foreach (var claim in jwtSecurityToken.Claims)
        {
            result.Claims.Add(claim.Type, claim.Value);
        }

        return result;
    }

    /// <inheritdoc/>
    public CreateJsonWebTokenResult Create(Claim claim, IDictionary<string, IEnumerable<string>>? headers = null)
        => Create(new List<Claim> { claim });

    /// <inheritdoc/>
    public CreateJsonWebTokenResult Create(IEnumerable<Claim> claims, IDictionary<string, IEnumerable<string>>? headers = null)
    {
        claims.ToThrowIfNullOrAny();

        JsonWebTokenSettings.PrivateKey.ToThrowIfNullOrEmpty();

        var expires = DateTime.UtcNow.Add(new TimeSpan(
           JsonWebTokenSettings.Expire.Days!.Value,
           JsonWebTokenSettings.Expire.Hours!.Value,
           JsonWebTokenSettings.Expire.Minutes!.Value,
           JsonWebTokenSettings.Expire.Seconds!.Value));

        using RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(JsonWebTokenSettings.PrivateKey!), out _);
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: JsonWebTokenSettings.Issuer,
            audience: JsonWebTokenSettings.Audience,
            claims,
            notBefore: DateTime.UtcNow,
            expires,
            signingCredentials);

        if (headers != null)
        {
            foreach ((string key, object value) in headers)
            {
                jwtSecurityToken.Header.Add(key, value);
            }
        }

        var result = new CreateJsonWebTokenResult
        {
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            Expire = expires.ToString(System.Globalization.CultureInfo.CurrentCulture),
        };

        return result;
    }
}
