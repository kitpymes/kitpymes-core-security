// -----------------------------------------------------------------------
// <copyright file="PasswordService.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Password;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Kitpymes.Core.Security.Password.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

/*
    Clase para encriptar contraseñas PasswordService
    Contiene los métodos para encriptar contraseñas
*/

/// <summary>
/// Clase para encriptar contraseñas <c>PasswordService</c>.
/// Contiene los métodos para encriptar contraseñas.
/// </summary>
/// <remarks>
/// <para>En esta interfaz se pueden agregar todos los métodos para la encriptación de contraseñas.</para>
/// </remarks>
/// <remarks>
/// Inicializa una nueva instancia de la clase <see cref="PasswordService"/>.
/// </remarks>
/// <param name="settings">Configuración de la contraseña.</param>
public class PasswordService(PasswordSettings settings)
    : IPasswordService
{
    /// <summary>
    /// Iteraciones máximas que se aceptan al leer un hash. Muy por encima de las recomendadas hoy para PBKDF2;
    /// evita que un hash con un número absurdo deje bloqueada la verificación.
    /// </summary>
    private const uint MaxIterCount = 10_000_000;

    /// <summary>
    /// Longitud mínima de la cabecera: la marca de formato y tres enteros de 4 bytes.
    /// </summary>
    private const int MinHeaderByteLength = 13;

    private PasswordSettings PasswordSettings { get; set; } = settings;

    /// <inheritdoc/>
    public string? CreateRandom()
    {
        Shared.Util.Verify.ToThrowIf($"{nameof(PasswordSettings)} is not enabled.", () => PasswordSettings.Enabled == false);

        var passwordBuilder = new StringBuilder();

        if (PasswordSettings.RequireDigit == true)
        {
            var digit = "0123456789".ToRandom(1);

            passwordBuilder.Append(digit);
        }

        if (PasswordSettings.RequireEspecialChars == true)
        {
            var especialChars = "@#%&*?¿_-+=".ToRandom(1);

            passwordBuilder.Append(especialChars);
        }

        if (PasswordSettings.RequireLowercase == true)
        {
            var lowercase = "abcdefghijklmnopqrstuvw".ToRandom(1);

            passwordBuilder.Append(lowercase);
        }

        if (PasswordSettings.RequireUppercase == true)
        {
            var uppercase = "ABCDEFGHJKLMNOPQRSTUVW".ToRandom(1);

            passwordBuilder.Append(uppercase);
        }

        if (PasswordSettings.RequiredUniqueChars == true)
        {
            var uniqueChars = "xyzXYZ".ToRandom(1);

            passwordBuilder.Append(uniqueChars);
        }

        // Sólo se rellena si los caracteres obligatorios no llegan a la longitud mínima.
        if (PasswordSettings.RequiredMinLength.HasValue && PasswordSettings.RequiredMinLength.Value > passwordBuilder.Length)
        {
            var length = PasswordSettings.RequiredMinLength.Value - passwordBuilder.Length;

            const string chars = "0123456789ABCDEFGHJKLMNOPQRSTUVWabcdefghijklmnopqrstuvw";

            // Con caracteres únicos, el relleno al azar podía repetir uno ya usado y CreateRandom devolvía null.
            var fill = PasswordSettings.RequiredUniqueChars == true
                ? ToRandomUnique(chars, length, passwordBuilder.ToString())
                : chars.ToRandom(length);

            passwordBuilder.Append(fill);
        }

        var plainPassword = passwordBuilder.ToString();

        var errors = Validate(plainPassword);

        return errors.Count > 0 ? null : plainPassword;
    }

    /// <inheritdoc/>
    public (string? hashPassword, ReadOnlyCollection<PasswordErrorResult> errors) Create(string? plainPassword)
    {
        Shared.Util.Verify.ToThrowIf($"{nameof(PasswordSettings)} is not enabled.", () => PasswordSettings.Enabled == false);

        var errors = Validate(plainPassword);

        var hashPassword = errors.Count > 0 ? null : CreatePassword(plainPassword!);

        return (hashPassword, errors);
    }

    /// <inheritdoc/>
    public bool Verify(string? plainPassword, string? hashPassword)
    {
        var errors = Validate(plainPassword);

        var isValid = errors.Count == 0 && VerifyPassword(hashPassword, plainPassword);

        return isValid;
    }

    /// <inheritdoc/>
    public bool NeedsRehash(string? hashPassword)
    {
        if (!TryReadHash(hashPassword, out var prf, out var iterCount, out var salt, out _))
        {
            return true;
        }

        var settings = PasswordSettings.EncryptionSettings;

        return prf != settings.KeyDerivationAlgorithm!.Value.ToEnum<KeyDerivationPrf>()
            || iterCount != settings.IterCount!.Value
            || salt.Length != settings.SaltLength!.Value;
    }

    /// <inheritdoc/>
    public ReadOnlyCollection<PasswordErrorResult> Validate(string? plainPassword)
    {
        var errors = new List<PasswordErrorResult>();

        if (plainPassword.ToIsNullOrEmpty())
        {
            errors.Add(PasswordErrorResult.RequiredValue);
        }
        else if (PasswordSettings != null)
        {
            if (PasswordSettings.RequireDigit == true && !plainPassword.ToIsContainsDigit())
            {
                errors.Add(PasswordErrorResult.RequireDigit);
            }

            if (PasswordSettings.RequiredMinLength.HasValue && plainPassword.ToIsLess(PasswordSettings.RequiredMinLength.Value))
            {
                errors.Add(PasswordErrorResult.RequiredMinLength);
            }

            if (PasswordSettings.RequiredUniqueChars == true && !plainPassword.ToIsContainsUniqueChars())
            {
                errors.Add(PasswordErrorResult.RequiredUniqueChars);
            }

            if (PasswordSettings.RequireEspecialChars == true && !plainPassword.ToIsContainsEspecialChars())
            {
                errors.Add(PasswordErrorResult.RequireEspecialChars);
            }

            if (PasswordSettings.RequireLowercase == true && !plainPassword.ToIsLowercase())
            {
                errors.Add(PasswordErrorResult.RequireLowercase);
            }

            if (PasswordSettings.RequireUppercase == true && !plainPassword.ToIsUppercase())
            {
                errors.Add(PasswordErrorResult.RequireUppercase);
            }
        }

        return errors.AsReadOnly();
    }

    #region Private

    private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
    {
        return (uint)buffer[offset + 0] << 24
            | (uint)buffer[offset + 1] << 16
            | (uint)buffer[offset + 2] << 8
            | buffer[offset + 3];
    }

    private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
    {
        buffer[offset + 0] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)(value >> 0);
    }

    /// <summary>
    /// Elige al azar, sin repetir, caracteres de <paramref name="chars"/> que no estén en <paramref name="used"/>.
    /// Si no hay bastantes, devuelve todos los disponibles.
    /// </summary>
    /// <param name="chars">Caracteres entre los que elegir.</param>
    /// <param name="length">Cantidad de caracteres que se quieren.</param>
    /// <param name="used">Caracteres que ya tiene la contraseña.</param>
    /// <returns>Los caracteres elegidos.</returns>
    private static string ToRandomUnique(string chars, int length, string used)
    {
        var available = chars.Distinct().Where(x => !used.Contains(x, StringComparison.Ordinal)).ToArray();

        var count = Math.Min(length, available.Length);

        for (var i = 0; i < count; i++)
        {
            var j = RandomNumberGenerator.GetInt32(i, available.Length);

            (available[i], available[j]) = (available[j], available[i]);
        }

        return new string(available, 0, count);
    }

    private static byte[] CreateSalt(int saltLength)
    {
        byte[] randomBytes = new byte[saltLength];

        using var generator = RandomNumberGenerator.Create();

        generator.GetBytes(randomBytes);

        return randomBytes;
    }

    private string CreatePassword(string plainPassword)
    {
        var settings = PasswordSettings.EncryptionSettings;

        var salt = CreateSalt(settings.SaltLength!.Value);

        var subkey = KeyDerivation.Pbkdf2(plainPassword, salt, settings.KeyDerivationAlgorithm!.Value.ToEnum<KeyDerivationPrf>(), settings.IterCount!.Value, settings.SaltLength!.Value);

        var outputBytes = new byte[settings.HeaderByteLength!.Value + salt.Length + subkey.Length];

        outputBytes[0] = settings.FormatMarker!.Value;

        WriteNetworkByteOrder(outputBytes, 1, (uint)settings.KeyDerivationAlgorithm!.Value);
        WriteNetworkByteOrder(outputBytes, 5, (uint)settings.IterCount!.Value);
        WriteNetworkByteOrder(outputBytes, 9, (uint)settings.SaltLength!.Value);

        Buffer.BlockCopy(salt, 0, outputBytes, settings.HeaderByteLength!.Value, salt.Length);
        Buffer.BlockCopy(subkey, 0, outputBytes, settings.HeaderByteLength!.Value + settings.SaltLength!.Value, subkey.Length);

        return Convert.ToBase64String(outputBytes);
    }

    private bool VerifyPassword(string? hashedPassword, string? plainPassword)
    {
        if (plainPassword.ToIsNullOrEmpty() || !TryReadHash(hashedPassword, out var prf, out var iterCount, out var salt, out var expectedSubkey))
        {
            return false;
        }

        // El algoritmo y las iteraciones salen de la cabecera del propio hash, no de la configuración,
        // para que un hash guardado se siga verificando aunque la configuración cambie.
        var actualSubkey = KeyDerivation.Pbkdf2(plainPassword, salt, prf, iterCount, expectedSubkey.Length);

        // Comparación en tiempo constante, para no dar pistas por el tiempo de respuesta.
        return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
    }

    /// <summary>
    /// Lee la cabecera de un hash creado por <see cref="Create"/>: marca de formato, algoritmo, iteraciones
    /// y longitud de la sal, seguidos de la sal y de la clave derivada, que mide lo mismo que la sal.
    /// </summary>
    /// <param name="hashedPassword">Hash en base64.</param>
    /// <param name="prf">Algoritmo leído de la cabecera.</param>
    /// <param name="iterCount">Iteraciones leídas de la cabecera.</param>
    /// <param name="salt">Sal del hash.</param>
    /// <param name="subkey">Clave derivada guardada en el hash.</param>
    /// <returns>false si el hash es nulo, vacío o está mal formado.</returns>
    private bool TryReadHash(string? hashedPassword, out KeyDerivationPrf prf, out int iterCount, out byte[] salt, out byte[] subkey)
    {
        prf = default;
        iterCount = 0;
        salt = Array.Empty<byte>();
        subkey = Array.Empty<byte>();

        if (hashedPassword.ToIsNullOrEmpty())
        {
            return false;
        }

        byte[] decoded;

        try
        {
            decoded = Convert.FromBase64String(hashedPassword);
        }
        catch (FormatException)
        {
            return false;
        }

        var settings = PasswordSettings.EncryptionSettings;

        var headerLength = settings.HeaderByteLength!.Value;

        // La cabecera lleva la marca y tres enteros de 4 bytes (algoritmo, iteraciones y sal): 13 bytes como mínimo.
        if (headerLength < MinHeaderByteLength || decoded.Length < headerLength || decoded[0] != settings.FormatMarker!.Value)
        {
            return false;
        }

        var prfRead = ReadNetworkByteOrder(decoded, 1);
        var iterCountRead = ReadNetworkByteOrder(decoded, 5);
        var saltLengthRead = ReadNetworkByteOrder(decoded, 9);

        // Un algoritmo desconocido, unas iteraciones fuera de rango o una sal vacía son un hash mal formado.
        if (prfRead > 2 || iterCountRead == 0 || iterCountRead > MaxIterCount || saltLengthRead == 0)
        {
            return false;
        }

        // La clave derivada mide lo mismo que la sal (así la escribe CreatePassword): un hash cortado o alargado no vale.
        if ((long)decoded.Length - headerLength != 2L * saltLengthRead)
        {
            return false;
        }

        prf = (KeyDerivationPrf)prfRead;
        iterCount = (int)iterCountRead;
        salt = decoded.AsSpan(headerLength, (int)saltLengthRead).ToArray();
        subkey = decoded.AsSpan(headerLength + (int)saltLengthRead).ToArray();

        return true;
    }

    #endregion Private
}