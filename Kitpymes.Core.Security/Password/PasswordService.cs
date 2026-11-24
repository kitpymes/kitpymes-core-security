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
using System.Runtime.CompilerServices;
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

    // Compares two byte arrays for equality. The method is specifically written so that the loop is not optimized.
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a == null && b == null)
        {
            return true;
        }

        if (a == null || b == null || a.Length != b.Length)
        {
            return false;
        }

        var areSame = true;

        for (var i = 0; i < a.Length; i++)
        {
            areSame &= a[i] == b[i];
        }

        return areSame;
    }

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
        if (plainPassword.ToIsNullOrEmpty() || hashedPassword.ToIsNullOrEmpty())
        {
            return false;
        }

        var plain = plainPassword;
        var hash = hashedPassword;

        byte[] decodedHashedPassword;

        try
        {
            decodedHashedPassword = Convert.FromBase64String(hash);
        }
        catch (Exception)
        {
            return false;
        }

        var settings = PasswordSettings.EncryptionSettings;

        if (decodedHashedPassword.Length == 0 || decodedHashedPassword[0] != settings.FormatMarker!.Value)
        {
            return false;
        }

        try
        {
            var shaUInt = ReadNetworkByteOrder(decodedHashedPassword, 1);

            // Un código de algoritmo desconocido es un hash mal formado.
            if (shaUInt > 2)
            {
                return false;
            }

            var verifyPrf = shaUInt switch
            {
                0 => KeyDerivationPrf.HMACSHA1,
                1 => KeyDerivationPrf.HMACSHA256,
                _ => KeyDerivationPrf.HMACSHA512,
            };

            if (verifyPrf != settings.KeyDerivationAlgorithm!.Value.ToEnum<KeyDerivationPrf>())
            {
                return false;
            }

            var verifyAlgorithmName = shaUInt switch
            {
                0 => HashAlgorithmName.SHA1,
                1 => HashAlgorithmName.SHA256,
                _ => HashAlgorithmName.SHA512,
            };

            if (verifyAlgorithmName != settings.AlgorithmName.ToHashAlgorithmName(HashAlgorithmName.SHA256))
            {
                return false;
            }

            int iterCountRead = (int)ReadNetworkByteOrder(decodedHashedPassword, 5);

            if (iterCountRead != settings.IterCount!.Value)
            {
                return false;
            }

            int saltLengthRead = (int)ReadNetworkByteOrder(decodedHashedPassword, 9);

            if (saltLengthRead != settings.SaltLength!.Value)
            {
                return false;
            }

            byte[] salt = new byte[settings.SaltLength!.Value];

            Buffer.BlockCopy(decodedHashedPassword, settings.HeaderByteLength!.Value, salt, 0, salt.Length);

            int subkeyLength = decodedHashedPassword.Length - settings.HeaderByteLength!.Value - salt.Length;

            if (subkeyLength != settings.SaltLength!.Value)
            {
                return false;
            }

            byte[] expectedSubkey = new byte[subkeyLength];

            Buffer.BlockCopy(decodedHashedPassword, settings.HeaderByteLength!.Value + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            byte[] actualSubkey = new byte[settings.SaltLength!.Value];

            actualSubkey = KeyDerivation.Pbkdf2(plain, salt, settings.KeyDerivationAlgorithm!.Value.ToEnum<KeyDerivationPrf>(), settings.IterCount!.Value, subkeyLength);

            return ByteArraysEqual(actualSubkey, expectedSubkey);
        }
        catch
        {
            // This should never occur except in the case of a malformed payload, where
            // we might go off the end of the array. Regardless, a malformed payload
            // implies verification failed.
            return false;
        }
    }

    #endregion Private
}