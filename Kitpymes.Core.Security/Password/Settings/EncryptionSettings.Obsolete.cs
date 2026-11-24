// -----------------------------------------------------------------------
// <copyright file="EncryptionSettings.Obsolete.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Password.Settings;

using System;
using System.ComponentModel;
using System.Security.Cryptography;

/// <summary>
/// Miembros obsoletos de <see cref="EncryptionSettings"/>. Se eliminan en la 3.0.0.
/// </summary>
public partial class EncryptionSettings
{
    /// <summary>
    /// Obsoleto: no se usa. El algoritmo lo marca <see cref="KeyDerivationAlgorithm"/> al crear el hash, y al verificar se lee del propio hash.
    /// Valor por defecto que indica el nombre de un algoritmo hash criptográfico.
    /// <list type="bullet">
    /// <item>
    /// <descripction>MD5</descripction>
    /// </item>
    /// <item>
    /// <descripction>SHA1</descripction>
    /// </item>
    /// <item>
    /// <descripction>SHA256</descripction>
    /// </item>
    /// <item>
    /// <descripction>SHA384</descripction>
    /// </item>
    /// <item>
    /// <descripction>SHA256</descripction>
    /// </item>
    /// </list>
    /// <para><strong>Default:</strong> SHA256.</para>
    /// </summary>
    [Obsolete("No se usa: el algoritmo lo marca KeyDerivationAlgorithm y Verify lo lee del hash. Se elimina en 3.0.0.", DiagnosticId = "KPY0004")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static readonly string DefaultAlgorithmName = HashAlgorithmName.SHA256.ToString();

    private string _algorithmName = HashAlgorithmName.SHA256.ToString();

    /// <summary>
    /// Obtiene o establece el nombre de un algoritmo hash criptográfico. Obsoleto: no se usa. El algoritmo lo marca
    /// <see cref="KeyDerivationAlgorithm"/> al crear el hash, y al verificar se lee del propio hash. Antes, <c>Verify</c>
    /// exigía que coincidiera con el algoritmo del hash.
    /// </summary>
    [Obsolete("No se usa: el algoritmo lo marca KeyDerivationAlgorithm y Verify lo lee del hash. Se elimina en 3.0.0.", DiagnosticId = "KPY0004")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public string? AlgorithmName
    {
        get => _algorithmName;
        set
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                _algorithmName = value;
            }
        }
    }
}
