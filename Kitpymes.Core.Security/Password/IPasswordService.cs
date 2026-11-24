// -----------------------------------------------------------------------
// <copyright file="IPasswordService.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Password;

using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

/*
    Interfaz para encriptar contraseñas IPasswordService
    Contiene las firmas para encriptar contraseñas
*/

/// <summary>
/// Interfaz para encriptar <c>IPasswordService</c>.
/// Contiene las firmas para encriptar.
/// </summary>
/// <remarks>
/// <para>En esta interfaz se pueden agregar todas las firmas para la encriptación de contraseñas.</para>
/// </remarks>
public interface IPasswordService
{
    /// <summary>
    /// Crea una contraseña plana random.
    /// </summary>
    /// <returns>string | null: si no se pudo crear la contraseña.</returns>
    string? CreateRandom();

    /// <summary>
    /// Crea una contraseña.
    /// </summary>
    /// <param name="plainPassword">Contraseña de texto a cifrar.</param>
    /// <remarks>
    /// Lanza una excepción si el servicio está desactivado o si la configuración pide más de 10.000.000 de iteraciones,
    /// el máximo que acepta <c>Verify</c>.
    /// </remarks>
    /// <returns>(string? hashPassword, List{PasswordErrorResult} errors).</returns>
    (string? hashPassword, ReadOnlyCollection<PasswordErrorResult> errors) Create(string? plainPassword);

    /// <summary>
    /// Verifica si una contraseña es correcta.
    /// </summary>
    /// <param name="plainPassword">Contraseña de cadena.</param>
    /// <param name="hashPassword">Contraseña cifrada.</param>
    /// <remarks>
    /// El algoritmo, las iteraciones y la longitud de la sal se leen del propio hash, así que un hash creado con otra
    /// configuración se sigue verificando. La marca de formato y la longitud de la cabecera sí tienen que ser las mismas.
    /// No aplica la política de contraseñas (<c>Validate</c>): sólo la comprueba <c>Create</c>, así que una contraseña creada
    /// con una política anterior sigue entrando aunque no cumpla la actual.
    /// </remarks>
    /// <returns>true si la contraseña corresponde al hash; false si no corresponde, si alguno de los dos es nulo o vacío, o si el hash está mal formado. No lanza excepciones por el contenido de los argumentos.</returns>
    bool Verify(string? plainPassword, string? hashPassword);

    /// <summary>
    /// Indica si un hash se creó con parámetros distintos de los de la configuración actual (algoritmo, iteraciones
    /// o longitud de la sal) y conviene regenerarlo con <c>Create</c>.
    /// </summary>
    /// <remarks>
    /// Se llama después de un <c>Verify</c> correcto, que es cuando se tiene la contraseña en claro para regenerarlo.
    /// Una implementación propia que no lo sobrescriba devuelve false: nunca pide regenerar.
    /// </remarks>
    /// <param name="hashPassword">Contraseña cifrada.</param>
    /// <returns>true si hay que regenerar el hash, también si es nulo, vacío o está mal formado; false si ya usa la configuración actual.</returns>
    bool NeedsRehash(string? hashPassword) => false;

    /// <summary>
    /// Valida una contraseña.
    /// </summary>
    /// <param name="plainPassword">Contraseña de cadena.</param>
    /// <returns>List{PasswordErrorResult} errors.</returns>
    ReadOnlyCollection<PasswordErrorResult> Validate(string? plainPassword);
}
