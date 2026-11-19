// -----------------------------------------------------------------------
// <copyright file="DefaultPolicySettings.cs" company="Kitpymes">
// Copyright (c) Kitpymes. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project docs folder for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace Kitpymes.Core.Security.Authorization.Settings
{
    /*
        Clase para la configuración de la fecha de expiración DefaultPolicySettings
        Contiene los métodos para la configuración de la fecha de expiración
    */

    /// <summary>
    /// Clase para la configuración de la fecha de expiración <c>DefaultPolicySettings</c>.
    /// Contiene los métodos para la configuración de la fecha de expiración.
    /// </summary>
    /// <remarks>
    /// <para>En esta clase se pueden agregar todos los métodos para la configuración de la fecha de expiración.</para>
    /// </remarks>
    public class DefaultPolicySettings
    {
        /// <summary>
        /// Valor por defecto que indica los minutos de expiración.
        /// </summary>
        public const bool DefaultRequiredSchemes = false;

        /// <summary>
        /// Valor por defecto que indica los segundos de expiración.
        /// </summary>
        public const bool DefaultRequireAuthenticatedUser = false;

        private bool _requiredSchemes = DefaultRequiredSchemes;
        private bool _requireAuthenticatedUser = DefaultRequireAuthenticatedUser;

        /// <summary>
        /// Obtiene o establece los minutos de expiración.
        /// <para><strong>Default:</strong> <see cref="DefaultRequiredSchemes"/> = 0.</para>
        /// </summary>
        public bool? RequiredSchemes
        {
            get => _requiredSchemes;
            set
            {
                if (value.HasValue)
                {
                    _requiredSchemes = value.Value;
                }
            }
        }

        /// <summary>
        /// Obtiene o establece los segundos de expiración.
        /// <para><strong>Default:</strong> <see cref="DefaultRequireAuthenticatedUser"/> = 0.</para>
        /// </summary>
        public bool? RequireAuthenticatedUser
        {
            get => _requireAuthenticatedUser;
            set
            {
                if (value.HasValue)
                {
                    _requireAuthenticatedUser = value.Value;
                }
            }
        }
    }
}
