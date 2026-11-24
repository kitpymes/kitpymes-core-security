using Kitpymes.Core.Security.Authentication;
using Kitpymes.Core.Security.Authentication.Cookies.Settings;
using Kitpymes.Core.Security.Authentication.JsonWebToken.Settings;
using Kitpymes.Core.Security.Authentication.OAuth.Settings;
using Kitpymes.Core.Security.Authorization.Settings;
using Kitpymes.Core.Security.Encryptor.Settings;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Kitypmes.Core.Security.Tests
{
    [TestClass]
    public class SettingsTest
    {
        // Cada propiedad con valor por defecto: un valor nuevo se guarda, y nulo (o vacío y espacios, en las cadenas)
        // no lo cambia.
        [TestMethod]
        [DataRow(typeof(ExpireSettings), nameof(ExpireSettings.Days))]
        [DataRow(typeof(ExpireSettings), nameof(ExpireSettings.Hours))]
        [DataRow(typeof(ExpireSettings), nameof(ExpireSettings.Minutes))]
        [DataRow(typeof(ExpireSettings), nameof(ExpireSettings.Seconds))]
        [DataRow(typeof(CookiesSettings), nameof(CookiesSettings.Enabled))]
        [DataRow(typeof(CookiesSettings), nameof(CookiesSettings.AuthenticateScheme))]
        [DataRow(typeof(CookiesSettings), nameof(CookiesSettings.SlidingExpiration))]
        [DataRow(typeof(CookiesSettings), nameof(CookiesSettings.HttpOnly))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.Enabled))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.AuthenticateScheme))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.ChallengeScheme))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.RequireHttpsMetadata))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.RequireExpirationTime))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.SaveToken))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.IncludeErrorDetails))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.ValidateLifetime))]
        [DataRow(typeof(JsonWebTokenSettings), nameof(JsonWebTokenSettings.ClockSkewSeconds))]
        [DataRow(typeof(OAuthSettings), nameof(OAuthSettings.Enabled))]
        [DataRow(typeof(AuthenticationSettings), nameof(AuthenticationSettings.Enabled))]
        [DataRow(typeof(AuthorizationSettings), nameof(AuthorizationSettings.Enabled))]
        [DataRow(typeof(DefaultPolicySettings), nameof(DefaultPolicySettings.RequiredSchemes))]
        [DataRow(typeof(DefaultPolicySettings), nameof(DefaultPolicySettings.RequireAuthenticatedUser))]
        [DataRow(typeof(EncryptorSettings), nameof(EncryptorSettings.Enabled))]
        [DataRow(typeof(EncryptorSettings), nameof(EncryptorSettings.ApplicationName))]
        [DataRow(typeof(EncryptorSettings), nameof(EncryptorSettings.KeyLifetimeFromDays))]
        [DataRow(typeof(EncryptorSettings), nameof(EncryptorSettings.PersistKeysToFileSystem))]
        public void Setter_Passing_Value_Stores_It_And_Null_Keeps_It(Type type, string propertyName)
        {
            var settings = Activator.CreateInstance(type)!;
            var property = type.GetProperty(propertyName)!;
            var defaultValue = property.GetValue(settings);

            object value = defaultValue switch
            {
                bool b => !b,
                int i => i + 3,
                string s => s + "-otro",
                _ => throw new InvalidOperationException($"Tipo sin caso: {property.PropertyType}"),
            };

            property.SetValue(settings, value);
            Assert.AreEqual(value, property.GetValue(settings));

            property.SetValue(settings, null);
            Assert.AreEqual(value, property.GetValue(settings));

            if (value is string)
            {
                property.SetValue(settings, string.Empty);
                Assert.AreEqual(value, property.GetValue(settings));

                property.SetValue(settings, "   ");
                Assert.AreEqual(value, property.GetValue(settings));
            }
        }

        [TestMethod]
        public void EncryptorSettings_KeyLifetimeFromDays_Accepts_Seven_Or_More()
        {
            var settings = new EncryptorSettings();

            settings.KeyLifetimeFromDays = 7;
            Assert.AreEqual(7, settings.KeyLifetimeFromDays);

            settings.KeyLifetimeFromDays = 6;
            Assert.AreEqual(7, settings.KeyLifetimeFromDays);

            settings.KeyLifetimeFromDays = 8;
            Assert.AreEqual(8, settings.KeyLifetimeFromDays);
        }

        [TestMethod]
        [DataRow(null, null, false)]
        [DataRow(false, false, false)]
        [DataRow(true, false, true)]
        [DataRow(false, true, true)]
        [DataRow(true, true, true)]
        public void AuthorizationSettings_HasDefaultPolicy(bool? requiredSchemes, bool? requireAuthenticatedUser, bool expected)
        {
            var settings = new AuthorizationSettings();

            if (requiredSchemes.HasValue)
            {
                settings.DefaultPolicy = new DefaultPolicySettings
                {
                    RequiredSchemes = requiredSchemes,
                    RequireAuthenticatedUser = requireAuthenticatedUser,
                };
            }

            Assert.AreEqual(expected, settings.HasDefaultPolicy);
        }

        [TestMethod]
        public void Defaults_Are_The_Documented_Ones()
        {
            var expire = new ExpireSettings();
            Assert.AreEqual(30, expire.Days);
            Assert.AreEqual(0, expire.Hours);
            Assert.AreEqual(0, expire.Minutes);
            Assert.AreEqual(0, expire.Seconds);

            var cookies = new CookiesSettings();
            Assert.AreEqual(false, cookies.Enabled);
            Assert.AreEqual("Cookies", cookies.AuthenticateScheme);
            Assert.AreEqual(true, cookies.SlidingExpiration);
            Assert.AreEqual(true, cookies.HttpOnly);

            var jwt = new JsonWebTokenSettings();
            Assert.AreEqual(false, jwt.Enabled);
            Assert.AreEqual("Bearer", jwt.AuthenticateScheme);
            Assert.AreEqual("Bearer", jwt.ChallengeScheme);
            Assert.AreEqual(true, jwt.RequireHttpsMetadata);
            Assert.AreEqual(true, jwt.RequireExpirationTime);
            Assert.AreEqual(true, jwt.SaveToken);
            Assert.AreEqual(true, jwt.IncludeErrorDetails);
            Assert.AreEqual(true, jwt.ValidateLifetime);
            Assert.AreEqual(60, jwt.ClockSkewSeconds);

            var encryptor = new EncryptorSettings();
            Assert.AreEqual(false, encryptor.Enabled);
            Assert.AreEqual("App", encryptor.ApplicationName);
            Assert.AreEqual(30, encryptor.KeyLifetimeFromDays);
            Assert.AreEqual("bin/keys", encryptor.PersistKeysToFileSystem);

            Assert.AreEqual(false, new OAuthSettings().Enabled);
            Assert.AreEqual(false, new AuthenticationSettings().Enabled);
            Assert.AreEqual(false, new AuthorizationSettings().Enabled);
            Assert.AreEqual(false, new DefaultPolicySettings().RequiredSchemes);
            Assert.AreEqual(false, new DefaultPolicySettings().RequireAuthenticatedUser);
        }
    }
}
