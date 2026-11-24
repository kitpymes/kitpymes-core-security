using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Encryptor;
using Kitpymes.Core.Security.Encryptor.Extensions;
using Kitpymes.Core.Security.Encryptor.Settings;
using Kitpymes.Core.Security.Password.Extensions;
using Kitpymes.Core.Security.Password.Settings;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace Kitypmes.Core.Security.Tests
{
    [TestClass]
    public class EncryptorConfigurationTest
    {
        private static string NewDirectory() => Path.Combine(Path.GetTempPath(), "kitpymes-keys-" + Guid.NewGuid().ToString("N"));

        private static IEncryptorService LoadEncryptor(string applicationName, string directory, int keyLifetimeFromDays = 30)
            => new ServiceCollection()
                .LoadSecurity(sec => sec.WithEncryptor(x => x
                    .WithEnabled()
                    .WithApplicationName(applicationName)
                    .WithKeyLifetimeFromDays(keyLifetimeFromDays)
                    .WithPersistKeysToFileSystems(directory)))
                .GetEncryptor();

        [TestMethod]
        public void Encryptor_Persists_Keys_In_Configured_Directory_With_Configured_Lifetime()
        {
            var directory = NewDirectory();

            Assert.IsFalse(Directory.Exists(directory));

            var encryptor = LoadEncryptor("AppTest", directory, 10);

            Assert.AreEqual("hola", encryptor.Decrypt(encryptor.Encrypt("hola")));

            Assert.IsTrue(Directory.Exists(directory));

            var keyFile = Directory.GetFiles(directory, "key-*.xml").Single();
            var key = XDocument.Load(keyFile).Root!;

            var activation = DateTimeOffset.Parse(key.Element("activationDate")!.Value, System.Globalization.CultureInfo.InvariantCulture);
            var expiration = DateTimeOffset.Parse(key.Element("expirationDate")!.Value, System.Globalization.CultureInfo.InvariantCulture);

            Assert.AreEqual(TimeSpan.FromDays(10), expiration - activation);
        }

        [TestMethod]
        public void Encryptor_With_Other_ApplicationName_Cannot_Decrypt()
        {
            var directory = NewDirectory();

            var encrypted = LoadEncryptor("AppUno", directory).Encrypt("hola");

            Assert.AreEqual("hola", LoadEncryptor("AppUno", directory).Decrypt(encrypted));
            Assert.ThrowsExactly<CryptographicException>(() => LoadEncryptor("AppDos", directory).Decrypt(encrypted));
        }

        [TestMethod]
        public void Encryptor_Passing_NullOrEmpty_Throws()
        {
            var encryptor = LoadEncryptor("AppTest", NewDirectory());

            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => encryptor.Encrypt(null!));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => encryptor.Encrypt(string.Empty));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => encryptor.Decrypt(null!));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => encryptor.Decrypt(string.Empty));
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => encryptor.Encrypt<List<string>>(null!));
        }

        [TestMethod]
        public void EncryptorService_Passing_NullProvider_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new EncryptorService(null!));
        }

        [TestMethod]
        public void GetEncryptor_WithoutEncryptor_Throws()
        {
            Assert.ThrowsExactly<global::Kitpymes.Core.Shared.Util.SharedException>(() => new ServiceCollection().GetEncryptor());
        }

        [TestMethod]
        public void EncryptorOptions_Stores_Every_Value()
        {
            var settings = new EncryptorOptions()
                .WithEnabled()
                .WithApplicationName("AppTest")
                .WithKeyLifetimeFromDays(9)
                .WithPersistKeysToFileSystems("claves")
                .EncryptorSettings;

            Assert.AreEqual(true, settings.Enabled);
            Assert.AreEqual("AppTest", settings.ApplicationName);
            Assert.AreEqual(9, settings.KeyLifetimeFromDays);
            Assert.AreEqual("claves", settings.PersistKeysToFileSystem);
        }

        [TestMethod]
        public void SecurityOptions_FromConfiguration_Reads_Encryptor_And_Password()
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SecuritySettings:EncryptorSettings:ApplicationName"] = "DesdeConfiguracion",
                    ["SecuritySettings:PasswordSettings:RequiredMinLength"] = "9",
                })
                .Build();

            var settings = new SecurityOptions()
                .WithEncryptor(configuration)
                .WithPassword(configuration)
                .SecuritySettings;

            Assert.AreEqual("DesdeConfiguracion", settings.EncryptorSettings!.ApplicationName);
            Assert.AreEqual(9, settings.PasswordSettings!.RequiredMinLength);
        }

        [TestMethod]
        public void LoadSecurity_Registers_SecuritySettings_And_Enabled_Services()
        {
            var services = new ServiceCollection();

            services.LoadSecurity(sec => sec
                .WithPassword(x => x.WithEnabled())
                .WithEncryptor(x => x.WithEnabled().WithPersistKeysToFileSystems(NewDirectory())));

            var provider = services.BuildServiceProvider();

            Assert.IsNotNull(provider.GetService<SecuritySettings>());
            Assert.IsNotNull(services.GetPassword());
            Assert.IsNotNull(services.GetEncryptor());
        }

        [TestMethod]
        public void LoadSecurity_Passing_DisabledServices_Registers_None()
        {
            var services = new ServiceCollection();

            services.LoadSecurity(sec => sec
                .WithPassword(x => x.WithEnabled(false))
                .WithEncryptor(x => x.WithEnabled(false)));

            Assert.IsFalse(services.Any(x => x.ServiceType == typeof(IEncryptorService)));
            Assert.IsFalse(services.Any(x => x.ServiceType == typeof(Kitpymes.Core.Security.Password.IPasswordService)));
        }
    }
}
