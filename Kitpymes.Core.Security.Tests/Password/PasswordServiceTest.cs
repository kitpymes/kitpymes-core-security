using Kitpymes.Core.Security;
using Kitpymes.Core.Security.Password;
using Kitpymes.Core.Security.Password.Extensions;
using Kitpymes.Core.Security.Password.Settings;
using Kitpymes.Core.Shared.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;

namespace Kitypmes.Core.Security.Tests
{
    [TestClass]
	public class PasswordServiceTest
    {
        private readonly IServiceCollection services;

        private IPasswordService? passwordService;

        public PasswordServiceTest()
        {
            services = new ServiceCollection();
        }

        [TestInitialize]
        public void TestInitialize() { }

        #region DefaultSettings

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void DefaultSettings_Passing_Valid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(x => x.WithEnabled())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            var isValid = passwordService.Verify(plainPassword, hashPassword!);

            Assert.IsTrue(isValid);
        }

        [TestMethod]
        [DataRow("Passw")]
        [DataRow("1a_e")]
        public void DefaultSettings_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(x => x.WithEnabled())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
        }

        #endregion DefaultSettings

        #region AppSettings

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void AppSettings_Passing_Valid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            var directoryPath = Directory.GetCurrentDirectory() + "/Fakes";
            var jsonFileName = "FakeAppSettings";

            var configuration = services
                .ToConfiguration(directoryPath, (jsonFileName, true, true))
                .ToService<IConfiguration>();

            var passwordSettings = configuration?
                .GetSection(nameof(SecuritySettings))
                .GetSection(nameof(PasswordSettings))
                .Get<PasswordSettings>();

            passwordService = services.LoadSecurity(sec => sec.WithPassword(passwordSettings!)).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            var isValid = passwordService.Verify(plainPassword, hashPassword!);

            Assert.IsTrue(isValid);
        }

        #endregion AppSettings

        #region RequireDigit

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void RequireDigit_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequireDigit())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequireDigit));
        }

        #endregion RequireDigit

        #region RequiredMinLength

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void RequiredMinLength_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequiredMinLength(30))).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequiredMinLength));
        }

        #endregion RequiredMinLength

        #region RequiredUniqueChars

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void RequiredUniqueChars_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequiredUniqueChars())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequiredUniqueChars));
        }

        #endregion RequiredUniqueChars

        #region RequireEspecialCharacters

        [TestMethod]
        [DataRow("Password")]
        [DataRow(nameof(PasswordServiceTest))]
        public void RequireEspecialCharacters_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequireEspecialCharacters())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequireEspecialChars));
        }

        #endregion RequireEspecialCharacters

        #region RequireLowercase

        [TestMethod]
        [DataRow("PASSWORD")]
        public void RequireLowercase_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequireLowercase())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequireLowercase));
        }

        #endregion RequireLowercase

        #region RequireUppercase

        [TestMethod]
        [DataRow("password")]
        public void RequireUppercase_Passing_Invalid_Value_Returns_HasErrorsAndErrors(string plainPassword)
        {
            passwordService = services.LoadSecurity(sec => sec.WithPassword(options => options.WithEnabled().WithRequireUppercase())).GetPassword();

            var (hashPassword, errors) = passwordService.Create(plainPassword);

            Assert.IsTrue(errors.Count != 0);
            Assert.IsTrue(errors.Contains(PasswordErrorResult.RequireUppercase));
        }

        #endregion RequireUppercase

        #region Verify

        private const string PlainPassword = "Password";

        private static PasswordService CreateDefaultService()
        {
            Action<PasswordOptions> options = x => x.WithEnabled();

            return new PasswordService(options.ToConfigureOrDefault().PasswordSettings);
        }

        private static byte[] CreateDecodedHash(PasswordService service)
        {
            var (hashPassword, errors) = service.Create(PlainPassword);

            Assert.AreEqual(0, errors.Count);
            Assert.IsNotNull(hashPassword);

            return Convert.FromBase64String(hashPassword);
        }

        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        [TestMethod]
        [DataRow("password")]
        [DataRow("Passwore")]
        [DataRow("PasswordX")]
        [DataRow("Passwor")]
        public void Verify_Passing_WrongPassword_Returns_False(string wrongPassword)
        {
            var service = CreateDefaultService();

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.IsTrue(service.Verify(PlainPassword, hashPassword));
            Assert.IsFalse(service.Verify(wrongPassword, hashPassword));
        }

        [TestMethod]
        public void Verify_Passing_HashWithAnyByteChanged_Returns_False()
        {
            // Cambiar cualquier byte (marca, cabecera, sal o clave derivada) tiene que dar false.
            var service = CreateDefaultService();

            var decoded = CreateDecodedHash(service);

            for (var i = 0; i < decoded.Length; i++)
            {
                var changed = (byte[])decoded.Clone();

                changed[i] ^= 0x01;

                Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(changed)), $"Byte {i} cambiado.");
            }
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void Verify_Passing_NullOrEmptyHash_Returns_False(string? hashPassword)
        {
            // Hasta la 2.1.1 lanzaba SharedException.
            var service = CreateDefaultService();

            Assert.IsFalse(service.Verify(PlainPassword, hashPassword));
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        public void Verify_Passing_NullOrEmptyPassword_Returns_False(string? plainPassword)
        {
            var service = CreateDefaultService();

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.IsFalse(service.Verify(plainPassword, hashPassword));
        }

        [TestMethod]
        [DataRow("no es base64")]
        [DataRow("AA==")]
        [DataRow("wA==")]
        [DataRow("wAAAAAE=")]
        public void Verify_Passing_MalformedHash_Returns_False(string hashPassword)
        {
            // Texto que no es base64, un solo byte (0x00 y la marca 0xC0) y una cabecera cortada.
            var service = CreateDefaultService();

            Assert.IsFalse(service.Verify(PlainPassword, hashPassword));
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(13)]
        [DataRow(29)]
        [DataRow(-1)]
        public void Verify_Passing_TruncatedOrExtendedHash_Returns_False(int length)
        {
            // Hash cortado (sólo la marca, sólo la cabecera, cabecera y sal sin la clave) o con un byte de más.
            var service = CreateDefaultService();

            var decoded = CreateDecodedHash(service);

            var changed = length > 0 ? decoded.Take(length).ToArray() : decoded.Append((byte)0).ToArray();

            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(changed)));
        }

        [TestMethod]
        [DataRow(0u)]
        [DataRow(2u)]
        [DataRow(3u)]
        [DataRow(7u)]
        [DataRow(uint.MaxValue)]
        public void Verify_Passing_HashOfOtherOrUnknownAlgorithm_Returns_False(uint algorithm)
        {
            // Con la configuración por defecto (HMACSHA256, código 1), un hash marcado como HMACSHA1 (0) o HMACSHA512 (2)
            // no vale, y un código desconocido es un hash mal formado. Hasta la 2.1.1, un código desconocido se tomaba
            // como HMACSHA256 y el hash se aceptaba.
            var service = CreateDefaultService();

            var decoded = CreateDecodedHash(service);

            WriteNetworkByteOrder(decoded, 1, algorithm);

            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(decoded)));
        }

        [TestMethod]
        public void Verify_Passing_HashWithOtherIterCountOrSaltLength_Returns_False()
        {
            var service = CreateDefaultService();

            var iterCount = CreateDecodedHash(service);
            WriteNetworkByteOrder(iterCount, 5, (uint)EncryptionSettings.DefaultIterCount + 1);

            var saltLength = CreateDecodedHash(service);
            WriteNetworkByteOrder(saltLength, 9, (uint)EncryptionSettings.DefaultSaltLength + 1);

            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(iterCount)));
            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(saltLength)));
        }

        [TestMethod]
        public void Verify_Passing_HashCreatedWithOtherAlgorithm_Returns_False()
        {
            // Un hash bueno hecho con HMACSHA512 no vale para un servicio configurado con HMACSHA256, ni al revés.
            Action<PasswordOptions> sha512 = x => x.WithEnabled();
            var sha512Settings = sha512.ToConfigureOrDefault().PasswordSettings;
            sha512Settings.EncryptionSettings.KeyDerivationAlgorithm = 2;
            sha512Settings.EncryptionSettings.AlgorithmName = "SHA512";
            var sha512Service = new PasswordService(sha512Settings);

            var service = CreateDefaultService();

            var (sha512Hash, sha512Errors) = sha512Service.Create(PlainPassword);
            var (sha256Hash, _) = service.Create(PlainPassword);

            Assert.AreEqual(0, sha512Errors.Count);
            Assert.IsTrue(sha512Service.Verify(PlainPassword, sha512Hash));
            Assert.IsFalse(service.Verify(PlainPassword, sha512Hash));
            Assert.IsFalse(sha512Service.Verify(PlainPassword, sha256Hash));
        }

        #endregion Verify

        #region CreateRandom

        [TestMethod]
        public void CreateRandom_WithLoadSettings_Returns_PlainPassword_Value()
        {
            var expectedMinLength = 7;

            var directoryPath = Directory.GetCurrentDirectory() + "/Fakes";
            var jsonFileName = "FakeAppSettings";

            var configuration = services
                .ToConfiguration(directoryPath, (jsonFileName, true, true))
                .ToService<IConfiguration>();

            var settings = configuration?
                .GetSection(nameof(SecuritySettings))
                .GetSection(nameof(PasswordSettings)).Get<PasswordSettings>();

            passwordService = services.LoadSecurity(sec => sec.WithPassword(settings!)).GetPassword();

            var plainPassword = passwordService.CreateRandom();

            Assert.IsNotNull(plainPassword);
            Assert.AreEqual(expectedMinLength, plainPassword?.Length);
        }

        [TestMethod]
        public void CreateRandom_WithCustomSettings_Returns_PlainPassword_Value()
        {
            var expectedMinLength = 7;

            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(expectedMinLength)
                .WithRequiredUniqueChars()
                .WithRequireEspecialCharacters()
                .WithRequireLowercase()
                .WithRequireUppercase();

            var passwordService = new PasswordService(options.ToConfigureOrDefault().PasswordSettings);

            var plainPassword = passwordService.CreateRandom();

            Assert.IsNotNull(plainPassword);
            Assert.AreEqual(expectedMinLength, plainPassword?.Length);
        }

        [TestMethod]
        public void CreateRandom_WithRequiredUniqueChars_Returns_UniqueChars_Always()
        {
            // El relleno al azar hasta la longitud mínima podía repetir un carácter ya usado y CreateRandom devolvía null
            // (una de cada ocho veces con esta configuración): 1000 intentos lo destapan siempre.
            var expectedMinLength = 7;

            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(expectedMinLength)
                .WithRequiredUniqueChars()
                .WithRequireEspecialCharacters()
                .WithRequireLowercase()
                .WithRequireUppercase();

            var passwordService = new PasswordService(options.ToConfigureOrDefault().PasswordSettings);

            for (var i = 0; i < 1000; i++)
            {
                var plainPassword = passwordService.CreateRandom();

                Assert.IsNotNull(plainPassword);
                Assert.AreEqual(expectedMinLength, plainPassword.Length);
                Assert.AreEqual(plainPassword.Length, plainPassword.Distinct().Count());
            }
        }

        [TestMethod]
        public void CreateRandom_WithLongMinLength_Returns_RequiredMinLength()
        {
            // Sin caracteres únicos, el relleno puede repetir caracteres: una longitud mayor que los caracteres disponibles
            // (55) tiene que salir entera.
            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(100)
                .WithRequireLowercase();

            var passwordService = new PasswordService(options.ToConfigureOrDefault().PasswordSettings);

            var plainPassword = passwordService.CreateRandom();

            Assert.IsNotNull(plainPassword);
            Assert.AreEqual(100, plainPassword.Length);
        }

        [TestMethod]
        [DataRow(3)]
        [DataRow(4)]
        public void CreateRandom_WithMinLengthReachedByRequiredChars_Returns_RequiredChars_NotDuplicated(int requiredMinLength)
        {
            // Con la longitud mínima ya alcanzada por los caracteres obligatorios, la contraseña se añadía otra vez a sí misma
            // y salía del doble de largo (por ejemplo "1@aB1@aB").
            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(requiredMinLength)
                .WithRequireEspecialCharacters()
                .WithRequireLowercase()
                .WithRequireUppercase();

            var passwordService = new PasswordService(options.ToConfigureOrDefault().PasswordSettings);

            for (var i = 0; i < 100; i++)
            {
                var plainPassword = passwordService.CreateRandom();

                Assert.IsNotNull(plainPassword);
                Assert.AreEqual(4, plainPassword.Length);
                Assert.IsTrue(plainPassword.Any(char.IsDigit));
                Assert.IsTrue(plainPassword.Any(char.IsLower));
                Assert.IsTrue(plainPassword.Any(char.IsUpper));
                Assert.IsTrue(plainPassword.Any(x => !char.IsLetterOrDigit(x)));
            }
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(5)]
        public void CreateRandom_WithRequiredUniqueCharsAndMinLengthReached_Returns_UniqueChars(int requiredMinLength)
        {
            // Con caracteres únicos y la longitud mínima ya alcanzada, la contraseña duplicada repetía todos sus caracteres
            // y CreateRandom devolvía siempre null.
            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(requiredMinLength)
                .WithRequiredUniqueChars()
                .WithRequireEspecialCharacters()
                .WithRequireLowercase()
                .WithRequireUppercase();

            var passwordService = new PasswordService(options.ToConfigureOrDefault().PasswordSettings);

            for (var i = 0; i < 100; i++)
            {
                var plainPassword = passwordService.CreateRandom();

                Assert.IsNotNull(plainPassword);
                Assert.AreEqual(5, plainPassword.Length);
                Assert.AreEqual(plainPassword.Length, plainPassword.Distinct().Count());
            }
        }

        #endregion CreateRandom
    }
}