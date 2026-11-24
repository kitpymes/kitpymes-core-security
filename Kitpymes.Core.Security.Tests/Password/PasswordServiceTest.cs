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
            // Un hash HMACSHA256 con la cabecera cambiada a HMACSHA1 (0) o HMACSHA512 (2) no vale: se calcula con ese
            // algoritmo y la clave no coincide. Un código desconocido es un hash mal formado (hasta la 2.1.1 se tomaba
            // como HMACSHA256 y el hash se aceptaba).
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

        private static PasswordService CreateService(int keyDerivationAlgorithm, int iterCount, int saltLength = 16)
        {
            Action<PasswordOptions> options = x => x.WithEnabled();
            var settings = options.ToConfigureOrDefault().PasswordSettings;
            settings.EncryptionSettings.KeyDerivationAlgorithm = keyDerivationAlgorithm;
            settings.EncryptionSettings.IterCount = iterCount;
            settings.EncryptionSettings.SaltLength = saltLength;

            return new PasswordService(settings);
        }

        [TestMethod]
        [DataRow(0, 1000)]
        [DataRow(0, 50000)]
        [DataRow(1, 1000)]
        [DataRow(1, 50000)]
        [DataRow(0, 120000)]
        [DataRow(1, 120000)]
        [DataRow(2, 1000)]
        [DataRow(2, 50000)]
        [DataRow(2, 120000)]
        public void Verify_Passing_HashCreatedWithOtherAlgorithmOrIterCount_Returns_True(int keyDerivationAlgorithm, int iterCount)
        {
            // El algoritmo y las iteraciones se leen del hash: un hash creado con otra configuración se verifica con la
            // configuración por defecto (HMACSHA256, 600000) y con cualquier otra. Hasta la 2.2.0 daba false.
            var creator = CreateService(keyDerivationAlgorithm, iterCount);
            var otherConfigurations = new[] { CreateDefaultService(), CreateService(2, 2000), CreateService(0, 3000, 32) };

            var (hashPassword, errors) = creator.Create(PlainPassword);

            Assert.AreEqual(0, errors.Count);
            Assert.IsTrue(creator.Verify(PlainPassword, hashPassword));

            foreach (var service in otherConfigurations)
            {
                Assert.IsTrue(service.Verify(PlainPassword, hashPassword));
                Assert.IsFalse(service.Verify("Passwore", hashPassword));
            }
        }

        [TestMethod]
        [DataRow(32)]
        [DataRow(64)]
        public void Verify_Passing_HashCreatedWithOtherSaltLength_Returns_True(int saltLength)
        {
            var creator = CreateService(1, 1000, saltLength);

            var (hashPassword, _) = creator.Create(PlainPassword);

            Assert.IsTrue(CreateDefaultService().Verify(PlainPassword, hashPassword));
            Assert.IsFalse(CreateDefaultService().Verify("Passwore", hashPassword));
        }

        [TestMethod]
        [DataRow(0u)]
        [DataRow(10_000_001u)]
        [DataRow(uint.MaxValue)]
        public void Verify_Passing_HashWithIterCountOutOfRange_Returns_False(uint iterCount)
        {
            // 0 iteraciones o más de 10 millones es un hash mal formado: no se llega a calcular nada.
            var service = CreateDefaultService();

            var decoded = CreateDecodedHash(service);

            WriteNetworkByteOrder(decoded, 5, iterCount);

            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(decoded)));
        }

        [TestMethod]
        public void Verify_Passing_HashWithZeroSaltLength_Returns_False()
        {
            var service = CreateDefaultService();

            var decoded = CreateDecodedHash(service).Take(13).ToArray();

            WriteNetworkByteOrder(decoded, 9, 0);

            Assert.IsFalse(service.Verify(PlainPassword, Convert.ToBase64String(decoded)));
        }

        [TestMethod]
        public void Verify_Passing_HashWithLowerHeaderByteLengthConfigured_Returns_False()
        {
            // Una cabecera configurada por debajo de 13 bytes no cabe: el hash no se puede leer.
            var service = CreateDefaultService();
            var (hashPassword, _) = service.Create(PlainPassword);

            Action<PasswordOptions> options = x => x.WithEnabled();
            var settings = options.ToConfigureOrDefault().PasswordSettings;
            settings.EncryptionSettings.HeaderByteLength = 12;

            Assert.IsFalse(new PasswordService(settings).Verify(PlainPassword, hashPassword));
        }

        [TestMethod]
        [DataRow(14)]
        [DataRow(20)]
        public void Verify_Passing_HashWithLongerHeaderByteLength_DependsOnConfiguration(int headerByteLength)
        {
            // La longitud de la cabecera no va en el hash: con la misma configuración se verifica, con otra no.
            Action<PasswordOptions> options = x => x.WithEnabled();
            var settings = options.ToConfigureOrDefault().PasswordSettings;
            settings.EncryptionSettings.HeaderByteLength = headerByteLength;
            var service = new PasswordService(settings);

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.IsTrue(service.Verify(PlainPassword, hashPassword));
            Assert.IsFalse(service.NeedsRehash(hashPassword));
            Assert.IsFalse(CreateDefaultService().Verify(PlainPassword, hashPassword));
        }

        [TestMethod]
        public void Verify_Passing_HashWithOtherFormatMarker_DependsOnConfiguration()
        {
            // La marca de formato tampoco se lee de la configuración del que creó el hash: tiene que ser la misma.
            Action<PasswordOptions> options = x => x.WithEnabled();
            var settings = options.ToConfigureOrDefault().PasswordSettings;
            settings.EncryptionSettings.FormatMarker = 0xC1;
            settings.EncryptionSettings.FormatMarker = null;
            var service = new PasswordService(settings);

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.AreEqual((byte)0xC1, settings.EncryptionSettings.FormatMarker);
            Assert.AreEqual(0xC1, Convert.FromBase64String(hashPassword!)[0]);
            Assert.IsTrue(service.Verify(PlainPassword, hashPassword));
            Assert.IsFalse(CreateDefaultService().Verify(PlainPassword, hashPassword));
        }

        private static string CreateHeaderOnlyHash(uint iterCount, uint saltLength)
        {
            // Hash escrito a mano con la cabecera pedida y sal y clave a cero, con la longitud que exige el formato.
            var bytes = new byte[13 + (2 * (int)saltLength)];
            bytes[0] = EncryptionSettings.DefaultFormatMarker;
            WriteNetworkByteOrder(bytes, 1, 1);
            WriteNetworkByteOrder(bytes, 5, iterCount);
            WriteNetworkByteOrder(bytes, 9, saltLength);

            return Convert.ToBase64String(bytes);
        }

        [TestMethod]
        [DataRow(10_000_000u, false)]
        [DataRow(10_000_001u, true)]
        public void NeedsRehash_Passing_HashAtIterCountLimit_ReadsOnlyUpToTheLimit(uint iterCount, bool expected)
        {
            // Con la configuración en las mismas iteraciones, un hash dentro del límite tiene los parámetros actuales
            // (false) y uno por encima es un hash mal formado (true). NeedsRehash no calcula la clave, así que es barato.
            var service = CreateService(1, (int)iterCount);

            Assert.AreEqual(expected, service.NeedsRehash(CreateHeaderOnlyHash(iterCount, 16)));
        }

        [TestMethod]
        [DataRow(1024u, false)]
        [DataRow(1025u, true)]
        public void NeedsRehash_Passing_HashAtSaltLengthLimit_ReadsOnlyUpToTheLimit(uint saltLength, bool expected)
        {
            // Una sal de más de 1024 bytes es un hash mal formado: el coste de verificar crece con ella.
            var service = CreateService(1, 1000, (int)saltLength);

            Assert.AreEqual(expected, service.NeedsRehash(CreateHeaderOnlyHash(1000, saltLength)));
            Assert.IsFalse(service.Verify(PlainPassword, CreateHeaderOnlyHash(1000, saltLength)));
        }

        [TestMethod]
        public void Create_Passing_SamePasswordTwice_Returns_DifferentHashes()
        {
            // La sal es aleatoria: dos hashes de la misma contraseña no coinciden, y los dos verifican.
            var service = CreateDefaultService();

            var (first, _) = service.Create(PlainPassword);
            var (second, _) = service.Create(PlainPassword);

            Assert.AreNotEqual(first, second);
            Assert.IsTrue(service.Verify(PlainPassword, first));
            Assert.IsTrue(service.Verify(PlainPassword, second));
        }

        [TestMethod]
        public void Verify_Passing_ObsoleteAlgorithmName_IsIgnored()
        {
            // AlgorithmName está obsoleto (KPY0004): no cambia ni Create ni Verify.
            Action<PasswordOptions> options = x => x.WithEnabled();
            var settings = options.ToConfigureOrDefault().PasswordSettings;
#pragma warning disable KPY0004
            Assert.AreEqual(EncryptionSettings.DefaultAlgorithmName, settings.EncryptionSettings.AlgorithmName);
            settings.EncryptionSettings.AlgorithmName = "MD5";
            settings.EncryptionSettings.AlgorithmName = " ";
            Assert.AreEqual("MD5", settings.EncryptionSettings.AlgorithmName);
#pragma warning restore KPY0004
            var service = new PasswordService(settings);

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.IsTrue(service.Verify(PlainPassword, hashPassword));
            Assert.IsTrue(CreateDefaultService().Verify(PlainPassword, hashPassword));
        }

        [TestMethod]
        public void NeedsRehash_Passing_HashWithCurrentParameters_Returns_False()
        {
            var service = CreateService(2, 2000, 32);

            var (hashPassword, _) = service.Create(PlainPassword);

            Assert.IsFalse(service.NeedsRehash(hashPassword));
        }

        [TestMethod]
        [DataRow(0, 2000, 32)]
        [DataRow(1, 2000, 32)]
        [DataRow(2, 1000, 32)]
        [DataRow(2, 3000, 32)]
        [DataRow(2, 2000, 16)]
        [DataRow(2, 2000, 64)]
        public void NeedsRehash_Passing_HashWithOtherParameters_Returns_True(int keyDerivationAlgorithm, int iterCount, int saltLength)
        {
            // La configuración actual es HMACSHA512, 2000 iteraciones y sal de 32 bytes; cambia uno de los tres.
            var current = CreateService(2, 2000, 32);
            var old = CreateService(keyDerivationAlgorithm, iterCount, saltLength);

            var (hashPassword, _) = old.Create(PlainPassword);

            Assert.IsTrue(current.Verify(PlainPassword, hashPassword));
            Assert.IsTrue(current.NeedsRehash(hashPassword));
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("no es base64")]
        [DataRow("wA==")]
        public void NeedsRehash_Passing_NullOrMalformedHash_Returns_True(string? hashPassword)
        {
            Assert.IsTrue(CreateDefaultService().NeedsRehash(hashPassword));
        }

        [TestMethod]
        public void NeedsRehash_Passing_ThroughInterfaceDefault_Returns_False()
        {
            // Una implementación propia de IPasswordService que no sobrescribe NeedsRehash nunca pide regenerar.
            IPasswordService service = new PasswordServiceWithoutRehash();

            Assert.IsFalse(service.NeedsRehash("cualquier cosa"));
        }

        private sealed class PasswordServiceWithoutRehash : IPasswordService
        {
            public string? CreateRandom() => null;

            public (string? hashPassword, System.Collections.ObjectModel.ReadOnlyCollection<PasswordErrorResult> errors) Create(string? plainPassword)
                => (null, new System.Collections.ObjectModel.ReadOnlyCollection<PasswordErrorResult>(Array.Empty<PasswordErrorResult>()));

            public bool Verify(string? plainPassword, string? hashPassword) => false;

            public System.Collections.ObjectModel.ReadOnlyCollection<PasswordErrorResult> Validate(string? plainPassword)
                => new System.Collections.ObjectModel.ReadOnlyCollection<PasswordErrorResult>(Array.Empty<PasswordErrorResult>());
        }

        private static PasswordService CreatePolicyService(Action<PasswordOptions> options)
        {
            return new PasswordService(options.ToConfigureOrDefault().PasswordSettings);
        }

        [TestMethod]
        [DataRow("Password")]
        [DataRow("abcdef")]
        [DataRow("a")]
        public void Verify_Passing_PasswordThatMetOldPolicy_WithStricterPolicy_Returns_True(string plainPassword)
        {
            // La política sólo se comprueba en Create: endurecerla no deja fuera a quien ya tenía contraseña.
            // Hasta la 2.3.0, Verify aplicaba la política actual y estos casos daban false.
            var oldService = CreatePolicyService(x => x.WithEnabled().WithRequiredMinLength(1));
            var newService = CreatePolicyService(x => x
                .WithEnabled()
                .WithRequiredMinLength(12)
                .WithRequireDigit()
                .WithRequireEspecialCharacters()
                .WithRequireUppercase()
                .WithRequiredUniqueChars());

            var (hashPassword, oldErrors) = oldService.Create(plainPassword);

            Assert.AreEqual(0, oldErrors.Count);
            Assert.IsTrue(newService.Verify(plainPassword, hashPassword));
            Assert.IsFalse(newService.Verify(plainPassword + "x", hashPassword));

            var (newHash, newErrors) = newService.Create(plainPassword);

            Assert.IsNull(newHash);
            Assert.AreNotEqual(0, newErrors.Count);
        }

        [TestMethod]
        public void Verify_Passing_PasswordThatFailsPolicy_StillChecksTheHash()
        {
            // Sin la política, Verify depende sólo del hash: una contraseña corta y distinta sigue dando false.
            var oldService = CreatePolicyService(x => x.WithEnabled().WithRequiredMinLength(1));
            var (hashPassword, _) = oldService.Create("a");

            Assert.IsTrue(CreateDefaultService().Verify("a", hashPassword));
            Assert.IsFalse(CreateDefaultService().Verify("b", hashPassword));
            Assert.IsFalse(CreateDefaultService().Verify("A", hashPassword));
        }

        [TestMethod]
        public void DefaultIterCount_Is_OwaspRecommendationForHmacSha256()
        {
            // OWASP, Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256, 600000 iteraciones.
            Assert.AreEqual(600000, EncryptionSettings.DefaultIterCount);

            var decoded = CreateDecodedHash(CreateDefaultService());

            Assert.AreEqual(1u, ReadNetworkByteOrder(decoded, 1));
            Assert.AreEqual(600000u, ReadNetworkByteOrder(decoded, 5));
        }

        [TestMethod]
        public void NeedsRehash_Passing_HashWithOldDefaultIterCount_Returns_True_And_Verifies()
        {
            // Un hash creado con el valor por defecto de la 2.3.0 (50000) se sigue verificando y pide regenerarse;
            // el hash nuevo ya no lo pide.
            var service = CreateDefaultService();
            var (oldHash, _) = CreateService(1, 50000).Create(PlainPassword);

            Assert.IsTrue(service.Verify(PlainPassword, oldHash));
            Assert.IsTrue(service.NeedsRehash(oldHash));

            var (newHash, _) = service.Create(PlainPassword);

            Assert.IsTrue(service.Verify(PlainPassword, newHash));
            Assert.IsFalse(service.NeedsRehash(newHash));
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)buffer[offset] << 24)
                | ((uint)buffer[offset + 1] << 16)
                | ((uint)buffer[offset + 2] << 8)
                | buffer[offset + 3];
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