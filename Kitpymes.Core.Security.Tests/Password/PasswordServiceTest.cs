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
        public void CreateRandom_WithMinLengthBelowRequiredChars_Returns_RequiredChars_NotDuplicated()
        {
            // Con la longitud mínima ya alcanzada por los caracteres obligatorios, la contraseña se añadía otra vez a sí misma
            // y salía del doble de largo (por ejemplo "1@aB1@aB").
            Action<PasswordOptions> options = x => x.WithEnabled()
                .WithRequireDigit()
                .WithRequiredMinLength(3)
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