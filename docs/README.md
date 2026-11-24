# <img src="https://github.com/kitpymes/kitpymes-core-security/raw/master/docs/images/logo.png" height="30px"> Kitpymes.Core.Security

**Security, Json Web Token, Password Service, Encrypt, Decrypt, Seguridad, Token de sesión, Servicio de contraseña, encriptador, desencriptador**

[![Build Status](https://github.com/kitpymes/kitpymes-core-security/actions/workflows/ci.yml/badge.svg)](https://github.com/kitpymes/kitpymes-core-security/actions/workflows/ci.yml)
[![NuGet Status](https://img.shields.io/nuget/v/Kitpymes.Core.Security)](https://www.nuget.org/packages/Kitpymes.Core.Security/)
[![NuGet Download](https://img.shields.io/nuget/dt/Kitpymes.Core.Security)](https://www.nuget.org/stats/packages/Kitpymes.Core.Security?groupby=Version)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/kitpymes/kitpymes-core-security/blob/master/docs/LICENSE.txt)
[![Size Repo](https://img.shields.io/github/repo-size/kitpymes/kitpymes-core-security)](https://github.com/kitpymes/kitpymes-core-security/)
[![Last Commit](https://img.shields.io/github/last-commit/kitpymes/kitpymes-core-security)](https://github.com/kitpymes/kitpymes-core-security/)

## 📋 Requerimientos 

* Visual Studio 2026 o superior

* NET TargetFramework = net10.0

* SDK de .NET = 10.0.x

* C# = 12

* Conocimientos sobre Inyección de Dependencias

## 🔧 Instalación 

_Se puede instalar usando el administrador de paquetes Nuget o CLI dotnet._

_Nuget_

```
Install-Package Kitpymes.Core.Security
```

_CLI dotnet_

```
dotnet add package Kitpymes.Core.Security
```

## ⌨️ Código

```cs
public class SecuritySettings
{
    public EncryptorSettings EncryptorSettings { get; set; } = new EncryptorSettings();
    
    public JsonWebTokenSettings JsonWebTokenSettings { get; set; } = new JsonWebTokenSettings();

    public PasswordSettings PasswordSettings { get; set; } = new PasswordSettings();
}
```

```cs
public class SecurityOptions
{
    public SecurityOptions WithEncryptor(IConfiguration configuration) {}

    public SecurityOptions WithEncryptor(Action<EncryptorOptions> options) {}

    public SecurityOptions WithEncryptor(EncryptorSettings settings) {}

    
    public SecurityOptions WithJsonWebToken(IConfiguration configuration) {}
    
    public SecurityOptions WithJsonWebToken(Action<JsonWebTokenOptions> option) {}

    public SecurityOptions WithJsonWebToken(JsonWebTokenSettings settings) {}


    public SecurityOptions WithPassword(IConfiguration configuration) {}

    public SecurityOptions WithPassword(Action<PasswordOptions> option) {}

    public SecurityOptions WithPassword(PasswordSettings settings) {}
}
```

```cs
public static class SecurityServiceCollectionExtensions
{
    public static IServiceCollection LoadSecurity(this IServiceCollection services, IConfiguration configuration) {}

    public static IServiceCollection LoadSecurity(this IServiceCollection services, Action<SecurityOptions> options) {}

    public static IServiceCollection LoadSecurity(this IServiceCollection services, SecuritySettings settings) {}
}
```

### Encryptor

```cs
public class EncryptorSettings
{
    public bool? Enabled { get; set; }

    public string? ApplicationName { get; set; }

    public int? KeyLifetimeFromDays { get; set; }

    public string? PersistKeysToFileSystem { get; set; }
}
```

```cs
public class EncryptorOptions
{
    public EncryptorOptions WithEnabled(bool enabled = true) {}

    public EncryptorOptions WithApplicationName(string? applicationName) {}

    public EncryptorOptions WithKeyLifetimeFromDays(int? keyLifetimeFromDays) {}

    public EncryptorOptions WithPersistKeysToFileSystems(string? persistKeysToFileSystem) {}
}
```

```cs
public static class EncryptorServiceCollectionExtensions
{
    public static IEncryptorService GetEncryptor(this IServiceCollection services) {}

    public static IServiceCollection LoadEncryptor(this IServiceCollection services, Action<EncryptorOptions> settings) {}

    public static IServiceCollection LoadEncryptor(this IServiceCollection services, EncryptorSettings settings) {}

    public static IServiceCollection LoadEncryptor(this IServiceCollection services, Action<IDataProtectionBuilder> dataProtectionBuilder) {}
}
```

```cs
public interface IEncryptorService
{
    string Encrypt(string? value, TimeSpan? lifetime = null);

    string Decrypt(string? value);

    string Encrypt<T>(T value, TimeSpan? lifetime = null) where T : class;

    T Decrypt<T>(string? value) where T : class, new();
}
```

### JsonWebToken

Tokens firmados con RSA (`PrivateKey` para crearlos y `PublicKey` para validarlos, en base64). La validación la hace IdentityModel: firma, nbf y exp (con un margen de reloj de 60 segundos por defecto), y emisor y audiencia si se configuran.

```cs
public interface IJsonWebTokenService
{
    GetJsonWebTokenResult Get(string? token);

    CreateJsonWebTokenResult Create(Claim claim, IDictionary<string, IEnumerable<string>>? headers = null);

    CreateJsonWebTokenResult Create(IEnumerable<Claim> claims, IDictionary<string, IEnumerable<string>>? headers = null);
}
```

```cs
public class JsonWebTokenSettings
{
    public bool? Enabled { get; set; }                  // false

    public string? AuthenticateScheme { get; set; }     // "Bearer"

    public string? ChallengeScheme { get; set; }        // "Bearer"

    public bool? RequireHttpsMetadata { get; set; }     // true

    public bool? RequireExpirationTime { get; set; }    // true

    public bool? SaveToken { get; set; }                // true

    public bool? IncludeErrorDetails { get; set; }      // true

    public bool? ValidateLifetime { get; set; }         // true: se validan nbf y exp

    public int? ClockSkewSeconds { get; set; }          // 60: margen de reloj al validar nbf y exp; un negativo se ignora

    public ExpireSettings Expire { get; set; } = new ExpireSettings();   // 30 días: duración de los tokens que crea Create

    public string? PublicKey { get; set; }

    public string? PrivateKey { get; set; }

    public string? Issuer { get; set; }                 // si se pone, se valida

    public string? Audience { get; set; }               // si se pone, se valida
}
```

```cs
services.LoadSecurity(security => security.WithAuthentication(authentication => authentication
    .WithJsonWebToken(jwt => jwt
        .WithEnabled()
        .WithPrivateKey(privateKey)
        .WithPublicKey(publicKey)
        .WithClockSkew(60))));

var jsonWebTokenService = services.GetAuthJsonWebToken();
```

### Password

Hash de contraseñas con PBKDF2 (por defecto HMACSHA256 con 600.000 iteraciones, la cifra que recomienda OWASP) y una política de contraseñas configurable.

```cs
public interface IPasswordService
{
    // Contraseña al azar que cumple la política; null si no se puede (por ejemplo, más caracteres únicos que los disponibles).
    string? CreateRandom();

    // Comprueba la política y crea el hash. Si la contraseña no la cumple, hashPassword es null y errors dice por qué.
    (string? hashPassword, ReadOnlyCollection<PasswordErrorResult> errors) Create(string? plainPassword);

    // Compara con el hash. Lee algoritmo, iteraciones y sal del propio hash, y no aplica la política.
    bool Verify(string? plainPassword, string? hashPassword);

    // true si el hash se creó con parámetros distintos de la configuración actual: hay que regenerarlo.
    bool NeedsRehash(string? hashPassword) => false;

    ReadOnlyCollection<PasswordErrorResult> Validate(string? plainPassword);
}
```

Inicio de sesión, regenerando los hashes antiguos (por ejemplo, al subir `IterCount`):

```cs
if (passwordService.Verify(password, user.PasswordHash))
{
    if (passwordService.NeedsRehash(user.PasswordHash))
    {
        // Create aplica la política actual: si la contraseña antigua no la cumple, no hay hash nuevo y se deja el que había.
        var (hash, errors) = passwordService.Create(password);

        if (hash is not null)
        {
            user.PasswordHash = hash;
        }
    }
}
```

Cada `Verify` calcula PBKDF2: limitar en la aplicación la frecuencia de intentos de inicio de sesión.

```cs
public enum PasswordErrorResult
{
    RequiredValue,

    RequireDigit,

    RequiredMinLength,

    RequiredUniqueChars,

    RequireEspecialChars,

    RequireLowercase,

    RequireUppercase,
}
```

```cs
public class PasswordSettings
{
    public bool? Enabled { get; set; }                 // false

    public bool? RequireDigit { get; set; }            // false

    public bool? RequireLowercase { get; set; }        // false

    public bool? RequireUppercase { get; set; }        // false

    public bool? RequireEspecialChars { get; set; }    // false

    public bool? RequiredUniqueChars { get; set; }     // false: sin caracteres repetidos

    public int? RequiredMinLength { get; set; }        // 6; un valor menor que 1 se ignora

    public EncryptionSettings EncryptionSettings { get; set; } = new EncryptionSettings();
}
```

```cs
public partial class EncryptionSettings
{
    public byte? FormatMarker { get; set; }            // 0xC0; no cambiarlo con hashes guardados

    public int? IterCount { get; set; }                // 600000; Create lanza por encima de 10.000.000

    public int? HeaderByteLength { get; set; }         // 13; no cambiarlo con hashes guardados

    public int? KeyDerivationAlgorithm { get; set; }   // 1 (0 = HMACSHA1, 1 = HMACSHA256, 2 = HMACSHA512)

    public int? SaltLength { get; set; }               // 16; Create lanza por encima de 1024
}
```

```cs
public class PasswordOptions
{
    public PasswordOptions WithEnabled(bool enabled = true) {}

    public PasswordOptions WithRequireDigit(bool requireDigit = true) {}

    public PasswordOptions WithRequireLowercase(bool requireLowercase = true) {}

    public PasswordOptions WithRequireUppercase(bool requireUppercase = true) {}

    public PasswordOptions WithRequireEspecialCharacters(bool requireEspecialChars = true) {}

    public PasswordOptions WithRequiredUniqueChars(bool requiredUniqueChars = true) {}

    public PasswordOptions WithRequiredMinLength(int requiredMinLength = 6) {}
}
```

```cs
services.LoadSecurity(security => security.WithPassword(password => password
    .WithEnabled()
    .WithRequireDigit()
    .WithRequiredMinLength(10)));

var passwordService = services.GetPassword();
```

## ⚙️ Pruebas Unitarias

_Cada proyecto tiene su respectivo test, se ejecutan desde el "Explorador de pruebas"_

![Tests](images/screenshot/resultados_testing.png)


## 🛠️ Construido con 

* [NET Core](https://dotnet.microsoft.com/download) - Framework de trabajo
* [C#](https://docs.microsoft.com/es-es/dotnet/csharp/) - Lenguaje de programación
* [Inserción de dependencias](https://docs.microsoft.com/es-es/aspnet/core/fundamentals/dependency-injection?view=aspnetcore-3.0) - Patrón de diseño de software
* [MSTest](https://docs.microsoft.com/es-es/dotnet/core/testing/unit-testing-with-mstest) - Pruebas unitarias
* [Nuget](https://www.nuget.org/) - Manejador de dependencias
* [Visual Studio](https://visualstudio.microsoft.com/) - Entorno de programacion


## ✒️ Autores 

* **Sebastian R Ferrari** - *Trabajo Inicial* - [kitpymes](https://kitpymes.com)


## 📄 Licencia 

* Este proyecto está bajo la Licencia [LICENSE](LICENSE.txt)


## 🎁 Gratitud 

* Este proyecto fue diseñado para compartir, creemos que es la mejor forma de ayudar 📢
* Cada persona que contribuya sera invitada a tomar una 🍺 
* Gracias a todos! 🤓

---
[Kitpymes](https://github.com/kitpymes) 😊