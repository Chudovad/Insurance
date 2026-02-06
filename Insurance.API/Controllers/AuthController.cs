using Insurance.Domain.Models;
using Insurance.API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Insurance.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IJwtService jwtService) : ControllerBase
{
    // Для примера храним пользователей в памяти.
    // В реальном проекте вместо этого должен быть доступ к БД.
    private static readonly List<User> Users = [];

    private readonly IJwtService _jwtService = jwtService;

    [HttpPost("register")]
    [AllowAnonymous]
    public ActionResult<AuthResponse> Register([FromBody] RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest("Email и пароль обязательны.");
        }

        if (Users.Any(u => u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase)))
        {
            return Conflict("Пользователь с таким email уже существует.");
        }

        var user = new User
        {
            Email = request.Email.Trim(),
            PasswordHash = HashPassword(request.Password)
        };

        var tokens = _jwtService.GenerateTokens(user);
        user.RefreshToken = tokens.RefreshToken;
        user.RefreshTokenExpiresAt = tokens.RefreshTokenExpiresAt;
        Users.Add(user);

        return Ok(tokens);
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public ActionResult<AuthResponse> Login([FromBody] LoginRequest request)
    {
        var user = Users.SingleOrDefault(u =>
            u.Email.Equals(request.Email, StringComparison.OrdinalIgnoreCase));

        if (user is null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized("Неверный email или пароль.");
        }

        var tokens = _jwtService.GenerateTokens(user);
        user.RefreshToken = tokens.RefreshToken;
        user.RefreshTokenExpiresAt = tokens.RefreshTokenExpiresAt;

        return Ok(tokens);
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public ActionResult<AuthResponse> Refresh([FromBody] RefreshTokenRequest request)
    {
        var user = Users.SingleOrDefault(u =>
            u.RefreshToken == request.RefreshToken &&
            u.RefreshTokenExpiresAt != null &&
            u.RefreshTokenExpiresAt > DateTime.UtcNow);

        if (user is null)
        {
            return Unauthorized("Невалидный или просроченный refresh-токен.");
        }

        var tokens = _jwtService.GenerateTokens(user);
        user.RefreshToken = tokens.RefreshToken;
        user.RefreshTokenExpiresAt = tokens.RefreshTokenExpiresAt;

        return Ok(tokens);
    }

    [HttpGet("me")]
    [Authorize]
    public ActionResult<object> Me()
    {
        var email = User.FindFirstValue(ClaimTypes.Name) ?? User.FindFirstValue(ClaimTypes.Email);
        var id = User.FindFirstValue(ClaimTypes.NameIdentifier);

        return Ok(new { Id = id, Email = email });
    }

    [HttpPost("change-password")]
    [Authorize]
    public ActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest("Текущий и новый пароль обязательны.");
        }

        if (request.NewPassword.Length < 6)
        {
            return BadRequest("Новый пароль должен содержать минимум 6 символов.");
        }

        if (request.CurrentPassword == request.NewPassword)
        {
            return BadRequest("Новый пароль должен отличаться от текущего.");
        }

        // Получаем email пользователя из токена
        var email = User.FindFirstValue(ClaimTypes.Name) ?? User.FindFirstValue(ClaimTypes.Email);
        if (string.IsNullOrEmpty(email))
        {
            return Unauthorized("Не удалось определить пользователя.");
        }

        // Находим пользователя
        var user = Users.SingleOrDefault(u =>
            u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));

        if (user is null)
        {
            return NotFound("Пользователь не найден.");
        }

        // Проверяем текущий пароль
        if (!VerifyPassword(request.CurrentPassword, user.PasswordHash))
        {
            return Unauthorized("Неверный текущий пароль.");
        }

        // Обновляем пароль
        user.PasswordHash = HashPassword(request.NewPassword);

        return Ok(new { Message = "Пароль успешно изменен." });
    }

    private static string HashPassword(string password)
    {
        // Для примера: PBKDF2 + случайная "соль", сохранённая в начале строки.
        byte[] salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        var hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100_000,
            numBytesRequested: 32);

        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split('.');
        if (parts.Length != 2)
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var expectedHash = Convert.FromBase64String(parts[1]);

        var actualHash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100_000,
            numBytesRequested: 32);

        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}

