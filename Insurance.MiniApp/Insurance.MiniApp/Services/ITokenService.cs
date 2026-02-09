using Insurance.Domain.Models;

namespace Insurance.MiniApp.Services;

public interface ITokenService
{
    /// <summary>
    /// Событие, вызываемое при изменении состояния аутентификации (логин, логаут, обновление токена).
    /// Обработчики НЕ должны вызывать EnsureValidAccessTokenAsync/ForceRefreshAsync (риск deadlock).
    /// </summary>
    event Action? AuthStateChanged;

    /// <summary>
    /// Сохраняет токены в cookies.
    /// </summary>
    Task SaveTokensAsync(AuthResponse authResponse);

    /// <summary>
    /// Читает токены из cookies. НЕ выполняет refresh — чистое чтение.
    /// </summary>
    Task<AuthResponse?> GetTokensAsync();

    /// <summary>
    /// Возвращает валидный access-токен, при необходимости обновляя через refresh.
    /// Защищён от параллельных вызовов через SemaphoreSlim.
    /// </summary>
    Task<string?> EnsureValidAccessTokenAsync();

    /// <summary>
    /// Принудительно обновляет токен через refresh (после получения 401).
    /// </summary>
    Task<string?> ForceRefreshAsync();

    /// <summary>
    /// Удаляет все токены из cookies.
    /// </summary>
    Task ClearTokensAsync();

    /// <summary>
    /// Проверяет, аутентифицирован ли пользователь.
    /// Возвращает true, если есть валидный access-токен ИЛИ валидный refresh-токен.
    /// НЕ выполняет refresh.
    /// </summary>
    Task<bool> IsAuthenticatedAsync();

    /// <summary>
    /// Извлекает email пользователя из JWT access-токена (работает и с просроченным токеном).
    /// </summary>
    Task<string?> GetUserEmailAsync();
}
