using Insurance.Domain.Models;
using Microsoft.JSInterop;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Insurance.MiniApp.Services;

public class TokenService(
    IAuthService authService,
    IHttpContextAccessor httpContextAccessor,
    IWebHostEnvironment environment,
    IJSRuntime jsRuntime) : ITokenService
{
    private const string AccessTokenCookieName = "access_token";
    private const string RefreshTokenCookieName = "refresh_token";
    private const string AccessTokenExpiresCookieName = "access_token_expires";
    private const string RefreshTokenExpiresCookieName = "refresh_token_expires";
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Защита от параллельных refresh-запросов (static — общий для всех circuit'ов).
    /// </summary>
    private static readonly SemaphoreSlim _refreshLock = new(1, 1);

    private readonly IAuthService _authService = authService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IWebHostEnvironment _environment = environment;
    private readonly IJSRuntime _jsRuntime = jsRuntime;

    public event Action? AuthStateChanged;

    private void NotifyAuthStateChanged() => AuthStateChanged?.Invoke();

    #region Public API

    public async Task SaveTokensAsync(AuthResponse authResponse)
    {
        var secure = !_environment.IsDevelopment();
        var accessTokenExpires = authResponse.AccessTokenExpiresAt.ToUniversalTime();
        var refreshTokenExpires = authResponse.RefreshTokenExpiresAt.ToUniversalTime();

        try
        {
            var sameSite = "Lax";

            // Все куки живут до истечения refresh-токена, чтобы JWT access-токена
            // был доступен для чтения claims даже после его логического истечения
            await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
                AccessTokenCookieName, authResponse.AccessToken, refreshTokenExpires, secure, sameSite);

            await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
                AccessTokenExpiresCookieName, accessTokenExpires.ToString("O"), refreshTokenExpires, secure, sameSite);

            await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
                RefreshTokenCookieName, authResponse.RefreshToken, refreshTokenExpires, secure, sameSite);

            await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
                RefreshTokenExpiresCookieName, refreshTokenExpires.ToString("O"), refreshTokenExpires, secure, sameSite);
        }
        catch (InvalidOperationException)
        {
            // JS Interop недоступен (prerendering) — сохраняем через HTTP-заголовки
            SaveTokensViaHttpContext(authResponse, secure, refreshTokenExpires);
        }

        NotifyAuthStateChanged();
    }

    /// <summary>
    /// Читает токены из cookies. НЕ выполняет refresh — чистое чтение.
    /// Приоритет: JS Interop (актуальное состояние браузера) → HttpContext (prerendering fallback).
    /// </summary>
    public async Task<AuthResponse?> GetTokensAsync()
    {
        string? accessToken = null;
        string? refreshToken = null;
        string? accessTokenExpiresStr = null;
        string? refreshTokenExpiresStr = null;

        try
        {
            accessToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenCookieName);
            refreshToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenCookieName);
            accessTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenExpiresCookieName);
            refreshTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenExpiresCookieName);
        }
        catch
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext != null)
            {
                accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
                refreshToken = httpContext.Request.Cookies[RefreshTokenCookieName];
                accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];
                refreshTokenExpiresStr = httpContext.Request.Cookies[RefreshTokenExpiresCookieName];
            }
        }

        if (string.IsNullOrEmpty(accessToken) && string.IsNullOrEmpty(refreshToken))
            return null;

        var accessTokenExpiresAt = DateTime.TryParse(
                accessTokenExpiresStr, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var accessExpires)
            ? accessExpires.ToUniversalTime()
            : DateTime.MinValue;

        var refreshTokenExpiresAt = DateTime.TryParse(
                refreshTokenExpiresStr, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var refreshExpires)
            ? refreshExpires.ToUniversalTime()
            : DateTime.MinValue;

        return new AuthResponse
        {
            AccessToken = accessToken ?? string.Empty,
            RefreshToken = refreshToken ?? string.Empty,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshTokenExpiresAt = refreshTokenExpiresAt
        };
    }

    /// <summary>
    /// Возвращает валидный access-токен, обновляя через refresh при необходимости.
    /// </summary>
    public async Task<string?> EnsureValidAccessTokenAsync()
    {
        var tokens = await GetTokensAsync();
        if (tokens == null)
            return null;

        if (!string.IsNullOrEmpty(tokens.AccessToken) &&
            tokens.AccessTokenExpiresAt > DateTime.UtcNow.Add(RefreshBuffer))
        {
            return tokens.AccessToken;
        }

        if (string.IsNullOrEmpty(tokens.RefreshToken) ||
            tokens.RefreshTokenExpiresAt <= DateTime.UtcNow)
        {
            await ClearTokensAsync();
            return null;
        }

        return await RefreshWithLockAsync();
    }

    /// <summary>
    /// Принудительное обновление токена (после получения 401).
    /// </summary>
    public Task<string?> ForceRefreshAsync() => RefreshWithLockAsync();

    public async Task ClearTokensAsync()
    {
        try
        {
            var secure = !_environment.IsDevelopment();
            var sameSite = "Lax";

            await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenCookieName, secure, sameSite);
            await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenCookieName, secure, sameSite);
            await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenExpiresCookieName, secure, sameSite);
            await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenExpiresCookieName, secure, sameSite);
        }
        catch (InvalidOperationException)
        {
            ClearTokensViaHttpContext();
        }

        NotifyAuthStateChanged();
    }

    /// <summary>
    /// Проверяет, аутентифицирован ли пользователь.
    /// Возвращает true, если есть валидный access-токен ИЛИ валидный refresh-токен.
    /// НЕ выполняет refresh — это чистая проверка для UI.
    /// </summary>
    public async Task<bool> IsAuthenticatedAsync()
    {
        var tokens = await GetTokensAsync();
        if (tokens == null)
            return false;

        if (!string.IsNullOrEmpty(tokens.AccessToken) &&
            tokens.AccessTokenExpiresAt > DateTime.UtcNow)
            return true;

        if (!string.IsNullOrEmpty(tokens.RefreshToken) &&
            tokens.RefreshTokenExpiresAt > DateTime.UtcNow)
            return true;

        return false;
    }

    /// <summary>
    /// Извлекает email из JWT access-токена. Работает и с просроченным токеном,
    /// т.к. куки живут до истечения refresh-токена.
    /// </summary>
    public async Task<string?> GetUserEmailAsync()
    {
        var tokens = await GetTokensAsync();
        if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
            return null;

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(tokens.AccessToken);

            var email = jsonToken.Claims.FirstOrDefault(c =>
                c.Type == "email" ||
                c.Type == ClaimTypes.Email ||
                c.Type == JwtRegisteredClaimNames.Email)?.Value;

            return email;
        }
        catch
        {
            return null;
        }
    }

    #endregion

    #region Private refresh logic

    /// <summary>
    /// Выполняет refresh с защитой от параллельных вызовов.
    /// Double-check pattern: после получения блокировки перепроверяет токен.
    /// </summary>
    private async Task<string?> RefreshWithLockAsync()
    {
        await _refreshLock.WaitAsync();
        try
        {
            var currentTokens = await GetTokensAsync();
            if (currentTokens != null &&
                !string.IsNullOrEmpty(currentTokens.AccessToken) &&
                currentTokens.AccessTokenExpiresAt > DateTime.UtcNow.Add(RefreshBuffer))
            {
                return currentTokens.AccessToken;
            }

            if (currentTokens == null ||
                string.IsNullOrEmpty(currentTokens.RefreshToken) ||
                currentTokens.RefreshTokenExpiresAt <= DateTime.UtcNow)
            {
                await ClearTokensAsync();
                return null;
            }

            var result = await _authService.RefreshTokenAsync(
                new RefreshTokenRequest { RefreshToken = currentTokens.RefreshToken });

            if (result.IsSuccess && result.Data != null)
            {
                await SaveTokensAsync(result.Data);
                return result.Data.AccessToken;
            }

            await ClearTokensAsync();
            return null;
        }
        catch
        {
            try { await ClearTokensAsync(); } catch { }
            return null;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    #endregion

    #region HttpContext fallback (prerendering)

    /// <summary>
    /// Сохраняет токены через Set-Cookie заголовок HTTP-ответа.
    /// Используется при prerendering, когда JS Interop недоступен.
    /// </summary>
    private void SaveTokensViaHttpContext(
        AuthResponse authResponse, bool secure, DateTime cookieExpires)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null || httpContext.Response.HasStarted)
            return;

        var cookieOptions = new CookieOptions
        {
            Expires = new DateTimeOffset(cookieExpires),
            Path = "/",
            Secure = secure,
            SameSite = SameSiteMode.Lax,
            IsEssential = true
        };

        var accessTokenExpires = authResponse.AccessTokenExpiresAt.ToUniversalTime();

        httpContext.Response.Cookies.Append(AccessTokenCookieName, authResponse.AccessToken, cookieOptions);
        httpContext.Response.Cookies.Append(AccessTokenExpiresCookieName, accessTokenExpires.ToString("O"), cookieOptions);
        httpContext.Response.Cookies.Append(RefreshTokenCookieName, authResponse.RefreshToken, cookieOptions);
        httpContext.Response.Cookies.Append(RefreshTokenExpiresCookieName, cookieExpires.ToString("O"), cookieOptions);
    }

    /// <summary>
    /// Удаляет токены через Set-Cookie заголовок HTTP-ответа.
    /// </summary>
    private void ClearTokensViaHttpContext()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null || httpContext.Response.HasStarted)
            return;

        var deleteOptions = new CookieOptions
        {
            Path = "/",
            Secure = !_environment.IsDevelopment(),
            SameSite = SameSiteMode.Lax
        };

        httpContext.Response.Cookies.Delete(AccessTokenCookieName, deleteOptions);
        httpContext.Response.Cookies.Delete(RefreshTokenCookieName, deleteOptions);
        httpContext.Response.Cookies.Delete(AccessTokenExpiresCookieName, deleteOptions);
        httpContext.Response.Cookies.Delete(RefreshTokenExpiresCookieName, deleteOptions);
    }

    #endregion
}
