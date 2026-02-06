using Insurance.Domain.Models;
using Microsoft.JSInterop;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Insurance.MiniApp.Services;

public class TokenService(IHttpContextAccessor httpContextAccessor, IWebHostEnvironment environment, IJSRuntime jsRuntime) : ITokenService
{
    private const string AccessTokenCookieName = "access_token";
    private const string RefreshTokenCookieName = "refresh_token";
    private const string AccessTokenExpiresCookieName = "access_token_expires";
    private const string RefreshTokenExpiresCookieName = "refresh_token_expires";

    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IWebHostEnvironment _environment = environment;
    private readonly IJSRuntime _jsRuntime = jsRuntime;

    public async Task SaveTokensAsync(AuthResponse authResponse)
    {
        var secure = !_environment.IsDevelopment();
        var sameSite = "Lax";

        // Сохраняем Access Token (срок действия до истечения токена)
        var accessTokenExpires = authResponse.AccessTokenExpiresAt.ToUniversalTime();
        await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
            AccessTokenCookieName,
            authResponse.AccessToken,
            accessTokenExpires,
            secure,
            sameSite);

        await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
            AccessTokenExpiresCookieName,
            accessTokenExpires.ToString("O"),
            accessTokenExpires,
            secure,
            sameSite);

        // Сохраняем Refresh Token (срок действия до истечения токена)
        var refreshTokenExpires = authResponse.RefreshTokenExpiresAt.ToUniversalTime();
        await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
            RefreshTokenCookieName,
            authResponse.RefreshToken,
            refreshTokenExpires,
            secure,
            sameSite);

        await _jsRuntime.InvokeVoidAsync("cookieHelper.setCookie",
            RefreshTokenExpiresCookieName,
            refreshTokenExpires.ToString("O"),
            refreshTokenExpires,
            secure,
            sameSite);
    }

    public async Task<AuthResponse?> GetTokensAsync()
    {
        string? accessToken = null;
        string? refreshToken = null;
        string? accessTokenExpiresStr = null;
        string? refreshTokenExpiresStr = null;

        // 1. Пытаемся получить из HttpContext (доступен при SSR/prerendering)
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext != null)
        {
            accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
            refreshToken = httpContext.Request.Cookies[RefreshTokenCookieName];
            accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];
            refreshTokenExpiresStr = httpContext.Request.Cookies[RefreshTokenExpiresCookieName];
        }

        // 2. Для значений, не найденных в HttpContext, пробуем JS Interop (интерактивный режим)
        try
        {
            if (string.IsNullOrEmpty(accessToken))
                accessToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenCookieName);

            if (string.IsNullOrEmpty(refreshToken))
                refreshToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenCookieName);

            if (string.IsNullOrEmpty(accessTokenExpiresStr))
                accessTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenExpiresCookieName);

            if (string.IsNullOrEmpty(refreshTokenExpiresStr))
                refreshTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenExpiresCookieName);
        }
        catch
        {
            // JS Interop недоступен (например, при prerendering)
        }

        // 3. Если оба токена отсутствуют — пользователь не авторизован
        if (string.IsNullOrEmpty(accessToken) && string.IsNullOrEmpty(refreshToken))
            return null;

        // 4. Парсим даты с RoundtripKind (формат "O" — ISO 8601)
        //    Если дату распарсить не удалось — считаем токен просроченным (DateTime.MinValue)
        var accessTokenExpiresAt = DateTime.TryParse(
                accessTokenExpiresStr, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var accessExpires)
            ? accessExpires.ToUniversalTime()
            : DateTime.MinValue;

        var refreshTokenExpiresAt = DateTime.TryParse(
                refreshTokenExpiresStr, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var refreshExpires)
            ? refreshExpires.ToUniversalTime()
            : DateTime.MinValue;

        // 5. Если refresh-токен просрочен и access-токена нет — сессия недействительна
        if (refreshTokenExpiresAt <= DateTime.UtcNow && string.IsNullOrEmpty(accessToken))
            return null;

        return new AuthResponse
        {
            AccessToken = accessToken ?? string.Empty,
            RefreshToken = refreshToken ?? string.Empty,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshTokenExpiresAt = refreshTokenExpiresAt
        };
    }

    public async Task ClearTokensAsync()
    {
        var secure = !_environment.IsDevelopment();
        var sameSite = "Lax";

        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenExpiresCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenExpiresCookieName, secure, sameSite);
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        var tokens = await GetTokensAsync();
        if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
            return false;

        return tokens.AccessTokenExpiresAt > DateTime.UtcNow;
    }

    public async Task<string?> GetUserEmailAsync()
    {
        var tokens = await GetTokensAsync();
        if (tokens == null || string.IsNullOrEmpty(tokens.AccessToken))
            return null;

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(tokens.AccessToken);

            // Пытаемся получить email из различных claims
            var email = jsonToken.Claims.FirstOrDefault(c => c.Type == "email" ||
                                                             c.Type == ClaimTypes.Email ||
                                                             c.Type == JwtRegisteredClaimNames.Email)?.Value;

            return email;
        }
        catch
        {
            return null;
        }
    }
}
