using Insurance.Domain.Models;
using Microsoft.JSInterop;
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
        var sameSite = "Strict";

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
        // Пытаемся получить из cookies через HttpContext (для серверной части)
        var httpContext = _httpContextAccessor.HttpContext;
        string? accessToken = null;
        string? refreshToken = null;
        string? accessTokenExpiresStr = null;
        string? refreshTokenExpiresStr = null;

        if (httpContext != null)
        {
            accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
            refreshToken = httpContext.Request.Cookies[RefreshTokenCookieName];
            accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];
            refreshTokenExpiresStr = httpContext.Request.Cookies[RefreshTokenExpiresCookieName];
        }

        // Если не найдено в HttpContext, пытаемся получить через JavaScript (для клиентской части)
        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
        {
            try
            {
                accessToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenCookieName);
                refreshToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenCookieName);
                accessTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenExpiresCookieName);
                refreshTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", RefreshTokenExpiresCookieName);
            }
            catch
            {
                // Игнорируем ошибки JS Interop
            }
        }

        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
            return null;

        var authResponse = new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiresAt = DateTime.TryParse(accessTokenExpiresStr, out var accessExpires)
                ? accessExpires
                : DateTime.UtcNow.AddMinutes(30),
            RefreshTokenExpiresAt = DateTime.TryParse(refreshTokenExpiresStr, out var refreshExpires)
                ? refreshExpires
                : DateTime.UtcNow.AddDays(7)
        };

        return authResponse;
    }

    public async Task ClearTokensAsync()
    {
        var secure = !_environment.IsDevelopment();
        var sameSite = "Strict";

        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", AccessTokenExpiresCookieName, secure, sameSite);
        await _jsRuntime.InvokeVoidAsync("cookieHelper.deleteCookie", RefreshTokenExpiresCookieName, secure, sameSite);
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        string? accessToken = null;
        string? accessTokenExpiresStr = null;

        // Пытаемся получить из HttpContext
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext != null)
        {
            accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
            accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];
        }

        // Если не найдено, пытаемся получить через JavaScript
        if (string.IsNullOrEmpty(accessToken))
        {
            try
            {
                accessToken = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenCookieName);
                accessTokenExpiresStr = await _jsRuntime.InvokeAsync<string?>("cookieHelper.getCookie", AccessTokenExpiresCookieName);
            }
            catch
            {
                return false;
            }
        }

        if (string.IsNullOrEmpty(accessToken))
            return false;

        // Проверяем, не истек ли токен
        if (DateTime.TryParse(accessTokenExpiresStr, out var expires))
        {
            return expires > DateTime.UtcNow;
        }

        return true;
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
