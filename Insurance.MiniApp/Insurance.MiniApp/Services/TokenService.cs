using System.Net;
using Insurance.Domain.Models;
using Microsoft.AspNetCore.Http;

namespace Insurance.MiniApp.Services;

public class TokenService(IHttpContextAccessor httpContextAccessor, IWebHostEnvironment environment) : ITokenService
{
    private const string AccessTokenCookieName = "access_token";
    private const string RefreshTokenCookieName = "refresh_token";
    private const string AccessTokenExpiresCookieName = "access_token_expires";
    private const string RefreshTokenExpiresCookieName = "refresh_token_expires";

    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IWebHostEnvironment _environment = environment;

    public Task SaveTokensAsync(AuthResponse authResponse)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return Task.CompletedTask;

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !_environment.IsDevelopment(), // В production только HTTPS, в development разрешаем HTTP
            SameSite = SameSiteMode.Strict,
            Path = "/"
        };

        // Сохраняем Access Token (срок действия до истечения токена)
        var accessTokenExpires = authResponse.AccessTokenExpiresAt.ToUniversalTime();
        cookieOptions.Expires = accessTokenExpires;
        httpContext.Response.Cookies.Append(AccessTokenCookieName, authResponse.AccessToken, cookieOptions);
        httpContext.Response.Cookies.Append(AccessTokenExpiresCookieName, accessTokenExpires.ToString("O"), cookieOptions);

        // Сохраняем Refresh Token (срок действия до истечения токена)
        var refreshTokenExpires = authResponse.RefreshTokenExpiresAt.ToUniversalTime();
        cookieOptions.Expires = refreshTokenExpires;
        httpContext.Response.Cookies.Append(RefreshTokenCookieName, authResponse.RefreshToken, cookieOptions);
        httpContext.Response.Cookies.Append(RefreshTokenExpiresCookieName, refreshTokenExpires.ToString("O"), cookieOptions);

        return Task.CompletedTask;
    }

    public Task<AuthResponse?> GetTokensAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return Task.FromResult<AuthResponse?>(null);

        var accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
        var refreshToken = httpContext.Request.Cookies[RefreshTokenCookieName];
        var accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];
        var refreshTokenExpiresStr = httpContext.Request.Cookies[RefreshTokenExpiresCookieName];

        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
            return Task.FromResult<AuthResponse?>(null);

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

        return Task.FromResult<AuthResponse?>(authResponse);
    }

    public Task ClearTokensAsync()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return Task.CompletedTask;

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = !_environment.IsDevelopment(), // В production только HTTPS, в development разрешаем HTTP
            SameSite = SameSiteMode.Strict,
            Path = "/",
            Expires = DateTime.UtcNow.AddDays(-1) // Удаляем cookie, устанавливая прошедшую дату
        };

        httpContext.Response.Cookies.Delete(AccessTokenCookieName, cookieOptions);
        httpContext.Response.Cookies.Delete(RefreshTokenCookieName, cookieOptions);
        httpContext.Response.Cookies.Delete(AccessTokenExpiresCookieName, cookieOptions);
        httpContext.Response.Cookies.Delete(RefreshTokenExpiresCookieName, cookieOptions);

        return Task.CompletedTask;
    }

    public bool IsAuthenticated()
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
            return false;

        var accessToken = httpContext.Request.Cookies[AccessTokenCookieName];
        var accessTokenExpiresStr = httpContext.Request.Cookies[AccessTokenExpiresCookieName];

        if (string.IsNullOrEmpty(accessToken))
            return false;

        // Проверяем, не истек ли токен
        if (DateTime.TryParse(accessTokenExpiresStr, out var expires))
        {
            return expires > DateTime.UtcNow;
        }

        return true;
    }
}
