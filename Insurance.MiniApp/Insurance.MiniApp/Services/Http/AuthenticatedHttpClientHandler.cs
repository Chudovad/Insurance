using Insurance.Domain.Models;
using System.Net;
using System.Net.Http.Headers;

namespace Insurance.MiniApp.Services.Http;

/// <summary>
/// DelegatingHandler, который:
/// 1. Добавляет Bearer-токен к запросам
/// 2. Проактивно обновляет access-токен за 30 секунд до истечения
/// 3. Ретраит запрос один раз при получении 401
/// 4. Защищён от параллельных refresh-запросов через SemaphoreSlim
/// </summary>
public class AuthenticatedHttpClientHandler(
    ITokenService tokenService,
    IHttpClientFactory httpClientFactory) : DelegatingHandler
{
    private readonly ITokenService _tokenService = tokenService;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    /// <summary>
    /// Буфер времени: обновляем токен за 30 секунд до фактического истечения,
    /// чтобы избежать гонки между проверкой и отправкой запроса.
    /// </summary>
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Защита от параллельных вызовов refresh (static, т.к. handler может пересоздаваться).
    /// </summary>
    private static readonly SemaphoreSlim RefreshLock = new(1, 1);

    private static readonly string[] AuthEndpoints =
    [
        "api/auth/register",
        "api/auth/login",
        "api/auth/refresh"
    ];

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Не добавляем токен к эндпоинтам аутентификации
        if (IsAuthEndpoint(request))
        {
            return await base.SendAsync(request, cancellationToken);
        }

        // Получаем валидный access-токен (с проактивным обновлением)
        var accessToken = await GetValidAccessTokenAsync();
        if (!string.IsNullOrEmpty(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // Если сервер вернул 401 — пробуем обновить токен и повторить запрос один раз
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            var newAccessToken = await ForceRefreshAsync();
            if (!string.IsNullOrEmpty(newAccessToken))
            {
                var retryRequest = await CloneRequestAsync(request);
                retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newAccessToken);

                response.Dispose();
                response = await base.SendAsync(retryRequest, cancellationToken);
            }
        }

        return response;
    }

    /// <summary>
    /// Возвращает валидный access-токен. Если токен скоро истечёт — обновляет.
    /// </summary>
    private async Task<string?> GetValidAccessTokenAsync()
    {
        var tokens = await _tokenService.GetTokensAsync();
        if (tokens == null)
            return null;

        // Access-токен ещё действителен (с учётом буфера) — используем его
        if (!string.IsNullOrEmpty(tokens.AccessToken) &&
            tokens.AccessTokenExpiresAt > DateTime.UtcNow.Add(RefreshBuffer))
        {
            return tokens.AccessToken;
        }

        // Access-токен истёк или скоро истечёт — обновляем
        if (!string.IsNullOrEmpty(tokens.RefreshToken) &&
            tokens.RefreshTokenExpiresAt > DateTime.UtcNow)
        {
            return await RefreshAccessTokenAsync(tokens.RefreshToken);
        }

        // Refresh-токен тоже просрочен — очищаем
        await _tokenService.ClearTokensAsync();
        return null;
    }

    /// <summary>
    /// Принудительное обновление токена (вызывается после получения 401).
    /// </summary>
    private async Task<string?> ForceRefreshAsync()
    {
        var tokens = await _tokenService.GetTokensAsync();
        if (tokens == null ||
            string.IsNullOrEmpty(tokens.RefreshToken) ||
            tokens.RefreshTokenExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        return await RefreshAccessTokenAsync(tokens.RefreshToken);
    }

    /// <summary>
    /// Выполняет refresh через API. Защищён от параллельных вызовов.
    /// После получения блокировки перепроверяет токен (double-check pattern),
    /// чтобы не обновлять повторно, если другой поток уже обновил.
    /// </summary>
    private async Task<string?> RefreshAccessTokenAsync(string refreshToken)
    {
        await RefreshLock.WaitAsync();
        try
        {
            // Double-check: возможно, другой запрос уже обновил токен
            var currentTokens = await _tokenService.GetTokensAsync();
            if (currentTokens != null &&
                !string.IsNullOrEmpty(currentTokens.AccessToken) &&
                currentTokens.AccessTokenExpiresAt > DateTime.UtcNow.Add(RefreshBuffer))
            {
                return currentTokens.AccessToken;
            }

            // Делаем refresh через "AuthApiClient" (без handler, без рекурсии)
            var authClient = _httpClientFactory.CreateClient("AuthApiClient");
            var response = await authClient.PostAsJsonAsync("api/auth/refresh",
                new RefreshTokenRequest { RefreshToken = refreshToken });

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
                if (authResponse != null)
                {
                    await _tokenService.SaveTokensAsync(authResponse);
                    return authResponse.AccessToken;
                }
            }

            // Refresh не удался — очищаем токены
            await _tokenService.ClearTokensAsync();
            return null;
        }
        finally
        {
            RefreshLock.Release();
        }
    }

    /// <summary>
    /// Клонирует HTTP-запрос для повторной отправки (оригинал нельзя отправить дважды).
    /// </summary>
    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version
        };

        if (request.Content != null)
        {
            var content = await request.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(content);

            foreach (var header in request.Content.Headers)
            {
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        foreach (var prop in request.Options)
        {
            clone.Options.TryAdd(prop.Key, prop.Value);
        }

        return clone;
    }

    private static bool IsAuthEndpoint(HttpRequestMessage request)
    {
        var path = request.RequestUri?.AbsolutePath.TrimEnd('/') ?? string.Empty;
        return AuthEndpoints.Any(ep => path.EndsWith(ep, StringComparison.OrdinalIgnoreCase));
    }
}
