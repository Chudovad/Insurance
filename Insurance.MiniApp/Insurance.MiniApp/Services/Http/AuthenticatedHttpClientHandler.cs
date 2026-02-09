using System.Net;
using System.Net.Http.Headers;

namespace Insurance.MiniApp.Services.Http;

/// <summary>
/// DelegatingHandler, который:
/// 1. Добавляет Bearer-токен к запросам (через TokenService.EnsureValidAccessTokenAsync)
/// 2. Ретраит запрос один раз при получении 401 (через TokenService.ForceRefreshAsync)
/// Вся логика refresh централизована в TokenService (единый SemaphoreSlim).
/// </summary>
public class AuthenticatedHttpClientHandler(ITokenService tokenService) : DelegatingHandler
{
    private readonly ITokenService _tokenService = tokenService;

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
        if (IsAuthEndpoint(request))
        {
            return await base.SendAsync(request, cancellationToken);
        }

        var accessToken = await _tokenService.EnsureValidAccessTokenAsync();
        if (!string.IsNullOrEmpty(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized && !string.IsNullOrEmpty(accessToken))
        {
            var newAccessToken = await _tokenService.ForceRefreshAsync();
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
