using Insurance.Domain.Models;
using System.Net;

namespace Insurance.MiniApp.Services;

public class AuthService(IHttpClientFactory httpClientFactory) : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    /// <summary>
    /// Клиент для auth-эндпоинтов (без AuthenticatedHttpClientHandler, избегаем циклическую зависимость).
    /// </summary>
    private HttpClient AuthClient => _httpClientFactory.CreateClient("AuthApiClient");

    /// <summary>
    /// Клиент для авторизованных запросов (с AuthenticatedHttpClientHandler).
    /// </summary>
    private HttpClient ApiClient => _httpClientFactory.CreateClient("ApiClient");

    public async Task<AuthResult<AuthResponse>> RegisterAsync(RegisterRequest request)
    {
        try
        {
            var response = await AuthClient.PostAsJsonAsync("api/auth/register", request);

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
                return AuthResult<AuthResponse>.Success(authResponse!);
            }

            var errorMessage = await response.Content.ReadAsStringAsync();

            return response.StatusCode switch
            {
                HttpStatusCode.Conflict => AuthResult<AuthResponse>.Failure(
                    "Пользователь с таким email уже существует",
                    response.StatusCode),
                HttpStatusCode.BadRequest => AuthResult<AuthResponse>.Failure(
                    errorMessage,
                    response.StatusCode),
                _ => AuthResult<AuthResponse>.Failure(
                    "Ошибка при регистрации. Попробуйте позже.",
                    response.StatusCode)
            };
        }
        catch (HttpRequestException ex)
        {
            return AuthResult<AuthResponse>.Failure($"Ошибка подключения к серверу: {ex.Message}");
        }
        catch (Exception ex)
        {
            return AuthResult<AuthResponse>.Failure($"Неожиданная ошибка: {ex.Message}");
        }
    }

    public async Task<AuthResult<AuthResponse>> LoginAsync(LoginRequest request)
    {
        try
        {
            var response = await AuthClient.PostAsJsonAsync("api/auth/login", request);

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
                return AuthResult<AuthResponse>.Success(authResponse!);
            }

            var errorMessage = await response.Content.ReadAsStringAsync();

            return response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => AuthResult<AuthResponse>.Failure(
                    "Неверный email или пароль",
                    response.StatusCode),
                HttpStatusCode.BadRequest => AuthResult<AuthResponse>.Failure(
                    errorMessage,
                    response.StatusCode),
                _ => AuthResult<AuthResponse>.Failure(
                    "Ошибка при входе. Попробуйте позже.",
                    response.StatusCode)
            };
        }
        catch (HttpRequestException ex)
        {
            return AuthResult<AuthResponse>.Failure($"Ошибка подключения к серверу: {ex.Message}");
        }
        catch (Exception ex)
        {
            return AuthResult<AuthResponse>.Failure($"Неожиданная ошибка: {ex.Message}");
        }
    }

    public async Task<AuthResult<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request)
    {
        try
        {
            var response = await AuthClient.PostAsJsonAsync("api/auth/refresh", request);

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
                return AuthResult<AuthResponse>.Success(authResponse!);
            }

            var errorMessage = await response.Content.ReadAsStringAsync();

            return response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => AuthResult<AuthResponse>.Failure(
                    "Невалидный или просроченный refresh-токен",
                    response.StatusCode),
                HttpStatusCode.BadRequest => AuthResult<AuthResponse>.Failure(
                    errorMessage,
                    response.StatusCode),
                _ => AuthResult<AuthResponse>.Failure(
                    "Ошибка при обновлении токена. Попробуйте позже.",
                    response.StatusCode)
            };
        }
        catch (HttpRequestException ex)
        {
            return AuthResult<AuthResponse>.Failure($"Ошибка подключения к серверу: {ex.Message}");
        }
        catch (Exception ex)
        {
            return AuthResult<AuthResponse>.Failure($"Неожиданная ошибка: {ex.Message}");
        }
    }

    public async Task<AuthResult<object>> ChangePasswordAsync(ChangePasswordRequest request)
    {
        try
        {
            var response = await ApiClient.PostAsJsonAsync("api/auth/change-password", request);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<object>();
                return AuthResult<object>.Success(result!);
            }

            var errorMessage = await response.Content.ReadAsStringAsync();

            return response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => AuthResult<object>.Failure(
                    "Неверный текущий пароль или требуется повторная авторизация",
                    response.StatusCode),
                HttpStatusCode.BadRequest => AuthResult<object>.Failure(
                    errorMessage,
                    response.StatusCode),
                HttpStatusCode.NotFound => AuthResult<object>.Failure(
                    "Пользователь не найден",
                    response.StatusCode),
                _ => AuthResult<object>.Failure(
                    "Ошибка при изменении пароля. Попробуйте позже.",
                    response.StatusCode)
            };
        }
        catch (HttpRequestException ex)
        {
            return AuthResult<object>.Failure($"Ошибка подключения к серверу: {ex.Message}");
        }
        catch (Exception ex)
        {
            return AuthResult<object>.Failure($"Неожиданная ошибка: {ex.Message}");
        }
    }
}
