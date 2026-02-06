using Insurance.Domain.Models;

namespace Insurance.MiniApp.Services;

public interface IAuthService
{
    /// <summary>
    /// Проверяет авторизацию. Перед проверкой обновляет access-токен, если он истёк, но refresh-токен действителен.
    /// </summary>
    Task<bool> IsAuthenticatedAsync();
    Task<AuthResult<AuthResponse>> RegisterAsync(RegisterRequest request);
    Task<AuthResult<AuthResponse>> LoginAsync(LoginRequest request);
    Task<AuthResult<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request);
    Task<AuthResult<object>> ChangePasswordAsync(ChangePasswordRequest request);
}

public class AuthResult<T>
{
    public bool IsSuccess { get; set; }
    public T? Data { get; set; }
    public string? ErrorMessage { get; set; }
    public System.Net.HttpStatusCode? StatusCode { get; set; }

    public static AuthResult<T> Success(T data) => new() { IsSuccess = true, Data = data };
    public static AuthResult<T> Failure(string errorMessage, System.Net.HttpStatusCode? statusCode = null) 
        => new() { IsSuccess = false, ErrorMessage = errorMessage, StatusCode = statusCode };
}
