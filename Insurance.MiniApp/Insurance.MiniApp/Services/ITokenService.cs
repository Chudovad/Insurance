using Insurance.Domain.Models;

namespace Insurance.MiniApp.Services;

public interface ITokenService
{
    Task SaveTokensAsync(AuthResponse authResponse);
    Task<AuthResponse?> GetTokensAsync();
    Task ClearTokensAsync();
    Task<bool> IsAuthenticatedAsync();
}
