namespace Insurance.API.Services;

public sealed class JwtOptions
{
    public string Issuer { get; init; } = string.Empty;
    public string Audience { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public int AccessTokenLifetimeMinutes { get; init; } = 30;
    public int RefreshTokenLifetimeDays { get; init; } = 7;
}

