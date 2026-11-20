// Public reproduction of dotnet/aspnetcore#70678 using owned, disposable data.
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

await RunAsync(false);
await RunAsync(true);

static async Task RunAsync(bool advanceProvider)
{
    var keyDir = Path.Combine(Path.GetTempPath(), "identity-public-issue-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(keyDir);
    try
    {
        var clock = new AdjustableClock(DateTimeOffset.UtcNow);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyDir));
        services.AddSingleton<TimeProvider>(advanceProvider ? clock : TimeProvider.System);
        services.AddSingleton<IUserStore<LabUser>, LabStore>();
        services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromSeconds(2));
        services.AddIdentityCore<LabUser>().AddDefaultTokenProviders();
        using var sp = services.BuildServiceProvider();
        var manager = sp.GetRequiredService<UserManager<LabUser>>();
        var user = new LabUser { Id = "owned-user", UserName = "owned-user", SecurityStamp = Guid.NewGuid().ToString("N") };
        Check((await manager.CreateAsync(user, "Dummy-Initial-Password-123!")).Succeeded, "create");
        var token = await manager.GeneratePasswordResetTokenAsync(user);
        var purpose = UserManager<LabUser>.ResetPasswordTokenPurpose;
        Check(await manager.VerifyUserTokenAsync(user, manager.Options.Tokens.PasswordResetTokenProvider, purpose, token), "fresh valid");
        Check(!await manager.VerifyUserTokenAsync(user, manager.Options.Tokens.PasswordResetTokenProvider, "other-purpose", token), "wrong purpose denied");
        if (advanceProvider) clock.Advance(TimeSpan.FromMinutes(2));
        else await Task.Delay(TimeSpan.FromSeconds(2.7));
        var result = await manager.ResetPasswordAsync(user, token, "Dummy-Replacement-Password-456!");
        var changed = await manager.CheckPasswordAsync(user, "Dummy-Replacement-Password-456!");
        Check(advanceProvider ? result.Succeeded && changed : !result.Succeeded && !changed, "reset outcome");
        Console.WriteLine($"mode={(advanceProvider ? "provider-advanced" : "system-time")} fresh=true wrong-purpose=false reset={result.Succeeded} changed={changed} wall-seconds={(DateTimeOffset.UtcNow - clock.Initial).TotalSeconds:F3} provider-seconds={(advanceProvider ? clock.GetUtcNow() - clock.Initial : DateTimeOffset.UtcNow - clock.Initial).TotalSeconds:F3}");
        var asm = typeof(DataProtectorTokenProvider<LabUser>).Assembly;
        Console.WriteLine($"identity-version={asm.GetName().Version} sha256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(asm.Location)))}");
    }
    finally { Directory.Delete(keyDir, true); }
}

static void Check(bool ok, string what) { if (!ok) throw new Exception("FAIL " + what); }

sealed class AdjustableClock(DateTimeOffset initial) : TimeProvider
{
    private DateTimeOffset _utcNow = initial;
    public DateTimeOffset Initial { get; } = initial;
    public override DateTimeOffset GetUtcNow() => _utcNow;
    public void Advance(TimeSpan by) => _utcNow += by;
}

sealed class LabUser
{
    public string Id { get; set; } = "";
    public string UserName { get; set; } = "";
    public string? NormalizedUserName { get; set; }
    public string? PasswordHash { get; set; }
    public string SecurityStamp { get; set; } = "";
}

sealed class LabStore : IUserPasswordStore<LabUser>, IUserSecurityStampStore<LabUser>
{
    private LabUser? _user;
    public void Dispose() { }
    public Task<string> GetUserIdAsync(LabUser user, CancellationToken ct) => Task.FromResult(user.Id);
    public Task<string?> GetUserNameAsync(LabUser user, CancellationToken ct) => Task.FromResult<string?>(user.UserName);
    public Task SetUserNameAsync(LabUser user, string? name, CancellationToken ct) { user.UserName = name ?? ""; return Task.CompletedTask; }
    public Task<string?> GetNormalizedUserNameAsync(LabUser user, CancellationToken ct) => Task.FromResult(user.NormalizedUserName);
    public Task SetNormalizedUserNameAsync(LabUser user, string? name, CancellationToken ct) { user.NormalizedUserName = name; return Task.CompletedTask; }
    public Task<IdentityResult> CreateAsync(LabUser user, CancellationToken ct) { _user = user; return Task.FromResult(IdentityResult.Success); }
    public Task<IdentityResult> UpdateAsync(LabUser user, CancellationToken ct) { _user = user; return Task.FromResult(IdentityResult.Success); }
    public Task<IdentityResult> DeleteAsync(LabUser user, CancellationToken ct) { _user = null; return Task.FromResult(IdentityResult.Success); }
    public Task<LabUser?> FindByIdAsync(string id, CancellationToken ct) => Task.FromResult(_user?.Id == id ? _user : null);
    public Task<LabUser?> FindByNameAsync(string name, CancellationToken ct) => Task.FromResult(_user?.NormalizedUserName == name ? _user : null);
    public Task SetPasswordHashAsync(LabUser user, string? hash, CancellationToken ct) { user.PasswordHash = hash; return Task.CompletedTask; }
    public Task<string?> GetPasswordHashAsync(LabUser user, CancellationToken ct) => Task.FromResult(user.PasswordHash);
    public Task<bool> HasPasswordAsync(LabUser user, CancellationToken ct) => Task.FromResult(user.PasswordHash is not null);
    public Task SetSecurityStampAsync(LabUser user, string stamp, CancellationToken ct) { user.SecurityStamp = stamp; return Task.CompletedTask; }
    public Task<string?> GetSecurityStampAsync(LabUser user, CancellationToken ct) => Task.FromResult(user.SecurityStamp);
}
