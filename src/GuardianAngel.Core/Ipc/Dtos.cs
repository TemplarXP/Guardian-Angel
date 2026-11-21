using System.Text.Json;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Ipc;

public sealed record PendingChangeDto(Guid Id, string Kind, string Description, DateTimeOffset RequestedAtUtc,
    long? RemainingMs, long? RequiredMs, ChangeStatus Status, string? FailureReason);

public sealed record EnforcementItemDto(string Name, bool Healthy, string Detail);

public sealed record StatusDto(
    bool IsLocked,
    DateTimeOffset? LockedAtUtc,
    FilterConfig? Filter,
    bool DelayEnabled,
    TimeSpan Delay,
    bool HasPartner,
    long PartnerLockoutRemainingMs,
    string ReflectionMessage,
    BrowserOptions Browser,
    IReadOnlyList<PendingChangeDto> Pending,
    IReadOnlyList<PendingChangeDto> RecentHistory,
    IReadOnlyList<EnforcementItemDto> Enforcement,
    bool SafeLocked,
    string? SafeLockedReason,
    bool IsDebugBuild,
    TimeSpan MinDelay,
    TimeSpan MaxDelay);

public sealed record TestFilterRequest(FilterConfig Filter, string? BlockedDomain);

public sealed record PartnerBeginResponse(string OtpAuthUri, string SecretForManualEntry);
public sealed record CodeRequest(string Code);

public sealed record LockRequest(
    FilterConfig Filter,
    bool DelayEnabled,
    TimeSpan Delay,
    string ReflectionMessage,
    BrowserOptions Browser,
    string? BlockedTestDomain,
    bool UserConfirmedBlockPage);

public sealed record LockResponse(bool Locked, ConnectionTestResult Test, IReadOnlyList<string> Errors);

public sealed record ChangeRequestDto(string Kind, JsonElement Parameters, string? Confirmation = null);

public sealed record ChangePreviewDto(Direction Direction, string Description, IReadOnlyList<string> Errors,
    TimeSpan? Delay, string ConfirmationPhrase, string ReflectionMessage);

public sealed record ChangeResultDto(bool Applied, bool Queued, Guid? Id, IReadOnlyList<string> Errors);

public sealed record IdRequest(Guid Id);
public sealed record ExpediteRequest(Guid Id, string Code);
public sealed record ExpediteResult(string Result, long LockoutRemainingMs);

public sealed record UninstallStatusDto(bool Allowed, string Message);
