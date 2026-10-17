// Black-box client (CLEAN_ROOM.md): auth0.net's Authentication API client
// runs the device flow against zeroauthy. Arguments: domain clientId audience
// scope. stdout carries one JSON object per line for m10-device.spec.mjs:
// {"event":"code",...} first, then {"event":"tokens",...} (exit 0) or
// {"event":"error","error":"<code>"} (exit 1).
using System.Text.Json;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Auth0.Core.Exceptions;

if (args.Length != 4)
{
    Console.Error.WriteLine("usage: DeviceE2E <domain> <clientId> <audience> <scope>");
    return 2;
}
var (domain, clientId, audience, scope) = (args[0], args[1], args[2], args[3]);
var client = new AuthenticationApiClient(new Uri(domain));

void Emit(object o) => Console.WriteLine(JsonSerializer.Serialize(o));

var start = await client.StartDeviceFlowAsync(new DeviceCodeRequest { ClientId = clientId, Audience = audience, Scope = scope });
Emit(new
{
    @event = "code", user_code = start.UserCode, verification_uri = start.VerificationUri,
    verification_uri_complete = start.VerificationUriComplete, interval = start.Interval, expires_in = start.ExpiresIn,
});

var interval = TimeSpan.FromSeconds(start.Interval);
AccessTokenResponse tokens;
while (true)
{
    await Task.Delay(interval);
    string? error;
    try
    {
        tokens = await client.GetTokenAsync(new DeviceCodeTokenRequest { ClientId = clientId, DeviceCode = start.DeviceCode });
        break;
    }
    catch (ErrorApiException e) { error = e.ApiError?.Error; }
    catch (RateLimitApiException e) { error = e.ApiError?.Error; } // HTTP 429 (slow_down)
    if (error == "authorization_pending") continue;
    if (error == "slow_down") { interval += TimeSpan.FromSeconds(5); continue; }
    Emit(new { @event = "error", error });
    return 1;
}

var refreshed = await client.GetTokenAsync(new RefreshTokenRequest { ClientId = clientId, RefreshToken = tokens.RefreshToken });
Emit(new
{
    @event = "tokens", access = !string.IsNullOrEmpty(tokens.AccessToken), id = !string.IsNullOrEmpty(tokens.IdToken),
    refresh = !string.IsNullOrEmpty(tokens.RefreshToken), refreshed = !string.IsNullOrEmpty(refreshed.AccessToken),
});
return 0;
