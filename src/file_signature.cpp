#include "stoker/plugin_support.h"
#include "signature_policy.h"

STOKER_PLUGIN_MANIFEST(R"json({
  "manifestVersion": 1,
  "id": "app.stokerhq.file-signature",
  "name": "File signature policy",
  "type": "hook",
  "version": "1.0.3",
  "abi": 1,
  "description": "Redirects CryptQueryObject file queries and optionally accepts WinVerifyTrust checks for integrations that replace a signed library. Does not alter files on disk.",
  "hosts": ["steamworks", "ubisoft", "galaxy", "eos"],
  "config": {
    "type": "object", "additionalProperties": false,
    "properties": {
      "process": {
        "type": "string", "title": "Game executable",
        "description": "Only act in this executable. Omit to act in every process. File name only, ASCII case-insensitive.",
        "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$"
      },
      "match": {
        "type": "string", "title": "File the game checks",
        "description": "Exact final filename to redirect, ASCII case-insensitive. Directories and filename suffixes do not match.",
        "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$"
      },
      "replace": {
        "type": "string", "title": "File to query instead",
        "description": "Filename in the same directory. CryptQueryObject queries this file and preserves the original output parameters and result.",
        "minLength": 1, "maxLength": 259, "pattern": "^(?!\\.{1,2}$)[^\\\\/:]+$"
      },
      "trustPolicy": {
        "type": "string", "title": "WinVerifyTrust policy", "default": "forward",
        "enum": ["forward", "accept-matched", "accept-all"],
        "description": "forward preserves verification. accept-matched accepts file checks for the configured filename. accept-all returns success for every WinVerifyTrust call in the selected process."
      },
      "logging": {
        "type": "string", "title": "Call logging", "default": "quiet",
        "enum": ["quiet", "changes"],
        "description": "changes logs redirected file queries and accepted trust checks. Initialization is always logged."
      }
    },
    "required": ["match", "replace"]
  }
})json");

#ifdef _WIN32
#include <wincrypt.h>
#include <wintrust.h>
#include <string>
namespace
{
    using namespace stoker::plugin;
    using QueryFn = BOOL (WINAPI*)(DWORD, const void*, DWORD, DWORD, DWORD, DWORD*, DWORD*, DWORD*, HCERTSTORE*, HCRYPTMSG*, const void**);
    using TrustFn = LONG (WINAPI*)(HWND, GUID*, LPVOID);
    QueryFn g_query = nullptr;
    TrustFn g_trust = nullptr;
    wchar_t g_match[MAX_PATH] = L"", g_replace[MAX_PATH] = L"";
    signature::TrustPolicy g_policy = signature::TrustPolicy::Forward;
    bool g_log = false;
    thread_local bool g_inside = false;

    // A leaf SEH reader avoids faulting on a game's malformed/unterminated pointer. No C++
    // destructor lives inside the SEH frame; string allocation belongs in its caller's try block.
    bool ReadPath(const wchar_t* path, wchar_t* output) noexcept
    {
        __try
        {
            for (size_t i = 0; i < 32768; ++i) { output[i] = path[i]; if (!output[i]) return true; }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return false;
    }

    bool Matches(const wchar_t* path) noexcept
    {
        wchar_t buffer[32768];
        return path && ReadPath(path, buffer) && signature::Matches<wchar_t>(buffer, g_match);
    }

    bool MatchesTrust(LPVOID data) noexcept
    {
        // File and blob/catalog unions have different layouts. Only a sufficiently sized FILE
        // request with an actual matching path is eligible for the scoped policy.
        WINTRUST_DATA trust{}; WINTRUST_FILE_INFO file{}; SIZE_T read = 0;
        if (!data || !ReadProcessMemory(GetCurrentProcess(), data, &trust, sizeof trust, &read) ||
            read != sizeof trust || trust.cbStruct < sizeof trust || trust.dwUnionChoice != WTD_CHOICE_FILE ||
            !trust.pFile || !ReadProcessMemory(GetCurrentProcess(), trust.pFile, &file, sizeof file, &read) ||
            read != sizeof file || file.cbStruct < sizeof file) return false;
        // A state created by a forwarded call must still be closed by Windows, even for a match.
        if (trust.dwStateAction == WTD_STATEACTION_CLOSE && trust.hWVTStateData) return false;
        return Matches(file.pcwszFilePath);
    }

    LONG WINAPI HookedTrust(HWND window, GUID* action, LPVOID data)
    {
        const DWORD error = GetLastError();
        if (g_policy == signature::TrustPolicy::AcceptAll ||
            (!g_inside && g_policy == signature::TrustPolicy::AcceptMatched && MatchesTrust(data)))
        {
            if (g_log) Log("file-signature: accepted WinVerifyTrust (%s)",
                g_policy == signature::TrustPolicy::AcceptAll ? "accept-all" : "accept-matched");
            SetLastError(error);
            return ERROR_SUCCESS;
        }
        SetLastError(error);
        return g_trust(window, action, data);
    }

    BOOL WINAPI HookedQuery(DWORD kind, const void* object, DWORD content, DWORD format, DWORD flags,
        DWORD* encoding, DWORD* contentType, DWORD* formatType, HCERTSTORE* store, HCRYPTMSG* message, const void** context)
    {
        const DWORD error = GetLastError();
        if (g_inside) return g_query(kind, object, content, format, flags, encoding, contentType, formatType, store, message, context);
        const void* selected = object;
        std::wstring redirected;
        try
        {
            // Blob queries can point at a structure or even an invalid address. Check the selector
            // before reading a path. Per-call storage survives the synchronous original call and
            // cannot be overwritten by another thread's query.
            if (kind == CERT_QUERY_OBJECT_FILE && object)
            {
                wchar_t buffer[32768];
                if (ReadPath(static_cast<const wchar_t*>(object), buffer) && signature::Matches<wchar_t>(buffer, g_match))
                {
                    std::wstring_view path(buffer);
                    redirected.assign(path.substr(0, signature::FilenameStart(path)));
                    redirected += g_replace;
                    selected = redirected.c_str();
                    if (g_log) Log("file-signature: redirected certificate query for configured filename");
                }
            }
        }
        catch (...) { selected = object; }
        SetLastError(error);
        // Prevent recursive certificate queries from being redirected again. The explicitly
        // process-wide accept-all policy still applies to nested trust calls, as its name promises.
        struct Guard { Guard() { g_inside = true; } ~Guard() { g_inside = false; } } guard;
        return g_query(kind, selected, content, format, flags, encoding, contentType, formatType, store, message, context);
    }
}
#endif

STOKER_HOOK_PLUGIN_ENTRY int STOKER_HOOK_CALL stoker_hook_plugin_init(const stoker_hook_host_v1* host)
{
    if (!stoker::plugin::Accept(host)) return STOKER_HOOK_UNSUPPORTED;
#ifdef _WIN32
    try
    {
        using namespace stoker::plugin;
        bool here = false;
        if (!ForThisProcess(here)) return STOKER_HOOK_INVALID_ARGUMENT;
        if (!here) return STOKER_HOOK_OK;
        char match[1024] = "", replace[1024] = "", policy[32] = "forward", logging[16] = "quiet";
        if (Option("match", match, sizeof match) != OptionRead::Present ||
            Option("replace", replace, sizeof replace) != OptionRead::Present ||
            Option("trustPolicy", policy, sizeof policy) == OptionRead::Invalid ||
            Option("logging", logging, sizeof logging) == OptionRead::Invalid ||
            !PlainFileName(match) || !PlainFileName(replace) ||
            !Wide(match, g_match, MAX_PATH) || !Wide(replace, g_replace, MAX_PATH) ||
            !signature::ParsePolicy(policy, g_policy) || (std::strcmp(logging, "quiet") && std::strcmp(logging, "changes")))
            return STOKER_HOOK_INVALID_ARGUMENT;
        g_log = !std::strcmp(logging, "changes");
        Log("file-signature: registering certificate filename redirect; trust policy %s", policy);
        int result = host->hook_export(host->user, "crypt32.dll", "CryptQueryObject", reinterpret_cast<void*>(&HookedQuery), reinterpret_cast<void**>(&g_query));
        if (result != STOKER_HOOK_OK || g_policy == signature::TrustPolicy::Forward) return result;
        return host->hook_export(host->user, "wintrust.dll", "WinVerifyTrust", reinterpret_cast<void*>(&HookedTrust), reinterpret_cast<void**>(&g_trust));
    }
    catch (...) { return STOKER_HOOK_ERROR; }
#else
    host->log(host->user, "file-signature requires Windows certificate APIs (including Proton); no POSIX certificate backend yet");
    return STOKER_HOOK_UNSUPPORTED;
#endif
}
