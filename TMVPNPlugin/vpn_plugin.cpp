// TMVPNPlugin for TrafficMonitor
// Items: node latency (GLOBAL selector, refreshed every 10 s via mihomo named pipe),
// VPN adapter speed, VPN connection status.
#include "PluginInterface.h"
#include "options_resource.h"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <shlobj.h>
#include <exdisp.h>
#include <shldisp.h>
#include <wrl/client.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <cwchar>
#include <cstdlib>
#include <cwctype>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iterator>
#include <optional>
#include <functional>
#include <unordered_set>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "uuid.lib")

namespace
{
    std::wstring ModulePath(HMODULE module)
    {
        std::wstring path(32768, L'\0');
        const DWORD size = GetModuleFileNameW(module, &path[0], static_cast<DWORD>(path.size()));
        if (size == 0 || size >= path.size())
            return {};
        path.resize(size);
        return path;
    }

    std::wstring RecoveryStateDirectory()
    {
        PWSTR path = nullptr;
        const HRESULT result = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
        std::wstring directory;
        if (SUCCEEDED(result) && path)
            directory = std::wstring(path) + L"\\ClashSubscriptionGuard";
        CoTaskMemFree(path);
        return directory;
    }

    enum class MonitorState { enabled, paused, unavailable };

    MonitorState ReadMonitorState(const std::wstring& directory)
    {
        if (directory.empty())
            return MonitorState::unavailable;
        const DWORD attributes = GetFileAttributesW((directory + L"\\monitor.pause").c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
            return (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                ? MonitorState::unavailable : MonitorState::paused;
        const DWORD error = GetLastError();
        return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            ? MonitorState::enabled : MonitorState::unavailable;
    }

    void ToggleMonitorState(const std::wstring& directory)
    {
        const auto state = ReadMonitorState(directory);
        const std::wstring marker = directory + L"\\monitor.pause";
        if (state == MonitorState::paused)
        {
            DeleteFileW(marker.c_str());
        }
        else if (state == MonitorState::enabled &&
                 (CreateDirectoryW(directory.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS))
        {
            const HANDLE file = CreateFileW(marker.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
                CloseHandle(file);
        }
    }

    bool IsFile(const std::wstring& path)
    {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool IsNormalUserShell(HWND hwnd)
    {
        DWORD pid = 0;
        if (!hwnd || !GetWindowThreadProcessId(hwnd, &pid) || !pid)
            return false;
        const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return false;
        HANDLE shell_token = nullptr;
        HANDLE host_token = nullptr;
        const BOOL have_shell_token = OpenProcessToken(process, TOKEN_QUERY, &shell_token);
        CloseHandle(process);
        if (!have_shell_token)
            return false;

        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        constexpr DWORD user_size = sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE;
        alignas(TOKEN_USER) BYTE shell_user[user_size]{};
        alignas(TOKEN_USER) BYTE host_user[user_size]{};
        const bool allowed = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &host_token)
            && GetTokenInformation(shell_token, TokenElevation, &elevation, sizeof(elevation), &size)
            && !elevation.TokenIsElevated
            && GetTokenInformation(shell_token, TokenUser, shell_user, user_size, &size)
            && GetTokenInformation(host_token, TokenUser, host_user, user_size, &size)
            && EqualSid(reinterpret_cast<TOKEN_USER*>(shell_user)->User.Sid,
                        reinterpret_cast<TOKEN_USER*>(host_user)->User.Sid);
        if (host_token)
            CloseHandle(host_token);
        CloseHandle(shell_token);
        return allowed;
    }

    // Execute in the desktop shell's own process, so an elevated host cannot elevate the helper.
    HRESULT LaunchInDesktopShell(PCWSTR executable, PCWSTR arguments, PCWSTR directory)
    {
        using Microsoft::WRL::ComPtr;
        ComPtr<IShellWindows> windows;
        HRESULT result = CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER,
                                          IID_PPV_ARGS(&windows));
        if (FAILED(result))
            return result;
        VARIANT desktop{}, empty{};
        desktop.vt = VT_I4;
        desktop.lVal = CSIDL_DESKTOP;
        long window = 0;
        ComPtr<IDispatch> desktop_window;
        result = windows->FindWindowSW(&desktop, &empty, SWC_DESKTOP, &window,
                                       SWFO_NEEDDISPATCH, &desktop_window);
        if (result != S_OK || !desktop_window)
            return FAILED(result) ? result : E_FAIL;
        if (!IsNormalUserShell(static_cast<HWND>(LongToHandle(window))))
            return E_ACCESSDENIED;

        ComPtr<IServiceProvider> services;
        ComPtr<IShellBrowser> browser;
        ComPtr<IShellView> view;
        ComPtr<IDispatch> background;
        ComPtr<IShellFolderViewDual> folder_view;
        ComPtr<IDispatch> application;
        ComPtr<IShellDispatch2> shell;
        if (FAILED(result = desktop_window.As(&services))
            || FAILED(result = services->QueryService(SID_STopLevelBrowser, IID_PPV_ARGS(&browser)))
            || FAILED(result = browser->QueryActiveShellView(&view))
            || FAILED(result = view->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&background)))
            || FAILED(result = background.As(&folder_view))
            || FAILED(result = folder_view->get_Application(&application))
            || FAILED(result = application.As(&shell)))
            return result;

        BSTR file = SysAllocString(executable);
        VARIANT args{}, work_dir{}, verb{}, show{};
        args.vt = work_dir.vt = verb.vt = VT_BSTR;
        args.bstrVal = SysAllocString(arguments);
        work_dir.bstrVal = SysAllocString(directory);
        verb.bstrVal = SysAllocString(L"open");
        show.vt = VT_I4;
        show.lVal = SW_HIDE;
        result = E_OUTOFMEMORY;
        if (file && args.bstrVal && work_dir.bstrVal && verb.bstrVal)
            result = shell->ShellExecute(file, args, work_dir, verb, show);
        SysFreeString(file);
        VariantClear(&args);
        VariantClear(&work_dir);
        VariantClear(&verb);
        return result;
    }

    std::wstring RecoveryOwnerName(DWORD pid, ULONGLONG created)
    {
        return L"Local\\TMVPNPlugin.Guard." + std::to_wstring(pid) + L"." + std::to_wstring(created);
    }

    bool HasRecoveryOwner(const std::wstring& name)
    {
        const HANDLE owner = OpenMutexW(SYNCHRONIZE, FALSE, name.c_str());
        if (!owner)
            return GetLastError() != ERROR_FILE_NOT_FOUND;
        CloseHandle(owner);
        return true;
    }

    void ReportRecoveryLaunchError(HRESULT hr)
    {
        wchar_t message[96]{};
        swprintf_s(message, L"TMVPNPlugin: recovery helper launch failed (0x%08lX)\n",
                   static_cast<unsigned long>(hr));
        OutputDebugStringW(message);
    }

    // ===================== basic helpers =====================
    std::wstring Utf8ToWide(const std::string& s)
    {
        if (s.empty()) return std::wstring();
        int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), (int)s.size(), nullptr, 0);
        if (n <= 0) return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), (int)s.size(), &w[0], n);
        return w;
    }

    std::string WideToUtf8(const std::wstring& w)
    {
        if (w.empty()) return std::string();
        int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return std::string();
        std::string s((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
        return s;
    }

    std::wstring Trim(std::wstring s)
    {
        size_t b = 0, e = s.size();
        while (b < e && (iswspace(s[b]) || s[b] == 0x3000)) ++b;
        while (e > b && (iswspace(s[e - 1]) || s[e - 1] == 0x3000)) --e;
        return s.substr(b, e - b);
    }

    // "PRO | 日本家宽S VL03 | 2倍" -> "日本家宽S VL03"
    std::wstring ShortNodeName(const std::wstring& name)
    {
        std::vector<std::wstring> parts;
        std::wstring cur;
        for (wchar_t c : name)
        {
            if (c == L'|')
            {
                parts.push_back(Trim(cur));
                cur.clear();
            }
            else
            {
                cur += c;
            }
        }
        parts.push_back(Trim(cur));
        std::wstring result;
        if (parts.size() >= 3)
        {
            for (size_t i = 1; i + 1 < parts.size(); ++i)
            {
                if (!result.empty()) result += L'|';
                result += parts[i];
            }
            result = Trim(result);
        }
        if (result.empty()) result = Trim(name);
        return result;
    }

    std::wstring FormatSpeed(unsigned long long bytes_per_sec)
    {
        wchar_t buf[64]{};
        const double v = static_cast<double>(bytes_per_sec);
        if (v < 1024.0)
        {
            swprintf_s(buf, L"%.0f B/s", v);
        }
        else if (v < 1024.0 * 1024.0)
        {
            const double k = v / 1024.0;
            swprintf_s(buf, k < 100.0 ? L"%.1f KB/s" : L"%.0f KB/s", k);
        }
        else if (v < 1024.0 * 1024.0 * 1024.0)
        {
            const double m = v / (1024.0 * 1024.0);
            swprintf_s(buf, m < 100.0 ? L"%.1f MB/s" : L"%.0f MB/s", m);
        }
        else
        {
            const double g = v / (1024.0 * 1024.0 * 1024.0);
            swprintf_s(buf, L"%.2f GB/s", g);
        }
        return buf;
    }

    // ===================== tiny JSON parser =====================
    struct JsonValue
    {
        enum class Type { Null, Bool, Number, String, Array, Object };
        Type type{ Type::Null };
        bool boolean{};
        double number{};
        std::string str;
        std::vector<JsonValue> array;
        std::map<std::string, JsonValue> object;

        const JsonValue* Find(const std::string& key) const
        {
            if (type != Type::Object) return nullptr;
            auto it = object.find(key);
            return it == object.end() ? nullptr : &it->second;
        }
    };

    class JsonParser
    {
    public:
        explicit JsonParser(const std::string& text) : m_text(text) {}

        bool Parse(JsonValue& out)
        {
            SkipWs();
            if (!ParseValue(out, 0)) return false;
            SkipWs();
            return m_pos == m_text.size();
        }

    private:
        bool ParseValue(JsonValue& v, unsigned depth)
        {
            if (depth > 32 || m_pos >= m_text.size()) return false;
            const char c = m_text[m_pos];
            if (c == '{') return ParseObject(v, depth);
            if (c == '[') return ParseArray(v, depth);
            if (c == '"')
            {
                v.type = JsonValue::Type::String;
                return ParseString(v.str);
            }
            if (c == 't' && Match("true")) { v.type = JsonValue::Type::Bool; v.boolean = true; return true; }
            if (c == 'f' && Match("false")) { v.type = JsonValue::Type::Bool; v.boolean = false; return true; }
            if (c == 'n' && Match("null")) { v.type = JsonValue::Type::Null; return true; }
            return ParseNumber(v);
        }

        bool ParseObject(JsonValue& v, unsigned depth)
        {
            v.type = JsonValue::Type::Object;
            ++m_pos; // {
            SkipWs();
            if (m_pos < m_text.size() && m_text[m_pos] == '}') { ++m_pos; return true; }
            for (;;)
            {
                SkipWs();
                std::string key;
                if (!ParseString(key)) return false;
                SkipWs();
                if (m_pos >= m_text.size() || m_text[m_pos] != ':') return false;
                ++m_pos;
                SkipWs();
                JsonValue child;
                if (!ParseValue(child, depth + 1)) return false;
                if (!v.object.emplace(std::move(key), std::move(child)).second) return false;
                SkipWs();
                if (m_pos >= m_text.size()) return false;
                if (m_text[m_pos] == ',') { ++m_pos; continue; }
                if (m_text[m_pos] == '}') { ++m_pos; return true; }
                return false;
            }
        }

        bool ParseArray(JsonValue& v, unsigned depth)
        {
            v.type = JsonValue::Type::Array;
            ++m_pos; // [
            SkipWs();
            if (m_pos < m_text.size() && m_text[m_pos] == ']') { ++m_pos; return true; }
            for (;;)
            {
                SkipWs();
                JsonValue child;
                if (!ParseValue(child, depth + 1)) return false;
                v.array.push_back(std::move(child));
                SkipWs();
                if (m_pos >= m_text.size()) return false;
                if (m_text[m_pos] == ',') { ++m_pos; continue; }
                if (m_text[m_pos] == ']') { ++m_pos; return true; }
                return false;
            }
        }

        bool ParseString(std::string& out)
        {
            if (m_pos >= m_text.size() || m_text[m_pos] != '"') return false;
            ++m_pos;
            out.clear();
            while (m_pos < m_text.size())
            {
                char c = m_text[m_pos++];
                if (c == '"') return true;
                if (static_cast<unsigned char>(c) < 0x20) return false;
                if (c != '\\') { out += c; continue; }
                if (m_pos >= m_text.size()) return false;
                char e = m_text[m_pos++];
                switch (e)
                {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u':
                {
                    if (m_pos + 4 > m_text.size()) return false;
                    unsigned code = 0;
                    for (int i = 0; i < 4; ++i)
                    {
                        char h = m_text[m_pos++];
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= (unsigned)(h - 'A' + 10);
                        else return false;
                    }
                    wchar_t wc = (wchar_t)code;
                    if (code >= 0xD800 && code <= 0xDBFF && m_pos + 6 <= m_text.size()
                        && m_text[m_pos] == '\\' && m_text[m_pos + 1] == 'u')
                    {
                        m_pos += 2;
                        unsigned low = 0;
                        for (int i = 0; i < 4; ++i)
                        {
                            char h = m_text[m_pos++];
                            low <<= 4;
                            if (h >= '0' && h <= '9') low |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') low |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') low |= (unsigned)(h - 'A' + 10);
                            else return false;
                        }
                        if (low < 0xDC00 || low > 0xDFFF) return false;
                        wchar_t pair[2]{ wc, static_cast<wchar_t>(low) };
                        out += WideToUtf8(std::wstring(pair, 2));
                    }
                    else
                    {
                        if (code >= 0xD800 && code <= 0xDFFF) return false;
                        out += WideToUtf8(std::wstring(1, wc));
                    }
                    break;
                }
                default: return false;
                }
            }
            return false;
        }

        bool ParseNumber(JsonValue& v)
        {
            size_t start = m_pos;
            while (m_pos < m_text.size())
            {
                char c = m_text[m_pos];
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') ++m_pos;
                else break;
            }
            v.str = m_text.substr(start, m_pos - start);
            if (v.str.empty()) return false;
            char* end = nullptr;
            v.number = std::strtod(v.str.c_str(), &end);
            if (end != v.str.c_str() + v.str.size()) return false;
            v.type = JsonValue::Type::Number;
            return true;
        }

        bool Match(const char* literal)
        {
            size_t len = std::strlen(literal);
            if (m_text.compare(m_pos, len, literal) != 0) return false;
            m_pos += len;
            return true;
        }

        void SkipWs()
        {
            while (m_pos < m_text.size())
            {
                char c = m_text[m_pos];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++m_pos;
                else break;
            }
        }

        const std::string& m_text;
        size_t m_pos{};
    };

    constexpr int refresh_options[]{ 5, 10, 15, 30, 60 };
    constexpr wchar_t default_target[] = L"PRO | 日本家宽S VL03 | 2倍";
    constexpr wchar_t update_target[] = L"PRO | 订阅专用节点AN | 0倍";

    struct VpnSettings
    {
        std::wstring target{ default_target };
        int refresh_seconds{ 10 };
        bool valid{ false };
        std::optional<std::string> profile_uid;
    };

    class SettingsWriteIdentity
    {
    public:
        SettingsWriteIdentity()
        {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
                return;
            TOKEN_ELEVATION elevation{};
            DWORD size = 0;
            const BOOL token_ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
            CloseHandle(token);
            if (!token_ok)
                return;
            if (!elevation.TokenIsElevated)
            {
                m_allowed = true;
                return;
            }
            const HWND desktop = GetShellWindow();
            DWORD pid = 0;
            if (!IsNormalUserShell(desktop) || !GetWindowThreadProcessId(desktop, &pid))
                return;
            const HANDLE shell = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!shell)
                return;
            const BOOL opened = OpenProcessToken(shell, TOKEN_QUERY | TOKEN_DUPLICATE, &token);
            CloseHandle(shell);
            if (!opened)
                return;
            HANDLE identity = nullptr;
            if (DuplicateToken(token, SecurityImpersonation, &identity))
            {
                m_impersonating = ImpersonateLoggedOnUser(identity) != FALSE;
                CloseHandle(identity);
            }
            CloseHandle(token);
            m_allowed = m_impersonating;
        }

        ~SettingsWriteIdentity()
        {
            if (m_impersonating && !RevertToSelf())
                std::terminate();
        }

        bool Allowed() const { return m_allowed; }

    private:
        bool m_allowed{};
        bool m_impersonating{};
    };

    bool IsValidTarget(const std::wstring& name, const std::string& utf8)
    {
        if (name.empty() || utf8.empty() || utf8.size() > 512)
            return false;
        const auto space = [](wchar_t c) {
            return c == 0x20 || c == 0x85 || c == 0xa0 || c == 0x1680
                || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029
                || c == 0x202f || c == 0x205f || c == 0x3000;
        };
        if (space(name.front()) || space(name.back()) || std::any_of(name.begin(), name.end(),
              [](wchar_t c) { return c < 0x20 || c == 0x7f; }))
            return false;
        const PCWSTR reserved[]{ update_target, L"DIRECT", L"REJECT", L"REJECT-DROP",
                                 L"PASS", L"COMPATIBLE", L"GLOBAL" };
        return std::none_of(std::begin(reserved), std::end(reserved), [&](PCWSTR value) {
            return CompareStringOrdinal(name.c_str(), -1, value, -1, TRUE) == CSTR_EQUAL;
        });
    }

    bool IsProfileUid(const std::string& uid)
    {
        return !uid.empty() && uid.size() <= 128 && std::all_of(uid.begin(), uid.end(), [](char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        });
    }

    VpnSettings ParseSettings(const std::string& json)
    {
        JsonValue root;
        if (!JsonParser(json).Parse(root))
            return {};
        const auto* target = root.Find("target_node");
        const auto* refresh = root.Find("refresh_seconds");
        const auto* profile = root.Find("profile_uid");
        if (!target || target->type != JsonValue::Type::String ||
            !refresh || refresh->type != JsonValue::Type::Number || root.object.size() != (profile ? 3 : 2) ||
            (profile && (profile->type != JsonValue::Type::String || (!profile->str.empty() && !IsProfileUid(profile->str)))))
            return {};
        const auto name = Utf8ToWide(target->str);
        if (IsValidTarget(name, target->str))
            for (int seconds : refresh_options)
                if (refresh->str == std::to_string(seconds))
                    return { name, seconds, true, profile ? std::optional<std::string>(profile->str) : std::nullopt };
        return {};
    }

    std::string ReadLocalFile(const std::wstring& path, DWORD capacity, bool allow_prefix = false)
    {
        if (path.empty())
            return {};
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return {};
        BY_HANDLE_FILE_INFORMATION info{};
        std::string data(capacity, '\0');
        DWORD size = 0;
        const bool ok = GetFileInformationByHandle(file, &info)
            && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            && ReadFile(file, &data[0], static_cast<DWORD>(data.size()), &size, nullptr)
            && (allow_prefix || size < data.size());
        CloseHandle(file);
        if (!ok)
            return {};
        data.resize(size);
        return data;
    }

    VpnSettings LoadSettings(const std::wstring& directory)
    {
        if (directory.empty())
            return {};
        return ParseSettings(ReadLocalFile(directory + L"\\plugin-settings.json", 4097));
    }

    bool SaveSettings(const std::wstring& directory, const VpnSettings& settings)
    {
        const auto target = WideToUtf8(settings.target);
        if (directory.empty() || !IsValidTarget(settings.target, target) ||
            (settings.profile_uid && !settings.profile_uid->empty() && !IsProfileUid(*settings.profile_uid)) ||
            std::find(std::begin(refresh_options), std::end(refresh_options), settings.refresh_seconds) ==
                std::end(refresh_options))
            return false;
        SettingsWriteIdentity identity;
        if (!identity.Allowed() || (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS))
            return false;
        const DWORD attributes = GetFileAttributesW(directory.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)
            || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return false;
        std::string json = "{\"target_node\":\"";
        for (char c : target)
        {
            if (c == '\\' || c == '"') json += '\\';
            json += c;
        }
        json += "\",\"refresh_seconds\":" + std::to_string(settings.refresh_seconds);
        if (settings.profile_uid)
            json += ",\"profile_uid\":\"" + *settings.profile_uid + '"';
        json += "}\n";

        GUID unique{};
        wchar_t suffix[39]{};
        if (FAILED(CoCreateGuid(&unique)) || !StringFromGUID2(unique, suffix, static_cast<int>(std::size(suffix))))
            return false;
        const auto temporary_path = directory + L"\\plugin-settings-" + suffix + L".tmp";
        const HANDLE file = CreateFileW(temporary_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        DWORD written = 0;
        bool saved = WriteFile(file, json.data(), static_cast<DWORD>(json.size()), &written, nullptr)
            && written == json.size() && FlushFileBuffers(file);
        CloseHandle(file);
        if (saved)
            saved = MoveFileExW(temporary_path.c_str(), (directory + L"\\plugin-settings.json").c_str(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
        if (!saved)
            DeleteFileW(temporary_path.c_str());
        return saved;
    }

    std::vector<std::wstring> ListRecoveryTargets(const JsonValue& proxies, const JsonValue& global)
    {
        const auto* all = global.Find("all");
        const auto* selector = global.Find("type");
        std::vector<std::wstring> nodes;
        if (!selector || selector->type != JsonValue::Type::String || selector->str != "Selector"
            || !all || all->type != JsonValue::Type::Array)
            return nodes;
        for (const auto& item : all->array)
        {
            if (item.type != JsonValue::Type::String)
                continue;
            const auto* node = proxies.Find(item.str);
            const auto* type = node ? node->Find("type") : nullptr;
            if (!type || type->type != JsonValue::Type::String)
                continue;
            const PCSTR protocols[]{ "shadowsocks", "shadowsocksr", "snell", "socks5", "http",
                "vmess", "vless", "trojan", "hysteria", "hysteria2", "wireguard", "tuic", "ssh",
                "mieru", "anytls", "sudoku", "masque", "trusttunnel", "shadowquic", "openvpn",
                "tailscale", "zerotier", "easytier", "gostrelay" };
            if (std::none_of(std::begin(protocols), std::end(protocols),
                             [&](PCSTR protocol) { return _stricmp(type->str.c_str(), protocol) == 0; }))
                continue;
            auto name = Utf8ToWide(item.str);
            if (IsValidTarget(name, item.str) && std::find(nodes.begin(), nodes.end(), name) == nodes.end())
                nodes.emplace_back(std::move(name));
        }
        return nodes;
    }

    struct Subscription
    {
        std::string uid;
        std::wstring name;
        bool ambiguous{};
    };

    struct ProfileCatalog
    {
        std::string current;
        std::string selected;
        std::vector<Subscription> items;
        bool available{};
    };

    ProfileCatalog ParseProfileCatalog(const std::string& json)
    {
        JsonValue root;
        if (!JsonParser(json).Parse(root))
            return {};
        using Type = JsonValue::Type;
        const auto* available = root.Find("available");
        const auto* current = root.Find("current");
        const auto* selected = root.Find("selected");
        const auto* items = root.Find("items");
        if (!available || available->type != Type::Bool || !current || current->type != Type::String
            || (!current->str.empty() && !IsProfileUid(current->str)) || !selected || selected->type != Type::String
            || (!selected->str.empty() && !IsProfileUid(selected->str)) || !items || items->type != Type::Array)
            return {};
        ProfileCatalog result{ current->str, selected->str, {}, available->boolean };
        if (!result.available)
            return result;
        std::unordered_set<std::string> uids;
        for (const auto& row : items->array)
        {
            const auto* uid = row.Find("uid");
            const auto* name = row.Find("name");
            const auto* ambiguous = row.Find("ambiguous");
            if (!uid || uid->type != Type::String || !IsProfileUid(uid->str) || !name || name->type != Type::String
                || name->str.size() > 512 || !ambiguous || ambiguous->type != Type::Bool)
                return {};
            auto title = Utf8ToWide(name->str);
            if (title.empty() || std::any_of(title.begin(), title.end(), [](wchar_t c) { return c < 32 || c == 127; })
                || !uids.insert(uid->str).second)
                return {};
            result.items.push_back({ uid->str, std::move(title), ambiguous->boolean });
        }
        return result;
    }

    ProfileCatalog LoadProfileCatalog(const std::wstring& directory)
    {
        if (directory.empty())
            return {};
        return ParseProfileCatalog(ReadLocalFile(directory + L"\\profile-catalog.json", 2 * 1024 * 1024 + 1));
    }

    std::string CurrentProfileUidFromHeader(const std::string& data)
    {
        // shortcut: verify the single root current marker from Verge's generated header; unsupported formats disable node picking.
        for (size_t start = data.compare(0, 3, "\xef\xbb\xbf") == 0 ? 3 : 0; start < data.size();)
        {
            const size_t end = data.find('\n', start);
            if (end == std::string::npos)
                break;
            if (data.compare(start, 6, "items:") == 0)
                break;
            if (data.compare(start, 8, "current:") == 0)
            {
                auto line = data.substr(start + 8, end - start - 8);
                const auto first = line.find_first_not_of(" \t\r");
                if (first == std::string::npos)
                    return {};
                line = line.substr(first, line.find_last_not_of(" \t\r") - first + 1);
                if (line.size() > 1 && (line.front() == '\'' || line.front() == '"') && line.back() == line.front())
                    line = line.substr(1, line.size() - 2);
                return IsProfileUid(line) ? line : std::string{};
            }
            start = end + 1;
        }
        return {};
    }

    std::string CurrentProfileUid()
    {
        PWSTR path = nullptr;
        const HRESULT result = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path);
        std::string uid;
        if (SUCCEEDED(result) && path)
            uid = CurrentProfileUidFromHeader(ReadLocalFile(std::wstring(path)
                + L"\\io.github.clash-verge-rev.clash-verge-rev\\profiles.yaml", 4096, true));
        CoTaskMemFree(path);
        return uid;
    }

    struct OptionsDialog
    {
        std::wstring directory;
        VpnSettings settings;
        ProfileCatalog catalog;
        std::string targets_profile;
        std::vector<std::wstring> targets;
        std::vector<Subscription> profiles;
        std::vector<std::wstring> visible_targets;
        std::function<bool(const std::string&, const std::wstring&)> has_current_target;
    };

    bool CanChooseProfile(const ProfileCatalog& catalog, const std::string& uid)
    {
        return catalog.available && !uid.empty() && std::any_of(catalog.items.begin(), catalog.items.end(),
            [&](const Subscription& item) { return item.uid == uid && !item.ambiguous; });
    }

    bool CanChooseTarget(const ProfileCatalog& catalog, const std::string& uid,
                         const std::string& targets_profile, const std::string& current)
    {
        return uid == catalog.current && uid == targets_profile && uid == current && CanChooseProfile(catalog, uid);
    }

    void RefreshTargetOptions(HWND hwnd, OptionsDialog& data)
    {
        const auto index = SendDlgItemMessageW(hwnd, IDC_VPN_PROFILE, CB_GETCURSEL, 0, 0);
        if (index < 0 || static_cast<size_t>(index) >= data.profiles.size())
            return;
        const auto& profile = data.profiles[index];
        const auto current = CurrentProfileUid();
        const bool active = !profile.uid.empty() && profile.uid == data.catalog.current && profile.uid == current;
        const bool has_nodes = !data.targets.empty() && CanChooseTarget(data.catalog, profile.uid, data.targets_profile, current);
        data.visible_targets = has_nodes ? data.targets : std::vector<std::wstring>{};
        const bool has_saved = std::find(data.visible_targets.begin(), data.visible_targets.end(), data.settings.target)
            != data.visible_targets.end();
        if (!has_saved)
            data.visible_targets.insert(data.visible_targets.begin(), data.settings.target);
        SendDlgItemMessageW(hwnd, IDC_VPN_TARGET, CB_RESETCONTENT, 0, 0);
        for (const auto& node : data.visible_targets)
        {
            const LRESULT row = SendDlgItemMessageW(hwnd, IDC_VPN_TARGET, CB_ADDSTRING, 0,
                                                   reinterpret_cast<LPARAM>(node.c_str()));
            if (node == data.settings.target && row >= 0)
                SendDlgItemMessageW(hwnd, IDC_VPN_TARGET, CB_SETCURSEL, row, 0);
        }
        EnableWindow(GetDlgItem(hwnd, IDC_VPN_TARGET), has_nodes);
        const PCWSTR status = !data.catalog.available ? L"暂未取得订阅列表。请启动 Clash Verge，再重新打开本窗口。"
            : profile.uid.empty() ? L"尚未选择订阅，自动恢复不会启动。"
            : profile.ambiguous ? L"存在同名订阅。请在 Clash Verge 中修改名称。"
            : !active ? L"请先在 Clash Verge 中启用所选订阅。"
            : !has_nodes ? L"暂未取得此订阅的节点列表，保留已保存的目标。"
            : !has_saved ? L"已保存的目标暂不在当前节点列表中。" : L"";
        SetDlgItemTextW(hwnd, IDC_VPN_STATUS, !data.settings.valid
            && GetFileAttributesW((data.directory + L"\\plugin-settings.json").c_str()) != INVALID_FILE_ATTRIBUTES
            ? L"配置无效，保存可修复。" : status);
    }

    INT_PTR CALLBACK OptionsProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
    {
        if (message == WM_INITDIALOG)
        {
            auto& data = *reinterpret_cast<OptionsDialog*>(lparam);
            SetWindowLongPtrW(hwnd, DWLP_USER, lparam);
            const auto saved = data.settings.profile_uid.value_or(data.catalog.selected);
            data.profiles.push_back({ {}, L"未选择订阅" });
            data.profiles.insert(data.profiles.end(), data.catalog.items.begin(), data.catalog.items.end());
            if (!saved.empty() && std::none_of(data.profiles.begin(), data.profiles.end(),
                [&](const Subscription& profile) { return profile.uid == saved; }))
                data.profiles.push_back({ saved, L"已保存的订阅（暂不可用）" });
            for (const auto& profile : data.profiles)
            {
                auto label = profile.name;
                if (!profile.uid.empty() && profile.uid == data.catalog.current)
                    label += L"（当前）";
                if (profile.ambiguous)
                    label += L"（同名）";
                const LRESULT index = SendDlgItemMessageW(hwnd, IDC_VPN_PROFILE, CB_ADDSTRING, 0,
                                                          reinterpret_cast<LPARAM>(label.c_str()));
                if (index >= 0 && profile.uid == saved)
                    SendDlgItemMessageW(hwnd, IDC_VPN_PROFILE, CB_SETCURSEL, index, 0);
            }
            EnableWindow(GetDlgItem(hwnd, IDC_VPN_PROFILE), data.profiles.size() > 1);
            RefreshTargetOptions(hwnd, data);
            const UINT dpi = GetDpiForWindow(hwnd);
            SendDlgItemMessageW(hwnd, IDC_VPN_PROFILE, CB_SETDROPPEDWIDTH, MulDiv(450, dpi, 96), 0);
            SendDlgItemMessageW(hwnd, IDC_VPN_TARGET, CB_SETDROPPEDWIDTH, MulDiv(450, dpi, 96), 0);
            for (int seconds : refresh_options)
            {
                const auto item = std::to_wstring(seconds) + L" 秒";
                const LRESULT index = SendDlgItemMessageW(hwnd, IDC_VPN_REFRESH, CB_ADDSTRING, 0,
                                                          reinterpret_cast<LPARAM>(item.c_str()));
                if (seconds == data.settings.refresh_seconds && index >= 0)
                    SendDlgItemMessageW(hwnd, IDC_VPN_REFRESH, CB_SETCURSEL, index, 0);
            }
            return TRUE;
        }
        if (message != WM_COMMAND)
            return FALSE;
        if (LOWORD(wparam) == IDCANCEL)
        {
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        auto* data = reinterpret_cast<OptionsDialog*>(GetWindowLongPtrW(hwnd, DWLP_USER));
        if (!data)
            return FALSE;
        if (LOWORD(wparam) == IDC_VPN_PROFILE && HIWORD(wparam) == CBN_SELCHANGE)
        {
            RefreshTargetOptions(hwnd, *data);
            return TRUE;
        }
        if (LOWORD(wparam) != IDOK)
            return FALSE;
        const auto profile_index = SendDlgItemMessageW(hwnd, IDC_VPN_PROFILE, CB_GETCURSEL, 0, 0);
        const auto target = SendDlgItemMessageW(hwnd, IDC_VPN_TARGET, CB_GETCURSEL, 0, 0);
        const auto interval = SendDlgItemMessageW(hwnd, IDC_VPN_REFRESH, CB_GETCURSEL, 0, 0);
        if (profile_index < 0 || static_cast<size_t>(profile_index) >= data->profiles.size()
            || target < 0 || static_cast<size_t>(target) >= data->visible_targets.size()
            || interval < 0 || static_cast<size_t>(interval) >= std::size(refresh_options))
        {
            SetDlgItemTextW(hwnd, IDC_VPN_STATUS, L"请选择目标节点和刷新间隔。");
            return TRUE;
        }
        const auto& profile = data->profiles[profile_index];
        const auto saved = data->settings.profile_uid.value_or(data->catalog.selected);
        const bool profile_changed = !profile.uid.empty() && profile.uid != saved;
        const bool target_changed = data->visible_targets[target] != data->settings.target;
        if (profile_changed || target_changed)
        {
            const auto catalog = LoadProfileCatalog(data->directory);
            if (profile_changed && !CanChooseProfile(catalog, profile.uid))
            {
                SetDlgItemTextW(hwnd, IDC_VPN_STATUS, L"所选订阅已不可用或存在同名订阅。请重新打开插件选项。");
                return TRUE;
            }
            if (target_changed && (!CanChooseTarget(catalog, profile.uid, data->targets_profile, CurrentProfileUid())
                || !data->has_current_target(profile.uid, data->visible_targets[target])))
            {
                SetDlgItemTextW(hwnd, IDC_VPN_STATUS, L"当前订阅或节点列表已变化。请重新打开插件选项。");
                return TRUE;
            }
        }
        VpnSettings settings{ data->visible_targets[target], refresh_options[interval], true, data->settings.profile_uid };
        if (profile.uid != saved || !profile.uid.empty())
            settings.profile_uid = profile.uid;
        if (data->settings.valid && settings.target == data->settings.target &&
            settings.refresh_seconds == data->settings.refresh_seconds && settings.profile_uid == data->settings.profile_uid)
        {
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
        }
        if (!SaveSettings(data->directory, settings))
        {
            SetDlgItemTextW(hwnd, IDC_VPN_STATUS, L"保存失败，原设置仍然有效。");
            return TRUE;
        }
        data->settings = settings;
        EndDialog(hwnd, IDOK);
        return TRUE;
    }

    // ===================== mihomo named-pipe HTTP =====================
    bool FindMihomoPipe(std::wstring& pipe_name)
    {
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\verge-mihomo*", &fd);
        if (h == INVALID_HANDLE_VALUE) return false;
        pipe_name = fd.cFileName;
        FindClose(h);
        return !pipe_name.empty();
    }

    bool HttpGetViaPipe(const std::wstring& pipe_name, const std::string& path, std::string& body)
    {
        std::wstring full = L"\\\\.\\pipe\\" + pipe_name;
        HANDLE h = CreateFileW(full.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_PIPE_BUSY)
            {
                if (!WaitNamedPipeW(full.c_str(), 2000))
                    return false;
                h = CreateFileW(full.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            }
            if (h == INVALID_HANDLE_VALUE)
                return false;
        }
        DWORD mode = PIPE_READMODE_BYTE;
        const BOOL setmode = SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

        std::string request = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        DWORD written = 0;
        const BOOL wok = WriteFile(h, request.data(), (DWORD)request.size(), &written, nullptr);
        if (!wok || written != request.size())
        {
            CloseHandle(h);
            return false;
        }

        std::string raw;
        char buf[8192];
        DWORD deadline = GetTickCount() + 6000;
        for (;;)
        {
            DWORD avail = 0;
            if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr))
            {
                break;
            }
            if (avail > 0)
            {
                DWORD got = 0;
                if (!ReadFile(h, buf, sizeof(buf), &got, nullptr) || got == 0)
                    break;
                raw.append(buf, got);
            }
            else
            {
                if (GetTickCount() > deadline)
                    break;
                Sleep(5);
            }
        }
        CloseHandle(h);

        const size_t header_end = raw.find("\r\n\r\n");
        if (header_end == std::string::npos)
            return false;
        const std::string head = raw.substr(0, header_end);
        if (head.rfind("HTTP/1.1 200", 0) != 0 && head.rfind("HTTP/1.0 200", 0) != 0)
            return false;
        std::string payload = raw.substr(header_end + 4);

        std::string lower = head;
        for (auto& ch : lower) ch = (char)tolower((unsigned char)ch);
        if (lower.find("transfer-encoding: chunked") != std::string::npos)
        {
            std::string decoded;
            size_t pos = 0;
            while (pos < payload.size())
            {
                const size_t line_end = payload.find("\r\n", pos);
                if (line_end == std::string::npos) break;
                const std::string size_str = payload.substr(pos, line_end - pos);
                const size_t chunk_size = std::strtoul(size_str.c_str(), nullptr, 16);
                pos = line_end + 2;
                if (chunk_size == 0) break;
                if (pos + chunk_size > payload.size()) return false;
                decoded.append(payload, pos, chunk_size);
                pos += chunk_size + 2;
            }
            body.swap(decoded);
        }
        else
        {
            body.swap(payload);
        }
        return true;
    }

    std::string UrlEncode(const std::string& utf8)
    {
        static const char hex[] = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : utf8)
        {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_' || c == '.' || c == '~')
            {
                out += (char)c;
            }
            else
            {
                out += '%';
                out += hex[c >> 4];
                out += hex[c & 0x0F];
            }
        }
        return out;
    }

    // ===================== plugin items =====================
    class CVpnNodeItem final : public IPluginItem
    {
    public:
        explicit CVpnNodeItem(std::mutex& m, const std::wstring& value) : m_mutex(m), m_value(value) {}
        const wchar_t* GetItemName() const override { return L"节点延迟"; }
        const wchar_t* GetItemId() const override { return L"vpn_node_delay"; }
        const wchar_t* GetItemLableText() const override { return L"节点"; }
        const wchar_t* GetItemValueText() const override
        {
            static thread_local std::wstring buf;
            std::lock_guard<std::mutex> lock(m_mutex);
            buf = m_value;
            return buf.c_str();
        }
        const wchar_t* GetItemValueSampleText() const override { return L"日本家宽S VL03 · 999 ms"; }
    private:
        std::mutex& m_mutex;
        const std::wstring& m_value;
    };

    class CVpnSpeedItem final : public IPluginItem
    {
    public:
        const wchar_t* GetItemName() const override { return L"VPN 网速"; }
        const wchar_t* GetItemId() const override { return L"vpn_net_speed"; }
        const wchar_t* GetItemLableText() const override { return L"VPN"; }
        const wchar_t* GetItemValueText() const override { return m_value.c_str(); }
        const wchar_t* GetItemValueSampleText() const override { return L"\u2191 100.0 MB/s \u2193 100.0 MB/s"; }
        std::wstring m_value{ L"未连接" };
    };

    class CVpnStatusItem final : public IPluginItem
    {
    public:
        const wchar_t* GetItemName() const override { return L"VPN 状态"; }
        const wchar_t* GetItemId() const override { return L"vpn_conn_status"; }
        const wchar_t* GetItemLableText() const override { return L"VPN"; }
        const wchar_t* GetItemValueText() const override { return m_value.c_str(); }
        const wchar_t* GetItemValueSampleText() const override { return L"未连接"; }
        std::wstring m_value{ L"未连接" };
    };

    // ===================== plugin =====================
    class CVpnPlugin final : public ITMPlugin
    {
    public:
        static CVpnPlugin& Instance()
        {
            // TrafficMonitor's plugin ABI keeps instances alive for the process lifetime.
            // A static destructor cannot join the display thread safely inside DLL detach.
            static CVpnPlugin* instance = new CVpnPlugin;
            return *instance;
        }

        IPluginItem* GetItem(int index) override
        {
            switch (index)
            {
            case 0: return &m_node_item;
            case 1: return &m_speed_item;
            case 2: return &m_status_item;
            default: return nullptr;
            }
        }

        void DataRequired() override
        {
            UpdateAdapter();
            if (m_start_recovery.exchange(false))
            {
                try
                {
                    m_recovery_worker = std::thread([this] { RecoveryWorkerLoop(); });
                }
                catch (const std::system_error&)
                {
                    OutputDebugStringW(L"TMVPNPlugin: recovery supervisor failed to start\n");
                }
            }
        }

        int GetCommandCount() override { return 1; }

        const wchar_t* GetCommandName(int index) override
        {
            return index == 0 ? L"自动恢复订阅" : nullptr;
        }

        void OnPluginCommand(int index, void*, void*) override
        {
            if (index == 0)
                ToggleMonitorState(StateDirectory());
        }

        int IsCommandChecked(int index) override
        {
            return index == 0 && ReadMonitorState(StateDirectory()) == MonitorState::enabled;
        }

        OptionReturn ShowOptionsDialog(void* parent) override
        {
            OptionsDialog data;
            data.directory = StateDirectory();
            data.settings = LoadSettings(data.directory);
            data.catalog = LoadProfileCatalog(data.directory);
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                data.targets_profile = m_targets_profile;
                data.targets = m_targets;
            }
            data.has_current_target = [this](const std::string& uid, const std::wstring& target) {
                std::lock_guard<std::mutex> lock(m_mutex);
                return uid == m_targets_profile && std::find(m_targets.begin(), m_targets.end(), target) != m_targets.end();
            };
            HMODULE module = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                    reinterpret_cast<PCWSTR>(&OptionsProc), &module))
                return OR_OPTION_UNCHANGED;
            const auto result = DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_VPN_OPTIONS),
                                                static_cast<HWND>(parent), OptionsProc,
                                                reinterpret_cast<LPARAM>(&data));
            if (result != IDOK)
                return OR_OPTION_UNCHANGED;
            {
                std::lock_guard<std::mutex> lock(m_refresh_mutex);
                m_refresh_seconds = data.settings.refresh_seconds;
            }
            m_refresh_condition.notify_all();
            return OR_OPTION_CHANGED;
        }

        const wchar_t* GetInfo(PluginInfoIndex index) override
        {
            switch (index)
            {
            case TMI_NAME: return L"VPN 监控";
            case TMI_DESCRIPTION: return L"显示 Mihomo 节点延迟、VPN 虚拟网卡上下行速度与连接状态";
            case TMI_AUTHOR: return L"";
            case TMI_COPYRIGHT: return L"";
            case TMI_VERSION: return L"1.4.0";
            case TMI_URL: return L"";
            default: return L"";
            }
        }

        void OnInitialize(ITrafficMonitor* app) override
        {
            if (!app)
                return;
            const std::wstring image = ModulePath(nullptr);
            const size_t separator = image.find_last_of(L"\\/");
            if (separator == std::wstring::npos || _wcsicmp(image.c_str() + separator + 1, L"TrafficMonitor.exe"))
                return;
            HMODULE module = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                   reinterpret_cast<PCWSTR>(&ModulePath), &module))
                m_start_recovery = true;
        }

#ifdef TMVPNPLUGIN_FIXTURE
        void StopWorkers()
        {
            {
                std::lock_guard<std::mutex> lock(m_refresh_mutex);
                m_stop = true;
            }
            m_refresh_condition.notify_all();
            if (m_recovery_worker.joinable())
                m_recovery_worker.join();
            if (m_worker.joinable())
                m_worker.join();
        }

        void UseFixtureStateDirectory(PCWSTR directory) { m_fixture_directory = directory; }
#endif

        const wchar_t* GetTooltipInfo() override
        {
            static thread_local std::wstring buf;
            std::lock_guard<std::mutex> lock(m_mutex);
            buf = m_tooltip;
            return buf.c_str();
        }

    private:
        CVpnPlugin()
            : m_node_item(m_mutex, m_node_value)
        {
            UpdateAdapter();
            m_worker = std::thread([this] { WorkerLoop(); });
        }

        std::wstring StateDirectory() const
        {
#ifdef TMVPNPLUGIN_FIXTURE
            return m_fixture_directory;
#else
            return RecoveryStateDirectory();
#endif
        }

        void RecoveryWorkerLoop()
        {
#ifndef TMVPNPLUGIN_FIXTURE
            const HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            if (FAILED(apartment))
            {
                ReportRecoveryLaunchError(apartment);
                return;
            }
            const std::wstring image = ModulePath(nullptr);
            FILETIME creation{}, exit{}, kernel{}, user{};
            HMODULE module = nullptr;
            if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)
                || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                      GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      reinterpret_cast<PCWSTR>(&ModulePath), &module))
            {
                ReportRecoveryLaunchError(HRESULT_FROM_WIN32(GetLastError()));
                CoUninitialize();
                return;
            }
            const std::wstring module_path = ModulePath(module);
            const size_t separator = module_path.find_last_of(L"\\/");
            if (image.empty() || separator == std::wstring::npos)
            {
                ReportRecoveryLaunchError(E_FAIL);
                CoUninitialize();
                return;
            }
            const DWORD pid = GetCurrentProcessId();
            const ULONGLONG created = (static_cast<ULONGLONG>(creation.dwHighDateTime) << 32)
                | creation.dwLowDateTime;
            const std::wstring owner_name = RecoveryOwnerName(pid, created);
            const std::wstring directory = module_path.substr(0, separator) + L"\\TMVPNPluginRecovery";
            const std::wstring script = directory + L"\\guard.py";
            const std::wstring ui_script = directory + L"\\verge_ui.ps1";
            const std::wstring arguments = L"-I -B \"" + script + L"\" --plugin-watch --host-pid "
                + std::to_wstring(pid) + L" --host-created " + std::to_wstring(created)
                + L" --host-image \"" + image + L"\"";
            const std::wstring bundled_python = directory + L"\\python\\pythonw.exe";
            const std::wstring pythonw = IsFile(bundled_python) ? bundled_python : L"C:\\Python314\\pythonw.exe";
            ULONGLONG next_launch = 0;
            while (!m_stop)
            {
                const ULONGLONG now = GetTickCount64();
                if (now >= next_launch && !HasRecoveryOwner(owner_name))
                {
                    next_launch = now + 60'000;
                    const HRESULT result = IsFile(pythonw) && IsFile(script) && IsFile(ui_script)
                        ? LaunchInDesktopShell(pythonw.c_str(), arguments.c_str(), directory.c_str())
                        : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
                    if (FAILED(result))
                        ReportRecoveryLaunchError(result);
                }
                for (int i = 0; i < 50 && !m_stop; ++i)
                    Sleep(100);
            }
            CoUninitialize();
#endif
        }

        void WorkerLoop()
        {
#ifndef TMVPNPLUGIN_FIXTURE
            {
                std::lock_guard<std::mutex> lock(m_refresh_mutex);
                if (!m_refresh_seconds)
                    m_refresh_seconds = LoadSettings(StateDirectory()).refresh_seconds;
            }
#endif
            while (!m_stop)
            {
                const auto start = std::chrono::steady_clock::now();
                std::unique_lock<std::mutex> lock(m_refresh_mutex);
#ifndef TMVPNPLUGIN_FIXTURE
                const int seconds = m_refresh_seconds;
                lock.unlock();
                UpdateNodeDelay(seconds);
                lock.lock();
#endif
                while (!m_stop)
                {
                    const auto due = start + std::chrono::seconds(m_refresh_seconds ? m_refresh_seconds : 10);
                    if (std::chrono::steady_clock::now() >= due)
                        break;
                    m_refresh_condition.wait_until(lock, due);
                }
            }
        }

        void UpdateNodeDelay(int refresh_seconds)
        {
            std::wstring pipe;
            const bool has_pipe = FindMihomoPipe(pipe);
            if (!has_pipe)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_node_value = L"未连接";
                m_tooltip = L"VPN: 未连接（未找到 mihomo 管道）";
                m_targets.clear();
                m_targets_profile.clear();
                return;
            }

            std::string body;
            std::string node_utf8;
            std::vector<std::wstring> targets;
            const auto profile_before = CurrentProfileUid();
            const bool proxies_ok = HttpGetViaPipe(pipe, "/proxies", body);
            if (proxies_ok)
            {
                JsonValue root;
                if (JsonParser(body).Parse(root))
                {
                    const JsonValue* proxies = root.Find("proxies");
                    const JsonValue* global = proxies ? proxies->Find("GLOBAL") : nullptr;
                    const JsonValue* now = global ? global->Find("now") : nullptr;
                    if (global)
                        targets = ListRecoveryTargets(*proxies, *global);
                    if (now && now->type == JsonValue::Type::String)
                        node_utf8 = now->str;
                }
            }
            const auto profile_after = CurrentProfileUid();
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!profile_before.empty() && profile_before == profile_after)
                {
                    m_targets.swap(targets);
                    m_targets_profile = profile_after;
                }
                else
                {
                    m_targets.clear();
                    m_targets_profile.clear();
                }
            }

            if (node_utf8.empty())
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_node_value = L"未连接";
                m_tooltip = L"VPN: 未连接（未取得当前节点）";
                return;
            }

            const std::wstring node_wide = Utf8ToWide(node_utf8);
            const std::wstring short_name = ShortNodeName(node_wide);

            int delay = -1;
            std::string delay_body;
            const std::string delay_path = "/proxies/" + UrlEncode(node_utf8)
                + "/delay?timeout=3000&url=" + UrlEncode("http://www.gstatic.com/generate_204");
            if (HttpGetViaPipe(pipe, delay_path, delay_body))
            {
                JsonValue d;
                if (JsonParser(delay_body).Parse(d))
                {
                    const JsonValue* dv = d.Find("delay");
                    if (dv && dv->type == JsonValue::Type::Number)
                        delay = static_cast<int>(dv->number);
                }
            }

            std::wstring value;
            std::wstring tooltip;
            const auto cadence = L"\r\n(每 " + std::to_wstring(refresh_seconds) + L" 秒测速)";
            if (delay >= 0)
            {
                wchar_t buf[160];
                swprintf_s(buf, L"%ls · %d ms", short_name.c_str(), delay);
                value = buf;
                tooltip = L"节点: " + node_wide + L"\r\n延迟: " + std::to_wstring(delay) + L" ms" + cadence;
            }
            else
            {
                value = short_name + L" · 超时";
                tooltip = L"节点: " + node_wide + L"\r\n延迟: 超时" + cadence;
            }
            std::lock_guard<std::mutex> lock(m_mutex);
            m_node_value = value;
            m_tooltip = tooltip;
        }

        void UpdateAdapter()
        {
            unsigned long long in_octets = 0;
            unsigned long long out_octets = 0;
            bool connected = false;

            PMIB_IF_TABLE2 table = nullptr;
            if (GetIfTable2(&table) == NO_ERROR && table != nullptr)
            {
                for (ULONG i = 0; i < table->NumEntries; ++i)
                {
                    const MIB_IF_ROW2& row = table->Table[i];
                    if (row.OperStatus != IfOperStatusUp)
                        continue;
                    if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
                        continue;
                    const std::wstring alias{ row.Alias };
                    const std::wstring desc{ row.Description };
                    if (alias == L"Mihomo" || desc == L"Meta Tunnel"
                        || alias.find(L"Mihomo") != std::wstring::npos
                        || desc.find(L"Meta Tunnel") != std::wstring::npos)
                    {
                        in_octets = row.InOctets;
                        out_octets = row.OutOctets;
                        connected = true;
                        break;
                    }
                }
                FreeMibTable(table);
            }

            m_connected = connected;
            const ULONGLONG now = GetTickCount64();

            if (connected)
            {
                if (m_last_tick != 0 && now > m_last_tick)
                {
                    const ULONGLONG dt = now - m_last_tick;
                    if (dt >= 300)
                    {
                        const unsigned long long up_delta = out_octets >= m_last_out ? out_octets - m_last_out : 0;
                        const unsigned long long down_delta = in_octets >= m_last_in ? in_octets - m_last_in : 0;
                        m_up_speed = static_cast<double>(up_delta) * 1000.0 / static_cast<double>(dt);
                        m_down_speed = static_cast<double>(down_delta) * 1000.0 / static_cast<double>(dt);
                        m_session_up += up_delta;
                        m_session_down += down_delta;
                        m_last_tick = now;
                        m_last_in = in_octets;
                        m_last_out = out_octets;
                    }
                }
                else
                {
                    m_last_tick = now;
                    m_last_in = in_octets;
                    m_last_out = out_octets;
                }
            }
            else
            {
                m_last_tick = 0;
                m_last_in = 0;
                m_last_out = 0;
                m_up_speed = 0.0;
                m_down_speed = 0.0;
            }

            if (connected)
            {
                m_speed_item.m_value = L"\u2191 " + FormatSpeed(static_cast<unsigned long long>(m_up_speed))
                    + L"  \u2193 " + FormatSpeed(static_cast<unsigned long long>(m_down_speed));
                m_status_item.m_value = L"已连接";
            }
            else
            {
                m_speed_item.m_value = L"未连接";
                m_status_item.m_value = L"未连接";
            }
        }

        std::mutex m_mutex;
        std::wstring m_node_value{ L"检测中..." };
        std::wstring m_tooltip{ L"VPN: 正在检测节点…" };
        std::string m_targets_profile;
        std::vector<std::wstring> m_targets;
        CVpnNodeItem m_node_item;
        CVpnSpeedItem m_speed_item;
        CVpnStatusItem m_status_item;

#ifdef TMVPNPLUGIN_FIXTURE
        std::wstring m_fixture_directory;
#endif

        std::thread m_worker;
        std::thread m_recovery_worker;
        std::atomic<bool> m_stop{ false };
        std::atomic<bool> m_start_recovery{ false };
        std::mutex m_refresh_mutex;
        std::condition_variable m_refresh_condition;
        int m_refresh_seconds{};

        bool m_connected{};
        ULONGLONG m_last_tick{};
        unsigned long long m_last_in{};
        unsigned long long m_last_out{};
        double m_up_speed{};
        double m_down_speed{};
        unsigned long long m_session_up{};
        unsigned long long m_session_down{};
    };
}

extern "C" __declspec(dllexport) ITMPlugin* TMPluginGetInstance()
{
    return &CVpnPlugin::Instance();
}

#ifdef TMVPNPLUGIN_FIXTURE
extern "C" __declspec(dllexport) void TMVPNPluginStopWorkers()
{
    CVpnPlugin::Instance().StopWorkers();
}

extern "C" __declspec(dllexport) void TMVPNPluginUseFixtureStateDirectory(PCWSTR directory)
{
    CVpnPlugin::Instance().UseFixtureStateDirectory(directory);
}

extern "C" __declspec(dllexport) BOOL TMVPNPluginTestSettings(PCWSTR directory)
{
    VpnSettings desired{ L"日本 \"回线\" \\ 家宽", 30, true, std::string("test_CN-01") };
    if (!SaveSettings(directory, desired))
        return FALSE;
    const auto settings = LoadSettings(directory);
    if (!settings.valid || settings.target != desired.target || settings.refresh_seconds != 30
        || settings.profile_uid != desired.profile_uid)
        return FALSE;
    desired.profile_uid = "";
    if (!SaveSettings(directory, desired) || LoadSettings(directory).profile_uid != desired.profile_uid)
        return FALSE;
    const auto legacy = ParseSettings(R"({"target_node":"Node A","refresh_seconds":10})");
    if (!legacy.valid || legacy.profile_uid.has_value())
        return FALSE;
    const PCSTR invalid[]{
        "{\"target_node\":\"日本\",\"refresh_seconds\":30.0}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":true}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":30,\"other\":[]}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":15,\"refresh_seconds\":30}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":30}junk",
        "{\"target_node\":\"日本\\n\",\"refresh_seconds\":30}",
        "{\"target_node\":\"日本\\uD800\",\"refresh_seconds\":30}",
        "{\"target_node\":\"ＤＩＲＥＣＴ \",\"refresh_seconds\":30}",
        "{\"target_node\":\"REJECT\",\"refresh_seconds\":30}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":25}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":30,\"profile_uid\":\"../private\"}",
        "{\"target_node\":\"日本\",\"refresh_seconds\":30,\"profile_uid\":null}",
        "\xef\xbb\xbf{\"target_node\":\"日本\",\"refresh_seconds\":30}",
    };
    for (PCSTR bad : invalid)
    {
        const auto fallback = ParseSettings(bad);
        if (fallback.valid || fallback.refresh_seconds != 10 || fallback.target != default_target)
            return FALSE;
    }
    auto catalog = ParseProfileCatalog(R"({"available":true,"current":"p1","selected":"p2","items":[
        {"uid":"p1","name":"订阅一","ambiguous":false},
        {"uid":"p2","name":"Subscription Two","ambiguous":true}
    ]})");
    if (catalog.items.size() != 2 || catalog.items.front().name != L"订阅一" || catalog.selected != "p2"
        || !CanChooseTarget(catalog, "p1", "p1", "p1") || CanChooseTarget(catalog, "p1", "p2", "p1")
        || CanChooseTarget(catalog, "p1", "p1", "p2") || CanChooseProfile(catalog, "p2")
        || CanChooseProfile(catalog, "missing")
        || CurrentProfileUidFromHeader("\xef\xbb\xbf# Profiles Config for Clash Verge\r\ncurrent: 'p1'\r\nitems:\r\n") != "p1"
        || !CurrentProfileUidFromHeader("current: ../p1\n").empty()
        || !CurrentProfileUidFromHeader("items:\n  current: p1\n").empty())
        return FALSE;
    catalog.items.front().ambiguous = true;
    if (CanChooseTarget(catalog, "p1", "p1", "p1"))
        return FALSE;
    const std::string mock = R"json({
        "GLOBAL":{"type":"Selector","all":["日本","Node A","DIRECT","分组","子中继","PRO | 订阅专用节点AN | 0倍","日本"]},
        "日本":{"type":"Vless"},"Node A":{"type":"Shadowsocks"},
        "DIRECT":{"type":"Direct"},"分组":{"type":"Selector","all":["日本"]},
        "子中继":{"type":"Relay"},"PRO | 订阅专用节点AN | 0倍":{"type":"Socks5"}
    })json";
    JsonValue proxies;
    if (!JsonParser(mock).Parse(proxies))
        return FALSE;
    const auto* global = proxies.Find("GLOBAL");
    const std::vector<std::wstring> expected{ L"日本", L"Node A" };
    return global && ListRecoveryTargets(proxies, *global) == expected;
}
#endif
