#include "PluginInterface.h"
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <cwchar>
#include <string>

class HostFixture final : public ITrafficMonitor
{
    int GetAPIVersion() override { return 0; }
    const wchar_t* GetVersion() override { return L"test"; }
    double GetMonitorValue(MonitorItem) override { return 0; }
    const wchar_t* GetMonitorValueString(MonitorItem, int) override { return L""; }
    void ShowNotifyMessage(const wchar_t*) override {}
    unsigned short GetLanguageId() const override { return 0; }
    const wchar_t* GetPluginConfigDir() const override { return L""; }
    int GetDPI(DPIType) const override { return 96; }
    unsigned int GetThemeColor() const override { return 0; }
    const wchar_t* GetStringRes(const wchar_t*, const wchar_t*) override { return L""; }
};

bool TestMenuFixture(ITMPlugin& plugin, PCWSTR directory)
{
    const std::wstring marker = std::wstring(directory) + L"\\monitor.pause";
    if (GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;
    if (plugin.GetCommandCount() != 1 || !plugin.GetCommandName(0)
        || wcscmp(plugin.GetCommandName(0), L"自动恢复订阅") != 0
        || plugin.GetCommandName(1) != nullptr || !plugin.IsCommandChecked(0)
        || plugin.IsCommandChecked(1))
        return false;

    plugin.OnPluginCommand(1, nullptr, nullptr);
    if (!plugin.IsCommandChecked(0))
        return false;

    plugin.OnPluginCommand(0, nullptr, nullptr);
    if (plugin.IsCommandChecked(0) || GetFileAttributesW(marker.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;

    plugin.DataRequired();
    for (int i = 0; i < 3; ++i)
    {
        IPluginItem* item = plugin.GetItem(i);
        if (!item || !item->GetItemValueText() || !item->GetItemValueText()[0])
            return false;
    }
    if (plugin.GetItem(3) != nullptr)
        return false;

    plugin.OnPluginCommand(0, nullptr, nullptr);
    if (!plugin.IsCommandChecked(0) || GetFileAttributesW(marker.c_str()) != INVALID_FILE_ATTRIBUTES)
        return false;

    if (!CreateDirectoryW(marker.c_str(), nullptr))
        return false;
    plugin.OnPluginCommand(0, nullptr, nullptr);
    const bool invalid_marker_rejected = !plugin.IsCommandChecked(0);
    return RemoveDirectoryW(marker.c_str()) && invalid_marker_rejected;
}

int wmain(int argc, wchar_t** argv)
{
    _setmode(_fileno(stdout), _O_U8TEXT);
    if (argc < 2 || argc > 4)
    {
        wprintf(L"usage: test_host <dll> [fixture-state-dir | --watch-smoke <probe>]\n");
        return 1;
    }
    HMODULE module = LoadLibraryW(argv[1]);
    if (module == nullptr) { wprintf(L"LoadLibrary failed: %lu\n", GetLastError()); return 2; }
    using GetInstanceFn = ITMPlugin * (*)();
    auto get_instance = reinterpret_cast<GetInstanceFn>(GetProcAddress(module, "TMPluginGetInstance"));
    if (get_instance == nullptr) { wprintf(L"GetProcAddress(TMPluginGetInstance) failed\n"); return 3; }
    ITMPlugin* plugin = get_instance();
    if (plugin == nullptr) { wprintf(L"plugin instance null\n"); return 4; }
    if (argc == 4)
    {
        if (wcscmp(argv[2], L"--watch-smoke") != 0
            || GetFileAttributesW(argv[3]) != INVALID_FILE_ATTRIBUTES)
            return 7;
        HostFixture host;
        plugin->OnInitialize(&host);
        plugin->DataRequired();
        for (int i = 0; i < 100; ++i)
        {
            if (GetFileAttributesW(argv[3]) != INVALID_FILE_ATTRIBUTES)
            {
                wprintf(L"watch_smoke=pass\n");
                return 0;
            }
            Sleep(150);
        }
        wprintf(L"watch_smoke=timeout\n");
        return 8;
    }
    if (argc == 3)
    {
        auto use_fixture_state = reinterpret_cast<void(*)(PCWSTR)>(
            GetProcAddress(module, "TMVPNPluginUseFixtureStateDirectory"));
        auto stop_workers = reinterpret_cast<void(*)()>(GetProcAddress(module, "TMVPNPluginStopWorkers"));
        auto test_settings = reinterpret_cast<BOOL(*)(PCWSTR)>(GetProcAddress(module, "TMVPNPluginTestSettings"));
        if (!use_fixture_state || !stop_workers || !test_settings)
            return 5;
        use_fixture_state(argv[2]);
        const bool success = TestMenuFixture(*plugin, argv[2]);
        const bool settings_ok = test_settings(argv[2]);
        stop_workers();
        HMODULE still_loaded = nullptr;
        const BOOL unloaded = FreeLibrary(module)
            && !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                                  | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                  reinterpret_cast<PCWSTR>(get_instance), &still_loaded);
        wprintf(L"menu_fixture=%ls settings_fixture=%ls dll_unloaded=%d\n",
                success ? L"pass" : L"fail", settings_ok ? L"pass" : L"fail", unloaded);
        return success && settings_ok && unloaded ? 0 : 6;
    }
    wprintf(L"api_version=%d\n", plugin->GetAPIVersion());
    wprintf(L"name=%ls version=%ls\n", plugin->GetInfo(ITMPlugin::TMI_NAME), plugin->GetInfo(ITMPlugin::TMI_VERSION));
    for (int i = 0;; ++i)
    {
        IPluginItem* item = plugin->GetItem(i);
        if (item == nullptr) break;
        wprintf(L"item[%d] id=%ls name=%ls label=%ls sample=%ls\n", i, item->GetItemId(), item->GetItemName(), item->GetItemLableText(), item->GetItemValueSampleText());
    }
    wprintf(L"waiting 4s for node delay...\n");
    Sleep(4000);
    plugin->DataRequired();
    for (int i = 0;; ++i)
    {
        IPluginItem* item = plugin->GetItem(i);
        if (item == nullptr) break;
        wprintf(L"item[%d] value=%ls\n", i, item->GetItemValueText());
    }
    wprintf(L"tooltip=%ls\n", plugin->GetTooltipInfo());
    fflush(stdout);
    FreeLibrary(module);
    return 0;
}
