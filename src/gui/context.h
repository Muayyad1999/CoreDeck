//
// Created by AbdulMuaz Aqeel on 18/04/2026.
//

#ifndef COREDECK_CONTEXT_H
#define COREDECK_CONTEXT_H

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "app/app_settings_types.h"
#include "core/avd_manager.h"
#include "core/adb.h"
#include "core/avd_root.h"
#include "core/cert.h"
#include "core/proxy.h"
#include "core/frida.h"
#include "core/flutter.h"
#include "core/checks.h"
#include "core/emulator.h"
#include "core/health_check.h"
#include "core/jdk.h"
#include "core/options.h"
#include "core/apk_analyzer.h"
#include "core/keytool.h"
#include "core/sdk.h"
#include "core/sdk_bootstrap.h"
#include "core/sdk_manager.h"
#include "core/skin.h"
#include "core/system_image.h"
#include "signer_work.h"

struct GLFWwindow;

namespace CoreDeck::Gui {
    enum class Screen : uint8_t {
        Onboarding,
        Main,
    };

    enum class WorkspacePage : uint8_t {
        Home,
        ApkAnalyzer,
        ApkSigner,
        Keytool,
        JarSigner,
    };

    enum class AvdSortMode : uint8_t {
        Name,
        ApiLevel,
        Device,
    };

    enum class ImageCategory : uint8_t {
        All,
        PhoneTablet,
        Wear,
        Tv,
        Automotive,
        Desktop,
        Xr,
        Other,
    };

    enum class DeviceCategory : uint8_t {
        All,
        Phone,
        Tablet,
        Wear,
        Tv,
        Automotive,
        Desktop,
        Other,
    };

    struct StorageScanResult {
        std::uintmax_t TotalAvdSize = 0;
        std::uintmax_t SystemImagesSize = 0;
    };

    enum class KeytoolTask : uint8_t {
        None,
        Inspect,
        Create,
    };

    enum class KeytoolPage : uint8_t {
        Inspect,
        Create,
    };

    struct AsyncLoad {
        std::atomic<bool> Loading{false};
        std::atomic<bool> Ready{false};
        std::future<void> Future;
    };

    template<typename Result>
    struct AsyncWork {
        std::atomic<bool> Busy{false};
        std::future<Result> Future;
    };

    using ApkSignerState = ApkSignerWork;
    using JarSignerState = JarSignerWork;

    struct Context {
        struct Host {
            Core::SdkInfo Sdk;
            Core::JdkInfo Jdk;
            Core::EmulatorManager Manager;

            explicit Host(Core::SdkInfo sdk) : Sdk(std::move(sdk)), Manager(Sdk) {
            }
        } Host;

        struct Flow {
            Screen CurrentScreen = Screen::Main;
        } Flow;

        struct Catalog {
            std::vector<std::string> AvdNames;
            std::vector<Core::AvdInfo> Avds;
            int SelectedAvd = -1;
            int PreviousSelectedAvd = -1;
            std::unordered_map<std::string, std::vector<Core::EmulatorOption>> PerAvdOptions;

            char SearchFilter[128] = {};
            AvdSortMode SortMode = AvdSortMode::Name;
            bool SortAscending = true;
            std::vector<int> FilteredIndices;
        } Catalog;

        // Selection shared across the reverse-engineering windows (Phase 1+).
        struct Target {
            std::string Serial;  // selected adb device serial
            std::string ApkPath; // selected/working APK path (used by later phases)
        } Target;

        struct LogViewState {
            std::string Search;
            int ActiveMatchIndex = 0;
            bool UseRegex = false;
        };

        struct Logs {
            std::unordered_map<std::string, LogViewState> PerAvdView;
            bool PendingScroll = false;
            bool PendingFocus = false;
            int PendingSyncFrames = 0;
        } Logs;

        struct Prefs {
            bool AutoScroll = true;
            bool ConfirmBeforeDeleteAvd = true;
            bool CrashReportingEnabled = true;
            bool CheckForUpdatesOnLaunch = true;
            bool IncludeBetaReleases = false;
            App::ThemePreference Theme = App::ThemePreference::System;
            std::string Language;
        } Prefs;

        struct UI {
            bool ShowAboutDialog = false;
            bool ShowDeleteAvdDialog = false;
            bool ShowCreateAvdDialog = false;
            bool ShowDeviceProfileDialog = false;
            bool ShowSkinDialog = false;
            bool ShowInstallImageDialog = false;
            bool ReopenCreateAvdOnInstallClose = false;
            bool ShowPreferences = false;
            bool ShowStorageDialog = false;
            bool ShowDevicePanel = false;
            bool ShowAvdRootDialog = false;
            bool ShowCertDialog = false;
            bool ShowProxyDialog = false;
            bool ShowFridaDialog = false;
            bool ShowFridaHookDialog = false;
            bool ShowFlutterDialog = false;
            bool ShowHardeningDialog = false;
            WorkspacePage Workspace = WorkspacePage::Home;
            bool ShowWipeDataDialog = false;
            bool ShowHealthCheckDialog = false;
            bool ShowAcceptLicensesDialog = false;
            bool ShowAvdListPanel = true;
            bool ShowOptionsPanel = true;
            bool ShowDetailsPanel = true;
            bool ShowLogPanel = true;
            GLFWwindow *MainWindow = nullptr;
            bool HideHealthCheckBanner = false;
            bool OpenPreferencesToJava = false;
            std::string NativeWindowPage;
        } UI;

        struct AvdCreationWork {
            std::vector<Core::SystemImage> SystemImages;
            std::vector<Core::DeviceProfile> DeviceProfiles;
            bool DeviceDefinitionsSkipped = false;
            std::vector<Core::Skin> Skins;
            Core::AvdCreationData CreationData;
            int SelectedSystemImage = 0;
            int SelectedDevice = 0;
            int PendingSelectedDevice = 0;
            int SelectedSkin = 0; // 0 = "No skin"
            int PendingSelectedSkin = 0;
            char SkinSearchFilter[128] = {};
            DeviceCategory SelectedDeviceCategory = DeviceCategory::Phone;
            char DeviceSearchFilter[128] = {};
            int SelectedGpuMode = 0;
            bool NameAutoFilled = true;
            bool DisplayNameAutoFilled = true;
            bool DeviceAutoFilled = true;
            bool SkinAutoFilled = true;
            int LastDeviceForSkinAuto = -1;

            AsyncLoad Prefetch;
            AsyncWork<bool> SystemImageRemoval;
        } AvdCreationWork;

        struct ImageInstallationWork {
            std::vector<Core::RemoteSystemImage> RemoteImages;
            int SelectedImage = -1;
            ImageCategory SelectedCategory = ImageCategory::PhoneTablet;
            char SearchFilter[128] = {};

            AsyncLoad Prefetch;

            std::atomic<bool> Installing{false};
            std::shared_ptr<Core::InstallProgressData> Progress;
            std::future<bool> InstallFuture;
            bool AwaitingLicenseConsent = false;
            std::atomic<bool> LicenseBusy{false};
            std::future<Core::SdkLicenseQuery> LicenseCheckFuture;
            std::future<bool> LicenseAcceptFuture;
            std::string PendingPackagePath;
            std::string LicenseError;
        } ImageInstallationWork;

        struct SdkBootstrapWork {
            Core::BootstrapPlan Plan;
            std::shared_ptr<Core::BootstrapProgressData> Progress;
            std::atomic<bool> Busy{false};
            std::future<bool> Future;
            Core::BootstrapError LastError = Core::BootstrapError::None;
            std::string LastErrorDetail;
        } SdkBootstrapWork;

        struct HealthCheckWork {
            std::shared_ptr<Core::HealthCheckProgressData> Progress;
            std::atomic<bool> Busy{false};
            std::future<void> Future;
            std::string ObservedTools;
        } HealthCheckWork;

        struct AcceptLicensesWork {
            std::atomic<bool> Busy{false};
            bool Accepted = false;
            std::future<bool> Future;
            std::string Error;
        } AcceptLicensesWork;

        struct LicenseNotice {
            std::atomic<bool> Busy{false};
            bool Known = false;
            Core::LicenseStatus Status = Core::LicenseStatus::AllAccepted;
            std::string SdkManagerPath;
            std::uint32_t Epoch = 0;
            std::uint32_t PendingEpoch = 0;
            std::future<Core::LicenseStatus> Future;
        } LicenseNotice;

        struct Jobs {
            AsyncWork<void> AvdCreation, AvdDeletion, AvdWipe;
        } Jobs;

        struct DiskUsage {
            std::unordered_map<std::string, std::uintmax_t> PerAvdCache;
            StorageScanResult LastScan;
            std::atomic<bool> Loading{false};
            bool Ready = false;
            std::future<StorageScanResult> Future;
        } DiskUsage;

        struct ApkAnalyzerWork {
            std::atomic<bool> Busy{false};
            std::atomic<float> Progress{0.0F};
            std::atomic<int> Stage{1};
            std::atomic<bool> Cancel{false};
            std::atomic<std::uint32_t> LoadEpoch{0};
            std::string PendingPath;
            std::future<Core::ApkReport> Future;
            bool HasReport = false;
            Core::ApkReport Report;

            std::atomic<bool> CompareBusy{false};
            std::string ComparePath;
            std::future<Core::ApkAnalyzerQuery<std::vector<Core::ApkCompareEntry>>> CompareFuture;
            bool HasCompare = false;
            Core::ApkAnalyzerQuery<std::vector<Core::ApkCompareEntry>> Compare;

            std::string SelectedPath;
            std::uint32_t ContentEpoch = 0;

            char TreeFilter[128] = {};

            std::vector<std::string> RecentApks;
            bool RecentLoaded = false;
            std::vector<std::string> PendingDrops;
        } ApkAnalyzerWork;

        struct DevicePanelWork {
            std::atomic<bool> DevicesBusy{false};
            std::future<std::vector<Core::DeviceSummary>> DevicesFuture;
            std::vector<Core::DeviceSummary> Devices;
            bool DevicesLoaded = false;

            std::atomic<bool> PackagesBusy{false};
            std::future<std::vector<std::string>> PackagesFuture;
            std::vector<std::string> Packages;
            std::string PackagesSerial; // serial the current package list belongs to
            bool PackagesLoaded = false;
            bool IncludeVendor = false;

            char PackageFilter[128] = {};
        } DevicePanelWork;

        struct AvdRootWork {
            bool IncludePrerelease = false;
            char MagiskOverride[512] = {};

            std::atomic<bool> ResolveBusy{false};
            std::future<std::pair<std::optional<Core::ResolvedMagisk>, std::string>> ResolveFuture;
            bool HasResolved = false;
            Core::ResolvedMagisk Resolved;
            std::string ResolveError;

            std::atomic<bool> RootCheckBusy{false};
            std::future<Core::RootStatus> RootCheckFuture;
            Core::RootStatus LastRootStatus = Core::RootStatus::Unknown;
            std::string RootCheckedSerial;

            bool StripVerity = true;
            std::atomic<bool> RootBusy{false};
            std::shared_ptr<Core::RootProgress> Progress;
            std::future<bool> RootFuture;
            std::string RootOutcome;

            std::atomic<bool> RestoreBusy{false};
            std::future<std::pair<bool, std::string>> RestoreFuture;
            std::string RestoreOutcome;
        } AvdRootWork;

        struct CertWork {
            char CertPath[1024] = {};
            Core::CaCertInfo Info;
            bool HasInfo = false;
            std::string Inspected; // path last inspected

            std::atomic<bool> InstallBusy{false};
            std::future<std::pair<std::optional<std::string>, std::string>> InstallFuture;
            std::string InstallOutcome;
            bool InstallOk = false;

            std::atomic<bool> RemoveBusy{false};
            std::future<std::pair<bool, std::string>> RemoveFuture;
            std::string RemoveOutcome;
        } CertWork;

        struct ProxyWork {
            char Target[128] = {};
            bool Transparent = false;

            std::atomic<bool> Busy{false};
            std::future<std::pair<bool, std::string>> Future;
            std::string Outcome;
            bool OutcomeOk = false;

            std::atomic<bool> StatusBusy{false};
            std::future<Core::ProxyStatus> StatusFuture;
            Core::ProxyStatus Status;
            bool HasStatus = false;
        } ProxyWork;

        struct FridaWork {
            char Version[64] = {};
            int Port = 0;
            bool Stealth = false;
            char DevName[64] = "frida-server";
            std::string HostVersion;
            bool HostChecked = false;

            std::atomic<bool> Busy{false};
            std::future<std::pair<bool, std::string>> Future;
            std::string Outcome;
            bool OutcomeOk = false;

            std::atomic<bool> PsBusy{false};
            std::future<std::pair<std::vector<Core::FridaProcess>, std::string>> PsFuture;
            std::vector<Core::FridaProcess> Processes;
            bool HasProcesses = false;
            std::string PsError;
            char PsFilter[128] = {};
        } FridaWork;

        struct FridaHookWork {
            char Package[256] = {};
            bool Attach = false;
            std::vector<bool> ScriptSelected;
            bool ScriptsInit = false;
            char UserScriptPath[1024] = {};
            std::vector<std::string> UserScripts;
            Core::FridaHookSession Session;
            std::string Error;
        } FridaHookWork;

        struct FlutterWork {
            char ApkPath[1024] = {};
            char BlutterPath[1024] = {};
            bool BlutterInit = false;
            bool NoAnalysis = true;
            std::atomic<bool> Busy{false};
            std::future<Core::BlutterRun> Future;
            bool HasResult = false;
            Core::BlutterRun Result;

            std::atomic<bool> TlsBusy{false};
            std::future<Core::FlutterPatchResult> TlsFuture;
            bool HasTlsResult = false;
            Core::FlutterPatchResult TlsResult;
        } FlutterWork;

        struct HardeningWork {
            char ApkPath[1024] = {};
            char ApktoolPath[1024] = {};
            bool ApktoolInit = false;

            std::atomic<bool> ScanBusy{false};
            std::future<Core::ScanResult> ScanFuture;
            bool HasScan = false;
            Core::ScanResult Scan;

            std::atomic<bool> NeutBusy{false};
            std::future<Core::NeutralizeResult> NeutFuture;
            bool HasNeut = false;
            Core::NeutralizeResult Neut;
        } HardeningWork;

        ApkSignerState ApkSignerWork;
        JarSignerState JarSignerWork;

        struct KeytoolWork {
            std::atomic<bool> Busy{false};
            KeytoolTask Task = KeytoolTask::None;
            KeytoolPage Page = KeytoolPage::Inspect;

            std::future<Core::KeystoreDescription> InspectFuture;
            std::future<Core::CreateKeystoreResult> CreateFuture;

            std::string InspectPath;
            std::string CreatePath;

            char InspectPassword[512] = {};
            char CreatePassword[512] = {};
            char ConfirmPassword[512] = {};
            char KeyPassword[512] = {};
            bool ShowInspectPassword = false;
            bool ShowCreatePassword = false;
            bool ShowConfirmPassword = false;
            bool ShowKeyPassword = false;
            bool KeyPasswordMatches = true;
            std::uint32_t SecretEpoch = 0;

            Core::KeystoreType StoreType = Core::KeystoreType::Pkcs12;
            int CreateExtension = 0;
            int CreateTemplate = 0;
            Core::KeyAlgorithm Algorithm = Core::KeyAlgorithm::Rsa;
            int KeySize = Core::DEFAULT_KEY_SIZE;
            int ValidityDays = Core::DEFAULT_KEY_VALIDITY_DAYS;
            char Alias[256] = {};
            char CommonName[256] = {};
            char OrganizationalUnit[256] = {};
            char Organization[256] = {};
            char Locality[256] = {};
            char StateName[256] = {};
            char Country[8] = {};

            bool HasInspect = false;
            Core::KeystoreDescription InspectResult;
            int InspectEntry = 0;

            bool HasCreate = false;
            Core::CreateKeystoreResult CreateResult;
            int CreateEntry = 0;
        } KeytoolWork;

        struct Updates {
            bool ShowNewVersionModal = false;
            std::string LatestVersion;
            std::string LatestNotes;
            bool ShowUpToDateModal = false;
            bool RequestManualUpdateCheck = false;
            bool UpdateCheckInFlight = false;
        } Updates;

        explicit Context(Core::SdkInfo sdk) : Host(std::move(sdk)) {
        }
    };

    inline void SetNativeWindowPage(Context &context, const char *page) {
        context.UI.NativeWindowPage = page != nullptr ? page : "";
    }
}

#endif // COREDECK_CONTEXT_H
