//
// Created by CoreDeck RE toolbench on 09/11/2026.
//
// Per-window state for the reverse-engineering (Research) tools, split out of
// the Context the way upstream splits its own work structs.
//

#ifndef COREDECK_CONTEXT_RE_WORK_H
#define COREDECK_CONTEXT_RE_WORK_H

#include <atomic>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/adb.h"
#include "core/appdata.h"
#include "core/avd_root.h"
#include "core/cert.h"
#include "core/checks.h"
#include "core/flutter.h"
#include "core/frida.h"
#include "core/mitm.h"
#include "core/proxy.h"
#include "core/repackage.h"
#include "core/tools.h"

namespace CoreDeck::Gui {
    struct DevicePanelWork {
        std::atomic<bool> DevicesBusy{false};
        std::future<std::vector<Core::Re::DeviceSummary>> DevicesFuture;
        std::vector<Core::Re::DeviceSummary> Devices;
        bool DevicesLoaded = false;

        std::atomic<bool> PackagesBusy{false};
        std::future<std::vector<std::string>> PackagesFuture;
        std::vector<std::string> Packages;
        std::string PackagesSerial; // serial the current package list belongs to
        bool PackagesLoaded = false;
        bool IncludeVendor = false;

        char PackageFilter[128] = {};
    };

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
    };

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
    };

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
    };

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
    };

    struct FridaHookWork {
        char Package[256] = {};
        bool Attach = false;
        std::vector<bool> ScriptSelected;
        bool ScriptsInit = false;
        char UserScriptPath[1024] = {};
        std::vector<std::string> UserScripts;
        Core::FridaHookSession Session;
        std::string Error;
    };

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
    };

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
    };

    struct AppDataWork {
        char Package[256] = {};
        std::string LoadedPackage; // package the listing/path belong to
        std::string SubPath; // current dir relative to /data/data/<pkg>

        std::atomic<bool> ListBusy{false};
        std::future<std::vector<Core::DataEntry>> ListFuture;
        std::vector<Core::DataEntry> Entries;
        std::string PendingSubPath; // subPath the in-flight list is for
        bool HasListing = false;
        std::string ListError;

        char GrepPattern[256] = {};
        std::atomic<bool> GrepBusy{false};
        std::future<std::vector<std::string>> GrepFuture;
        std::vector<std::string> GrepHits;
        bool HasGrep = false;

        std::atomic<bool> PullBusy{false};
        std::future<std::pair<bool, std::string>> PullFuture;
        std::string PullOutcome;
        bool PullOk = false;
    };

    struct MitmWork {
        char CertPath[1024] = {};
        char ProxyTarget[128] = {};
        char Package[256] = {};
        bool TrustCert = true;
        bool SetProxy = true;
        bool Transparent = false;
        bool Launch = true;
        bool RemoveCertOnTeardown = false;

        std::atomic<bool> Busy{false};
        std::future<Core::MitmResult> Future;
        bool HasResult = false;
        Core::MitmResult Result;
        bool WasTeardown = false;
        std::string InstalledCertName; // remembered for teardown
        std::string ValidationError;
    };

    struct RepackageWork {
        int SourceMode = 0; // 0 device, 1 directory, 2 single apk
        char Package[256] = {};
        char InputPath[1024] = {};
        char ApkEditorJar[1024] = {};
        int Method = 0; // 0 auto, 1 flutter static, 2 apk-mitm, 3 gadget, 4 reflutter, 5 none
        bool AddNsc = true;
        bool Sign = true;
        bool Install = false;
        bool Grant = true;

        std::atomic<bool> Busy{false};
        std::shared_ptr<Core::RepackageProgress> Progress;
        std::future<Core::RepackageResult> Future;
        bool HasResult = false;
        Core::RepackageResult Result;
        std::string ValidationError;
    };

    struct ReToolsWork {
        std::atomic<bool> Busy{false};
        std::future<std::vector<Core::ReToolStatus>> Future;
        std::vector<Core::ReToolStatus> Statuses;
        bool Loaded = false;
        bool Requested = false; // detection kicked off once on first open
    };
}

#endif // COREDECK_CONTEXT_RE_WORK_H
