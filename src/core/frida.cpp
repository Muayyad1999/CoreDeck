//
// Created by CoreDeck RE toolbench on 05/11/2026.
//

#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "core/frida.h"
#include "core/adb.h"
#include "core/xz.h"
#include "platform/http_download.h"
#include "platform/paths.h"
#include "platform/process.h"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

using namespace CoreDeck::Core::Re;

namespace CoreDeck::Core {
    namespace {
        std::string Trim(const std::string &value) {
            std::size_t start = 0;
            std::size_t end = value.size();
            while (start < end && std::isspace(static_cast<unsigned char>(value[start]))) {
                ++start;
            }
            while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
                --end;
            }
            return value.substr(start, end - start);
        }

        std::optional<std::vector<std::uint8_t>> ReadFileBytes(const std::string &path) {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }
            return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }
    }

    std::string AbiToFridaArch(const std::string &abi) {
        if (abi == "arm64-v8a") {
            return "arm64";
        }
        if (abi == "armeabi-v7a") {
            return "arm";
        }
        if (abi == "x86_64") {
            return "x86_64";
        }
        if (abi == "x86") {
            return "x86";
        }
        return "arm64";
    }

    std::string FridaServerAssetName(const std::string &version, const std::string &abi) {
        return "frida-server-" + version + "-android-" + AbiToFridaArch(abi);
    }

    std::string FridaServerDownloadUrl(const std::string &version, const std::string &abi) {
        return "https://github.com/frida/frida/releases/download/" + version + "/" +
               FridaServerAssetName(version, abi) + ".xz";
    }

    std::string ParseFridaVersion(const std::string &fridaVersionOutput) {
        const std::string trimmed = Trim(fridaVersionOutput);
        // Keep the first whitespace-delimited token (the version).
        const std::size_t space = trimmed.find_first_of(" \t\r\n");
        return space == std::string::npos ? trimmed : trimmed.substr(0, space);
    }

    std::vector<FridaProcess> ParseFridaPs(const std::string &fridaPsOutput) {
        std::vector<FridaProcess> processes;
        std::istringstream stream(fridaPsOutput);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string trimmed = Trim(line);
            if (trimmed.empty()) {
                continue;
            }
            // Skip the header row ("PID  Name") and the separator ("----  ----").
            if (trimmed.rfind("PID", 0) == 0 || trimmed.find_first_not_of("- \t") == std::string::npos) {
                continue;
            }
            std::istringstream row(trimmed);
            std::string pidText;
            row >> pidText;
            bool numeric = !pidText.empty();
            for (const char c: pidText) {
                if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
                    numeric = false;
                    break;
                }
            }
            if (!numeric) {
                continue;
            }
            std::string name;
            std::getline(row, name);
            FridaProcess process;
            process.Pid = std::stoi(pidText);
            process.Name = Trim(name);
            processes.push_back(std::move(process));
        }
        return processes;
    }

    std::string DetectHostFridaVersion() {
        const Platform::CommandResult result = Platform::RunCommandArgsResult("frida", {"--version"});
        if (!result.Started || result.ExitCode != 0) {
            return "";
        }
        return ParseFridaVersion(result.Output);
    }

    FridaServerDeps DefaultFridaServerDeps() {
        FridaServerDeps deps;
        deps.Download = [](const std::string &url, const std::string &dest, std::string &error) {
            return Platform::HttpDownloadToFile(
                url,
                dest,
                "CoreDeck",
                [](std::uint64_t, std::uint64_t) { return true; },
                error
            );
        };
        deps.CacheDir = Platform::JoinPaths({Platform::GetConfigDirectory(), "frida"});
        return deps;
    }

    std::optional<std::string> ResolveFridaServer(
        const FridaServerDeps &deps,
        const std::string &version,
        const std::string &abi,
        const bool allowDownload,
        std::string &error
    ) {
        if (version.empty()) {
            error = "No frida version given, and the host `frida` was not found.";
            return std::nullopt;
        }
        if (deps.CacheDir.empty()) {
            error = "No cache directory is configured.";
            return std::nullopt;
        }
        std::error_code ec;
        std::filesystem::create_directories(deps.CacheDir, ec);

        const std::string name = FridaServerAssetName(version, abi);
        const std::string cached = Platform::JoinPaths({deps.CacheDir, name});
        if (std::filesystem::exists(cached)) {
            return cached;
        }
        if (!allowDownload) {
            error = "frida-server is not cached and downloads are disabled.";
            return std::nullopt;
        }
        if (!deps.Download) {
            error = "No downloader is configured.";
            return std::nullopt;
        }

        const std::string xzPath = cached + ".xz";
        std::string downloadError;
        if (!deps.Download(FridaServerDownloadUrl(version, abi), xzPath, downloadError)) {
            error = "Download failed: " + downloadError;
            return std::nullopt;
        }
        const auto xzBytes = ReadFileBytes(xzPath);
        if (!xzBytes) {
            error = "Could not read the downloaded archive.";
            return std::nullopt;
        }
        const auto binary = XzDecompress(*xzBytes);
        if (!binary) {
            error = "Could not decompress the frida-server archive.";
            return std::nullopt;
        }
        {
            std::ofstream out(cached, std::ios::binary | std::ios::trunc);
            if (!out) {
                error = "Could not write the frida-server binary to the cache.";
                return std::nullopt;
            }
            out.write(reinterpret_cast<const char *>(binary->data()), static_cast<std::streamsize>(binary->size()));
        }
        std::filesystem::remove(xzPath, ec);
        return cached;
    }

    bool StartFridaServer(
        const SdkInfo &sdk,
        const std::string &serial,
        const std::string &binaryPath,
        const std::string &devName,
        const int port,
        std::string &error
    ) {
        const std::string devPath = "/data/local/tmp/" + devName;
        const AdbResult push = Push(sdk, serial, binaryPath, devPath);
        if (!push.Ok()) {
            error = "adb push failed: " + push.Output;
            return false;
        }
        const AdbResult chmod = ShellSu(sdk, serial, "chmod 755 " + devPath);
        if (!chmod.Ok()) {
            error = "Could not chmod frida-server (is the AVD rooted?). " + chmod.Output;
            return false;
        }
        const std::string listen = port > 0 ? (" -l 0.0.0.0:" + std::to_string(port)) : "";
        ShellSu(sdk, serial, "nohup " + devPath + listen + " >/dev/null 2>&1 &");
        return true;
    }

    bool StopFridaServer(const SdkInfo &sdk, const std::string &serial, const std::string &devName) {
        const AdbResult result =
            ShellSu(sdk, serial, "pkill -f frida-server; pkill -f /data/local/tmp/" + devName);
        return result.Started;
    }

    std::vector<FridaProcess> FridaPs(const std::string &serial, std::string &error) {
        const Platform::CommandResult result = Platform::RunCommandArgsResult("frida-ps", {"-D", serial});
        if (!result.Started) {
            error = "Could not run frida-ps. Install frida on the host (pip install frida-tools).";
            return {};
        }
        if (result.ExitCode != 0) {
            error = Trim(result.Output);
            return {};
        }
        return ParseFridaPs(result.Output);
    }

    // --------------------------------------------------------------- hook runner //

    namespace {
        void RunHookReader(
            const int outputFd,
            const std::shared_ptr<Platform::LogBuffer> &log,
            const std::shared_ptr<std::atomic<bool>> &stopFlag
        ) {
            std::array<char, 1024> buf{};
            std::string partial;
            const auto flushLines = [&](const char *data, const std::size_t n) {
                partial.append(data, n);
                std::size_t pos = 0;
                while ((pos = partial.find('\n')) != std::string::npos) {
                    if (const auto line = partial.substr(0, pos); !line.empty()) {
                        log->Push(line);
                    }
                    partial.erase(0, pos + 1);
                }
            };

            while (!stopFlag->load()) {
#ifdef _WIN32
                const auto handle = reinterpret_cast<HANDLE>(_get_osfhandle(outputFd));
                DWORD nRead = 0;
                if (ReadFile(handle, buf.data(), static_cast<DWORD>(buf.size()), &nRead, nullptr)) {
                    if (nRead > 0) {
                        flushLines(buf.data(), nRead);
                    } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                } else {
                    const DWORD err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) {
                        break;
                    }
                    if (err == ERROR_NO_DATA) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    } else {
                        break;
                    }
                }
#else
                if (const ssize_t n = read(outputFd, buf.data(), buf.size()); n > 0) {
                    flushLines(buf.data(), static_cast<std::size_t>(n));
                } else if (n == 0) {
                    break;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                } else {
                    break;
                }
#endif
            }

            if (!partial.empty()) {
                log->Push(partial);
            }
#ifdef _WIN32
            _close(outputFd);
#else
            close(outputFd);
#endif
        }
    }

    std::vector<FridaScript> BundledFridaScripts() {
        return {
            {"Method trace", "dev", "trace.js", "// Generic method tracer. Set TARGET to the class you want to trace.\n"
                                                "var TARGET = \"java.net.URL\";\n"
                                                "Java.perform(function () {\n"
                                                "    try {\n"
                                                "        var C = Java.use(TARGET);\n"
                                                "        C.class.getDeclaredMethods().forEach(function (m) {\n"
                                                "            var name = m.getName();\n"
                                                "            C[name].overloads.forEach(function (ov) {\n"
                                                "                ov.implementation = function () {\n"
                                                "                    console.log('[trace] ' + TARGET + '.' + name + '(' + "
                                                "Array.prototype.join.call(arguments, ', ') + ')');\n"
                                                "                    return ov.apply(this, arguments);\n"
                                                "                };\n"
                                                "            });\n"
                                                "        });\n"
                                                "        console.log('[trace] hooked ' + TARGET);\n"
                                                "    } catch (e) { console.log('[trace] error: ' + e); }\n"
                                                "});\n"},
            {"SQLite queries", "dev", "sqlite.js", "Java.perform(function () {\n"
                                                   "    var DB = Java.use('android.database.sqlite.SQLiteDatabase');\n"
                                                   "    DB.execSQL.overload('java.lang.String').implementation = function (sql) {\n"
                                                   "        console.log('[sqlite] execSQL: ' + sql);\n"
                                                   "        return this.execSQL(sql);\n"
                                                   "    };\n"
                                                   "    DB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = "
                                                   "function (sql, a) {\n"
                                                   "        console.log('[sqlite] rawQuery: ' + sql);\n"
                                                   "        return this.rawQuery(sql, a);\n"
                                                   "    };\n"
                                                   "    console.log('[sqlite] hooked SQLiteDatabase');\n"
                                                   "});\n"},
            {"Crypto (Cipher)", "dev", "crypto.js", "Java.perform(function () {\n"
                                                    "    var Cipher = Java.use('javax.crypto.Cipher');\n"
                                                    "    Cipher.doFinal.overload('[B').implementation = function (data) {\n"
                                                    "        console.log('[crypto] ' + this.getAlgorithm() + ' doFinal, ' + data.length + ' bytes');\n"
                                                    "        return this.doFinal(data);\n"
                                                    "    };\n"
                                                    "    console.log('[crypto] hooked javax.crypto.Cipher.doFinal');\n"
                                                    "});\n"},
            {"WebView", "dev", "webview.js", "Java.perform(function () {\n"
                                             "    var WV = Java.use('android.webkit.WebView');\n"
                                             "    WV.loadUrl.overload('java.lang.String').implementation = function (url) {\n"
                                             "        console.log('[webview] loadUrl: ' + url);\n"
                                             "        return this.loadUrl(url);\n"
                                             "    };\n"
                                             "    try {\n"
                                             "        WV.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback')"
                                             ".implementation = function (js, cb) {\n"
                                             "            console.log('[webview] evaluateJavascript: ' + js);\n"
                                             "            return this.evaluateJavascript(js, cb);\n"
                                             "        };\n"
                                             "    } catch (e) {}\n"
                                             "    console.log('[webview] hooked WebView');\n"
                                             "});\n"},
            {"SSL-pinning bypass", "sensitive", "ssl-bypass.js", "// SSL-pinning bypass for apps you are authorized to test.\n"
                                                                 "Java.perform(function () {\n"
                                                                 "    try {\n"
                                                                 "        var X509 = Java.use('javax.net.ssl.X509TrustManager');\n"
                                                                 "        var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
                                                                 "        var TM = Java.registerClass({ name: 'com.coredeck.TrustAll', implements: [X509],\n"
                                                                 "            methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {},\n"
                                                                 "                getAcceptedIssuers: function () { return []; } } });\n"
                                                                 "        var tms = [TM.$new()];\n"
                                                                 "        var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', "
                                                                 "'[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');\n"
                                                                 "        init.implementation = function (km, tm, sr) {\n"
                                                                 "            console.log('[ssl] SSLContext.init -> permissive');\n"
                                                                 "            init.call(this, km, tms, sr);\n"
                                                                 "        };\n"
                                                                 "    } catch (e) { console.log('[ssl] TrustManager: ' + e); }\n"
                                                                 "    try {\n"
                                                                 "        var CP = Java.use('okhttp3.CertificatePinner');\n"
                                                                 "        CP.check.overload('java.lang.String', 'java.util.List').implementation = function (host, p) "
                                                                 "{ console.log('[ssl] OkHttp pin bypassed: ' + host); };\n"
                                                                 "    } catch (e) {}\n"
                                                                 "    try {\n"
                                                                 "        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');\n"
                                                                 "        TMI.verifyChain.implementation = function (certs, ta, host, cc, o, t) {\n"
                                                                 "            console.log('[ssl] verifyChain bypassed: ' + host);\n"
                                                                 "            return certs;\n"
                                                                 "        };\n"
                                                                 "    } catch (e) {}\n"
                                                                 "    try {\n"
                                                                 "        var WVC = Java.use('android.webkit.WebViewClient');\n"
                                                                 "        WVC.onReceivedSslError.implementation = function (v, h, e) { h.proceed(); };\n"
                                                                 "    } catch (e) {}\n"
                                                                 "    console.log('[ssl] pinning bypass installed');\n"
                                                                 "});\n"},
            {"Root-detection bypass", "sensitive", "root-bypass.js", "// Root-detection bypass for apps you are authorized to test.\n"
                                                                     "Java.perform(function () {\n"
                                                                     "    var ROOT = ['/sbin/su','/system/bin/su','/system/xbin/su','/data/local/xbin/su',\n"
                                                                     "        '/data/local/bin/su','/system/sd/xbin/su','/system/bin/failsafe/su','/data/local/su',\n"
                                                                     "        '/su/bin/su','/system/app/Superuser.apk','/system/bin/magisk','/sbin/magisk'];\n"
                                                                     "    try {\n"
                                                                     "        var File = Java.use('java.io.File');\n"
                                                                     "        File.exists.implementation = function () {\n"
                                                                     "            var p = this.getAbsolutePath();\n"
                                                                     "            if (ROOT.indexOf(p) !== -1) { console.log('[root] hid ' + p); return false; }\n"
                                                                     "            return this.exists();\n"
                                                                     "        };\n"
                                                                     "    } catch (e) {}\n"
                                                                     "    try {\n"
                                                                     "        var Rt = Java.use('java.lang.Runtime');\n"
                                                                     "        Rt.exec.overload('java.lang.String').implementation = function (c) {\n"
                                                                     "            if (c.indexOf('su') !== -1 || c.indexOf('which') !== -1) {\n"
                                                                     "                console.log('[root] blocked exec: ' + c);\n"
                                                                     "                return this.exec('echo');\n"
                                                                     "            }\n"
                                                                     "            return this.exec(c);\n"
                                                                     "        };\n"
                                                                     "    } catch (e) {}\n"
                                                                     "    try { Java.use('android.os.Build').TAGS.value = 'release-keys'; } catch (e) {}\n"
                                                                     "    try {\n"
                                                                     "        var RB = Java.use('com.scottyab.rootbeer.RootBeer');\n"
                                                                     "        ['isRooted','isRootedWithoutBusyBoxCheck','checkForSu','detectRootManagementApps',\n"
                                                                     "         'checkForBinary','checkForDangerousProps','detectTestKeys'].forEach(function (m) {\n"
                                                                     "            try { RB[m].implementation = function () { return false; }; } catch (e) {}\n"
                                                                     "        });\n"
                                                                     "        console.log('[root] RootBeer neutralized');\n"
                                                                     "    } catch (e) {}\n"
                                                                     "    console.log('[root] root-detection bypass installed');\n"
                                                                     "});\n"},
        };
    }

    bool SaveFridaScript(
        const std::string &dir, const std::string &filename, const std::string &content, std::string &error
    ) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        const std::string path = Platform::JoinPaths({dir, filename});
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "Could not write " + path;
            return false;
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        return true;
    }

    std::vector<std::string> BuildFridaHookArgs(
        const std::string &serial, const std::string &package, const std::vector<std::string> &scriptPaths, const bool attach
    ) {
        std::vector<std::string> args;
        args.emplace_back("-D");
        args.push_back(serial);
        args.emplace_back(attach ? "-n" : "-f");
        args.push_back(package);
        for (const std::string &script: scriptPaths) {
            args.emplace_back("-l");
            args.push_back(script);
        }
        return args;
    }

    bool StartFridaHook(
        const std::string &serial,
        const std::string &package,
        const std::vector<std::string> &scriptPaths,
        const bool attach,
        FridaHookSession &session,
        std::string &error
    ) {
        if (package.empty()) {
            error = "Enter a target package.";
            return false;
        }
        if (scriptPaths.empty()) {
            error = "Select at least one script.";
            return false;
        }
        int outputFd = -1;
        const ProcessId pid =
            Platform::SpawnProcessWithPipe("frida", BuildFridaHookArgs(serial, package, scriptPaths, attach), outputFd);
#ifdef _WIN32
        if (pid == 0) {
#else
        if (pid <= 0) {
#endif
            error = "Could not start frida. Install the host frida tools (pip install frida-tools).";
            return false;
        }
        session.Log = std::make_shared<Platform::LogBuffer>();
        session.StopFlag = std::make_shared<std::atomic<bool>>(false);
        session.Pid = pid;
        session.Running = true;
        session.Reader = std::thread(RunHookReader, outputFd, session.Log, session.StopFlag);
        return true;
    }

    FridaHookSession::~FridaHookSession() {
        StopFridaHook(*this);
    }

    void StopFridaHook(FridaHookSession &session) {
        if (session.StopFlag) {
            session.StopFlag->store(true);
        }
        if (session.Running.load()) {
            Platform::TerminateProcessTree(session.Pid);
        }
        if (session.Reader.joinable()) {
            session.Reader.join();
        }
        session.Running = false;
    }
}
