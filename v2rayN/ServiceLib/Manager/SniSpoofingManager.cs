namespace ServiceLib.Manager;

/// <summary>
/// Hosts the official Patterniha SNI-Spoofing source runtime. It is deliberately
/// separate from the proxy core: the upstream implementation uses WinDivert to
/// observe the TCP handshake and inject its wrong-sequence ClientHello.
/// </summary>
public sealed class SniSpoofingManager
{
    private const string EngineFolder = "sni-spoofing";
    private static string EngineExe => Utils.IsWindows() ? "sni-spoofing.exe" : "sni-spoofing-py";
    private static string EngineRustExe => Utils.IsWindows() ? "sni-spoof-rs.exe" : "sni-spoof-rs";
    private static string EngineGoExe => Utils.IsWindows() ? "sni-spoof-go.exe" : "sni-spoofing";
    private const string EngineScript = "main.py";
    private static readonly Lazy<SniSpoofingManager> _instance = new(() => new());
    public static SniSpoofingManager Instance => _instance.Value;

    private ProcessService? _process;
    private bool _isRunning;
    private string _activeProfileId = string.Empty;
    private string? _runningTargetIp;
    private int _runningTargetPort;
    private string? _runningEngine;

    public static bool CanUse(ProfileItem node)
    {
        return IsSupported(node)
               && Instance._isRunning
               && (Instance._activeProfileId.IsNullOrEmpty() || node.IndexId == Instance._activeProfileId);
    }

    public static bool IsSupported(ProfileItem? node)
    {
        var setting = AppManager.Instance.Config.SniSpoofingItem;
        if (!setting.Enabled)
        {
            return false;
        }
        if (!File.Exists(GetRustExePath()) && !File.Exists(GetGoExePath()) && !File.Exists(GetExePath()) && !File.Exists(GetScriptPath()))
        {
            return false;
        }
        if (node == null)
        {
            return true;
        }
        return node.ConfigType is EConfigType.VMess or EConfigType.VLESS or EConfigType.Trojan
               && (node.StreamSecurity == Global.StreamSecurity || node.Address == Global.Loopback);
    }

    public static string GetOutboundAddress(ProfileItem node) => CanUse(node) ? Global.Loopback : node.Address;

    public static int GetOutboundPort(ProfileItem node) => CanUse(node) ? AppManager.Instance.Config.SniSpoofingItem.ListenPort : node.Port;

    public async Task<bool> StartAsync(ProfileItem? node = null, Func<bool, string, Task>? updateFunc = null)
    {
        var setting = AppManager.Instance.Config.SniSpoofingItem;
        if (!setting.Enabled)
        {
            await StopAsync();
            return true;
        }

        if (node != null && !IsSupported(node))
        {
            return true;
        }

        var rustExePath = GetRustExePath();
        var goExePath = GetGoExePath();
        var pyExePath = GetExePath();
        var scriptPath = GetScriptPath();

        var wantsGo = setting.Engine.Equals("Go", StringComparison.OrdinalIgnoreCase);
        var wantsPython = setting.Engine.Equals("Python", StringComparison.OrdinalIgnoreCase);
        var wantsRust = !wantsGo && !wantsPython;

        string activeEngine;
        if (wantsGo)
        {
            activeEngine = "Go";
        }
        else if (wantsPython)
        {
            activeEngine = "Python";
        }
        else
        {
            activeEngine = "Rust";
        }

        if (activeEngine == "Rust" && !File.Exists(rustExePath))
        {
            await SafeNotifyAsync(updateFunc, true, $"Rust SNI Spoofing engine ({EngineRustExe}) was not found in bin/sni-spoofing.");
            return false;
        }
        if (activeEngine == "Go" && !File.Exists(goExePath))
        {
            await SafeNotifyAsync(updateFunc, true, $"Go SNI Spoofing engine ({EngineGoExe}) was not found in bin/sni-spoofing.");
            return false;
        }
        if (activeEngine == "Python" && !File.Exists(pyExePath) && !File.Exists(scriptPath))
        {
            await SafeNotifyAsync(updateFunc, true, "Python SNI Spoofing engine was not found in bin/sni-spoofing.");
            return false;
        }

        if (Utils.IsWindows() && !Utils.IsAdministrator())
        {
            await SafeNotifyAsync(updateFunc, true, "SNI Spoofing requires MehrON to run as administrator. Approve the Windows prompt to continue.");
            if (ProcUtils.RebootAsAdmin())
            {
                await AppManager.Instance.AppExitAsync(true);
            }
            return false;
        }

        var targetIp = !setting.ConnectIp.IsNullOrEmpty()
            ? setting.ConnectIp.Trim()
            : (node != null && node.Address != Global.Loopback ? await ResolveIpv4Async(node.Address) : "188.114.98.0");

        if (string.IsNullOrEmpty(targetIp))
        {
            targetIp = "188.114.98.0";
        }

        var targetPort = !setting.ConnectIp.IsNullOrEmpty() && setting.ConnectPort is > 0 and <= 65535
            ? setting.ConnectPort
            : (node != null && node.Port > 0 ? node.Port : (setting.ConnectPort > 0 ? setting.ConnectPort : 443));

        if (_isRunning && _process != null && !_process.HasExited && _runningTargetIp == targetIp && _runningTargetPort == targetPort && _runningEngine == activeEngine)
        {
            if (node != null)
            {
                _activeProfileId = node.IndexId;
            }
            return true;
        }

        await StopAsync();
        KillLingeringProcesses();
        EnsureDriverInstalled();

        var folder = GetEngineDirectory();
        var configPath = Path.Combine(folder, "config.json");

        if (activeEngine == "Rust")
        {
            var rustConfig = new
            {
                graceful_shutdown_sec = 0,
                listeners = new[]
                {
                    new
                    {
                        listen = $"{setting.ListenHost}:{setting.ListenPort}",
                        connect = $"{targetIp}:{targetPort}",
                        fake_sni = setting.FakeSni,
                        conn_timeout_sec = 5,
                        handshake_timeout_sec = 2,
                        keepalive_time_sec = 11,
                        keepalive_interval_sec = 2
                    }
                }
            };
            var content = JsonSerializer.Serialize(rustConfig, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(configPath, content);
            _process = new ProcessService(rustExePath, $"\"{configPath}\"", folder, true, false, null, updateFunc);
        }
        else if (activeEngine == "Go")
        {
            var goArgs = $"-listen \"{setting.ListenHost}:{setting.ListenPort}\" -connect \"{targetIp}:{targetPort}\" -fake-sni \"{setting.FakeSni}\" -utls chrome";
            _process = new ProcessService(goExePath, goArgs, folder, true, false, null, updateFunc);
        }
        else
        {
            var pythonConfig = new Dictionary<string, object>
            {
                ["LISTEN_HOST"] = setting.ListenHost,
                ["LISTEN_PORT"] = setting.ListenPort,
                ["CONNECT_IP"] = targetIp,
                ["CONNECT_PORT"] = targetPort,
                ["FAKE_SNI"] = setting.FakeSni,
            };
            var content = JsonSerializer.Serialize(pythonConfig, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(configPath, content);

            if (File.Exists(pyExePath))
            {
                _process = new ProcessService(pyExePath, string.Empty, folder, true, false, null, updateFunc);
            }
            else if (File.Exists(scriptPath))
            {
                _process = new ProcessService(GetPythonExecutable(), "-X utf8 main.py", folder, true, false, null, updateFunc);
            }
        }

        try
        {
            await _process.StartAsync();
            for (var i = 0; i < 15; i++)
            {
                await Task.Delay(100);
                if (_process.HasExited)
                {
                    throw new InvalidOperationException($"The SNI Spoofing {activeEngine} engine exited unexpectedly.");
                }
            }

            _isRunning = true;
            _runningTargetIp = targetIp;
            _runningTargetPort = targetPort;
            _runningEngine = activeEngine;
            _activeProfileId = node?.IndexId ?? string.Empty;
            await SafeNotifyAsync(updateFunc, false, $"SNI Spoofing ({activeEngine}) enabled: {setting.ListenHost}:{setting.ListenPort} → {targetIp}:{targetPort}");
            return true;
        }
        catch (Win32Exception winEx) when (winEx.NativeErrorCode == 740)
        {
            try
            {
                var targetExe = activeEngine == "Rust" ? rustExePath : (activeEngine == "Go" ? goExePath : (File.Exists(pyExePath) ? pyExePath : GetPythonExecutable()));
                var targetArgs = activeEngine == "Rust" ? $"\"{configPath}\"" : (activeEngine == "Go" ? $"-listen \"{setting.ListenHost}:{setting.ListenPort}\" -connect \"{targetIp}:{targetPort}\" -fake-sni \"{setting.FakeSni}\" -utls chrome" : (File.Exists(pyExePath) ? string.Empty : "-X utf8 main.py"));
                var psi = new ProcessStartInfo
                {
                    FileName = targetExe,
                    Arguments = targetArgs,
                    WorkingDirectory = folder,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                };
                Process.Start(psi);
                _isRunning = true;
                _runningTargetIp = targetIp;
                _runningTargetPort = targetPort;
                _runningEngine = activeEngine;
                _activeProfileId = node?.IndexId ?? string.Empty;
                await SafeNotifyAsync(updateFunc, false, $"SNI Spoofing ({activeEngine}) enabled: {setting.ListenHost}:{setting.ListenPort} → {targetIp}:{targetPort}");
                return true;
            }
            catch (Exception ex)
            {
                Logging.SaveLog(nameof(SniSpoofingManager), ex);
                await StopAsync();
                await SafeNotifyAsync(updateFunc, true, $"Failed to start SNI Spoofing: {ex.Message}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(SniSpoofingManager), ex);
            await StopAsync();
            await SafeNotifyAsync(updateFunc, true, $"Failed to start SNI Spoofing: {ex.Message}");
            return false;
        }
    }

    public async Task StopAsync()
    {
        _isRunning = false;
        _runningTargetIp = null;
        _runningTargetPort = 0;
        _runningEngine = null;
        _activeProfileId = string.Empty;
        if (_process != null)
        {
            await _process.StopAsync();
            _process.Dispose();
            _process = null;
        }
        KillLingeringProcesses();
        await CleanupWinDivertAsync();
    }

    private static void EnsureDriverInstalled()
    {
        if (!Utils.IsWindows())
        {
            return;
        }
        try
        {
            var folder = GetEngineDirectory();
            var candidates = new[]
            {
                Path.Combine(folder, "WinDivert64.sys"),
                Path.Combine(folder, "_internal", "pydivert", "windivert_dll", "WinDivert64.sys"),
                Path.Combine(folder, "WinDivert.sys"),
                Path.Combine(folder, "_internal", "pydivert", "windivert_dll", "WinDivert.sys")
            };
            var source = candidates.FirstOrDefault(File.Exists);
            if (source != null)
            {
                var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var driversDir = Path.Combine(system32, "drivers");
                var driverDest = Path.Combine(driversDir, "WinDivert64.sys");
                try
                {
                    if (Directory.Exists(driversDir) && (!File.Exists(driverDest) || new FileInfo(source).Length != new FileInfo(driverDest).Length))
                    {
                        File.Copy(source, driverDest, true);
                    }
                }
                catch { }

                var sc = Path.Combine(system32, "sc.exe");
                if (File.Exists(sc))
                {
                    var driverPath = File.Exists(driverDest) ? driverDest : source;
                    var quoted = $"\"{driverPath}\"";
                    RunScCommand(sc, $"create WinDivert binPath= {quoted} type= kernel");
                    RunScCommand(sc, $"config WinDivert binPath= {quoted} type= kernel");
                    RunScCommand(sc, "start WinDivert");
                }
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(SniSpoofingManager), ex);
        }
    }

    private static void KillLingeringProcesses()
    {
        try
        {
            foreach (var name in new[] { "sni-spoofing", "sni-spoof-rs", "sni-spoofing-py" })
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        p.Kill(true);
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void RunScCommand(string scPath, string args)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = scPath,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
            proc.Start();
            proc.WaitForExit(3000);
        }
        catch { }
    }

    private static async Task SafeNotifyAsync(Func<bool, string, Task>? updateFunc, bool notify, string msg)
    {
        if (updateFunc == null)
        {
            return;
        }
        try
        {
            await updateFunc(notify, msg);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(SniSpoofingManager), ex);
        }
    }

    private static async Task CleanupWinDivertAsync()
    {
        if (!Utils.IsWindows())
        {
            return;
        }
        try
        {
            var sc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe");
            if (File.Exists(sc))
            {
                RunScCommand(sc, "stop WinDivert");
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(nameof(SniSpoofingManager), ex);
        }
        await Task.CompletedTask;
    }

    private static async Task<string?> ResolveIpv4Async(string address)
    {
        if (IPAddress.TryParse(address, out var parsed))
        {
            return parsed.AddressFamily == AddressFamily.InterNetwork ? parsed.ToString() : null;
        }
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(address);
            return addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static string GetEngineDirectory() => Utils.GetBinPath(EngineFolder);
    private static string GetExePath() => Path.Combine(GetEngineDirectory(), EngineExe);
    private static string GetRustExePath() => Path.Combine(GetEngineDirectory(), EngineRustExe);
    private static string GetGoExePath() => Path.Combine(GetEngineDirectory(), EngineGoExe);
    private static string GetScriptPath() => Path.Combine(GetEngineDirectory(), EngineScript);
    private static string GetPythonExecutable()
    {
        if (Utils.IsWindows())
        {
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var searchPaths = new List<string>
            {
                Path.Combine(progFiles, "PyManager", "python.exe"),
                Path.Combine(localApp, "Programs", "Python"),
                Path.Combine(localApp, "Python"),
                Path.Combine(progFiles, "Python")
            };

            foreach (var path in searchPaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
                if (Directory.Exists(path))
                {
                    var py = Directory.GetDirectories(path, "*python*", SearchOption.TopDirectoryOnly)
                        .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "python.exe"))
                        .FirstOrDefault(File.Exists);
                    if (!string.IsNullOrEmpty(py))
                    {
                        return py;
                    }
                }
            }
        }
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            var candidates = new[] { "/usr/local/bin/python3", "/opt/homebrew/bin/python3", "/usr/bin/python3" };
            foreach (var cand in candidates)
            {
                if (File.Exists(cand)) return cand;
            }
            return "python3";
        }
        return "python";
    }
}
