using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Input;
using Common;
using Common.Models;
using Common.StructLayout;
using Common.Utility;
using Common.Wrappers;
using Microsoft.Toolkit.Mvvm.ComponentModel;
using Microsoft.Toolkit.Mvvm.Input;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Constants = Common.Utility.Constants;
using Utils = Common.Utility.Utils;

namespace ViewModelSwiftUi
{
    public class MainWindowViewModel : ObservableObject
    {
        private ObservableCollection<ServerInfoModel> _serverList;
        private ServerInfoModel _selectedServer;
        private Utils _utils;

        public ICommand PatchBootCommand { get; set; }

        public MainWindowViewModel()
        {
            _utils = Utils.Instance;
            PatchBootCommand = new RelayCommand(PatchBootTask);

            if (!File.Exists($"{AppDomain.CurrentDomain.BaseDirectory}ServerList.json"))
            {
                string tempJson = @"
{
  ""ServerList"":[
    {
      ""ServerName"":""local"",
      ""PatchServerAddress"":""localhost"",
      ""PatchServerPort"":""54996"",
      ""LoginServerAddress"":""http://localhost:8081"",
      ""LobbyServerAddress"":""localhost""
    }
]
}";
                File.WriteAllText(tempJson, $"{AppDomain.CurrentDomain.BaseDirectory}ServerList.json");
            }

            _serverList =
                JObject.Parse(File.ReadAllText($"{AppDomain.CurrentDomain.BaseDirectory}ServerList.json"))[
                        "ServerList"]!
                    .ToObject<ObservableCollection<ServerInfoModel>>()!;

            if (_serverList.Count > 0)
                _selectedServer = _serverList[0];
        }

        public ObservableCollection<ServerInfoModel> ServerList
        {
            get => _serverList;
            set => _serverList = value ?? throw new ArgumentNullException(nameof(value));
        }

        public ServerInfoModel SelectedServer
        {
            get => _selectedServer;
            set => _selectedServer = value ?? throw new ArgumentNullException(nameof(value));
        }

        private void PatchBootTask()
        {

            string gameDir = _utils.GameInstallLocation();

            File.WriteAllText($"{gameDir}\\SelectedServer.json", JsonConvert.SerializeObject(_selectedServer));
            File.Copy($"{Directory.GetCurrentDirectory()}\\ApiHooks.dll", $"{gameDir}\\ApiHooks.dll", true);
            string exePath = $"{Directory.GetCurrentDirectory()}\\NovumLauncher.exe";
            Registry.SetValue($"{Constants.ImageExecutionOptions}\\ffxivlogin.exe", "debugger", exePath);
            Registry.SetValue($"{Constants.ImageExecutionOptions}\\ffxivgame.exe", "debugger", exePath);
            BootPatching bootPatching = new(_selectedServer);
            if (bootPatching.LaunchBoot())
            {

            }
        }
    }
    public interface IBootOffSet
    {

        public int GetRsaFunctionOffSet();
        public int GetRsaPatternOffset();
        public int GetLobbyOffset();
        public int GetHostNamePortOffset();
        public int GetHostNameOffset();
        public int GetSecureSquareEnixOffset();
    }
    public class BootUpdatedVersionOffset : IBootOffSet
    {
        public int GetRsaFunctionOffSet()
        {
            return 0x64310;
        }

        public int GetRsaPatternOffset()
        {
            return 0x646EC;
        }

        public int GetLobbyOffset()
        {
            return 0x965D08;
        }

        public int GetHostNamePortOffset()
        {
            return 0x9663FC;
        }

        public int GetHostNameOffset()
        {
            return 0x966404;
        }

        public int GetSecureSquareEnixOffset()
        {
            return 0x99212C;
        }
    }
    public class BootInstalledVersionOffset : IBootOffSet
    {
        public int GetRsaFunctionOffSet()
        {
            return 0x5DF50;
        }

        public int GetRsaPatternOffset()
        {
            return 0x5e32C;
        }

        public int GetLobbyOffset()
        {
            return 0x8E5C6C;
        }

        public int GetHostNamePortOffset()
        {
            return 0x8E62D4;
        }

        public int GetHostNameOffset()
        {
            return 0x8E62DC;
        }

        public int GetSecureSquareEnixOffset()
        {
            return 0x90A4A0;
        }
    }
    public class BootPatching
    {
        private readonly ServerInfoModel _serverInfoModel;
        private readonly Utils _utils;

        public BootPatching(ServerInfoModel serverInfoModel)
        {
            _serverInfoModel = serverInfoModel;
            _utils = Utils.Instance;
        }

        public bool LaunchBoot()
        {
            string workingDirectory = _utils.GameInstallLocation();
            string bootPath = $"{workingDirectory}\\ffxivboot.exe";

            string latestBootVersion = GetLatestBootVersionString(workingDirectory, _serverInfoModel.PatchServerAddress, _serverInfoModel.PatchServerPort);
            File.WriteAllText($"{workingDirectory}\\boot.ver", latestBootVersion);

            CreateProcessWrapper createProcessWrapper = new(bootPath);

            if (!ApplyPatchesToMemory(createProcessWrapper.PInfo.hProcess,
                    createProcessWrapper.PInfo.hThread, _serverInfoModel.PatchServerAddress, _serverInfoModel.PatchServerPort))
            {
                throw new Exception("Error while patching");
            }

            return true;
        }

        private bool ApplyPatchesToBinary(string bootPath, string workingDirectory, string patchServerAddress,
            string patchServerPort)
        {
            //Make Backup of current ffxivboot.exe
            Directory.CreateDirectory($"{workingDirectory}\\backup");
            File.Copy(bootPath, $"{workingDirectory}\\backup\\ffxivboot.exe", true);

            byte[] patchServerBytes = Encoding.Default.GetBytes(patchServerAddress + char.MinValue);
            byte[] patchPortBytes = Encoding.Default.GetBytes(patchServerPort + char.MinValue);
            byte[] patchServerWithPort =
                Encoding.Default.GetBytes($"{patchServerAddress}:{patchServerPort}" + char.MinValue);

            IBootOffSet bootOffSet = new BootInstalledVersionOffset();
            byte[] bootData = File.ReadAllBytes(bootPath);

            using MemoryStream memoryStream = new MemoryStream(bootData);
            // using MemoryStream modifiedMemoryStream = new MemoryStream();

            memoryStream.Seek(bootOffSet.GetRsaFunctionOffSet(), SeekOrigin.Begin);
            memoryStream.Write(Constants.RsaFunctionPatch, 0, Constants.RsaFunctionPatch.Length);

            memoryStream.Seek(bootOffSet.GetRsaPatternOffset(), SeekOrigin.Begin);
            memoryStream.Write(Constants.RsaPatternPatch, 0, Constants.RsaPatternPatch.Length);

            memoryStream.Seek(bootOffSet.GetLobbyOffset(), SeekOrigin.Begin);
            memoryStream.Write(patchServerBytes, 0, patchServerBytes.Length);

            memoryStream.Seek(bootOffSet.GetHostNameOffset(), SeekOrigin.Begin);
            memoryStream.Write(patchServerBytes, 0, patchServerBytes.Length);

            memoryStream.Seek(bootOffSet.GetHostNamePortOffset(), SeekOrigin.Begin);
            memoryStream.Write(patchPortBytes, 0, patchPortBytes.Length);

            memoryStream.Seek(bootOffSet.GetSecureSquareEnixOffset(), SeekOrigin.Begin);
            memoryStream.Write(patchServerWithPort, 0, patchServerWithPort.Length);

            File.WriteAllBytes(bootPath, bootData);

            string latestBootVersion = GetLatestBootVersionString(workingDirectory, patchServerAddress, patchServerPort);
            File.WriteAllText($"{workingDirectory}\\boot.ver", latestBootVersion);

            CreateProcessWrapper createProcessWrapper = new(bootPath);
            NativeMethods.ResumeThread(createProcessWrapper.PInfo.hThread);
            NativeMethods.CloseHandle(createProcessWrapper.PInfo.hProcess);
            NativeMethods.CloseHandle(createProcessWrapper.PInfo.hThread);

            return true;
        }

        private bool ApplyPatchesToMemory(IntPtr hProcess, IntPtr hThread, string patchServerAddress,
            string patchServerPort)
        {
            byte[] patchServerBytes = Encoding.Default.GetBytes(patchServerAddress);
            byte[] patchPortBytes = Encoding.Default.GetBytes(patchServerPort);
            byte[] patchServerWithPort = Encoding.Default.GetBytes($"{patchServerAddress}:{patchServerPort}");

            CONTEXT threadContext = new()
            {
                ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_FULL
            };

            IBootOffSet bootOffSet;

            if (!NativeMethods.GetThreadContext(hThread, ref threadContext))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr imageBaseAddressPtr = new(threadContext.Ebx + 8);

            MemoryAccessWrapper.ReadProcessMemory(hProcess, imageBaseAddressPtr, out IntPtr imageBaseAddress, 4,
                out IntPtr _);

            if (IsBootUpdatedVersion(hProcess, imageBaseAddress))
            {
                bootOffSet = new BootUpdatedVersionOffset();
            }
            else
            {
                bootOffSet = new BootInstalledVersionOffset();
            }

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetRsaFunctionOffSet()),
                Constants.RsaFunctionPatch,
                Constants.RsaFunctionPatch.Length);

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetRsaPatternOffset()),
                Constants.RsaPatternPatch,
                Constants.RsaPatternPatch.Length);

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetLobbyOffset()), patchServerBytes,
                patchServerBytes.Length + 1);

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetHostNameOffset()), patchServerBytes,
                patchServerBytes.Length + 1);

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetHostNamePortOffset()), patchPortBytes,
                patchPortBytes.Length + 1);

            _utils.WriteToMemory(hProcess, IntPtr.Add(imageBaseAddress, bootOffSet.GetSecureSquareEnixOffset()),
                patchServerWithPort,
                patchServerWithPort.Length + 1);

            NativeMethods.ResumeThread(hThread);
            NativeMethods.CloseHandle(hProcess);
            NativeMethods.CloseHandle(hThread);

            return true;
        }

        private bool IsBootUpdatedVersion(IntPtr hProcess, IntPtr address)
        {
            byte[] buffer = new byte[7];

            MemoryAccessWrapper.ReadProcessMemory(hProcess, IntPtr.Add(address, 0x646EC), buffer, 7,
                out IntPtr _);

            if (buffer.Length == Constants.OriginalRsaSign.Length &&
                NativeMethods.memcmp(buffer, Constants.OriginalRsaSign, buffer.Length) == 0)
            {
                return true;
            }

            // check if it's not the patched binary one 
            if (buffer.Length == Constants.RsaPatternPatch.Length &&
                NativeMethods.memcmp(buffer, Constants.OriginalRsaSign, buffer.Length) == 0)
            {
                return true;
            }

            return false;
        }

        /*private void GetPatchingMethod(string bootPath, string workingDirectory)
        {
            string sha1Value = _utils.GetSha1Hash(bootPath);

            if (string.Equals(sha1Value, Constants.BootSha1InstallVersion, StringComparison.OrdinalIgnoreCase))
            {
                return PatchingMethod.BinaryPatching;
            }

            if (File.Exists($"{workingDirectory}\\boot.ver"))
            {
                string bootVer = File.ReadAllText($"{workingDirectory}\\boot.ver");

                if (string.Equals(bootVer.Trim(), "2010.07.10.0000"))
                {
                    if (!File.Exists($"{workingDirectory}\\backup\\ffxivboot.exe"))
                    {
                        throw new Exception(
                            $"The Backup ffxivboot.exe does not exist {workingDirectory}\\backup\\ffxivboot.exe \n Reinstalling the game might be required");
                    }

                    sha1Value = _utils.GetSha1Hash($"{workingDirectory}\\backup\\ffxivboot.exe");
                    if (string.Equals(sha1Value, Constants.BootSha1InstallVersion, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Copy($"{workingDirectory}\\backup\\ffxivboot.exe", $"{workingDirectory}\\ffxivboot.exe", true);
                        return PatchingMethod.BinaryPatching;
                    }
                    else
                    {
                        throw new Exception(
                            $"The {workingDirectory}\\backup\\ffxivboot.exe \n is not the original one,Reinstalling the game might be required");
                    }
                }
            }

            return PatchingMethod.MemoryPatching;
        }*/

        private string GetLatestBootVersionString(string workingDirectory, string hostAddress, string hostPort)
        {
            string bootVer = File.ReadAllText($"{workingDirectory}\\boot.ver");
            string url = $"http://{hostAddress}:{hostPort}/patch/vercheck/ffxiv/win32/release/boot/{bootVer.Trim()}";

            try
            {
                using HttpClient client = new();
                HttpResponseMessage httpResponseMessage = client.GetAsync(url).Result;

                httpResponseMessage.Headers.TryGetValues("X-Latest-Version", out IEnumerable<string>? latesetVersion);

                if (latesetVersion != null) return latesetVersion.First();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

            return "2010.09.18.0000";
        }
    }
}