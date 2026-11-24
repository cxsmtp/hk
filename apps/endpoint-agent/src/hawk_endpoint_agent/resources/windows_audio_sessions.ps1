param(
  [string]$format = "text"
)

$ErrorActionPreference = "Stop"

$source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace HawkAudioSessions {
  public enum EDataFlow {
    eRender = 0,
    eCapture = 1,
    eAll = 2
  }

  public enum ERole {
    eConsole = 0,
    eMultimedia = 1,
    eCommunications = 2
  }

  public enum AudioSessionState {
    AudioSessionStateInactive = 0,
    AudioSessionStateActive = 1,
    AudioSessionStateExpired = 2
  }

  [ComImport]
  [Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
  public class MMDeviceEnumerator {}

  [ComImport]
  [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMDeviceEnumerator {
    int EnumAudioEndpoints(EDataFlow dataFlow, int dwStateMask, out object ppDevices);
    int GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, out IMMDevice ppEndpoint);
  }

  [ComImport]
  [Guid("D666063F-1587-4E43-81F1-B948E807363F")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IMMDevice {
    int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, out object ppInterface);
  }

  [ComImport]
  [Guid("77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioSessionManager2 {
    int GetAudioSessionControl(IntPtr AudioSessionGuid, int StreamFlags, out object SessionControl);
    int GetSimpleAudioVolume(IntPtr AudioSessionGuid, int StreamFlags, out object AudioVolume);
    int GetSessionEnumerator(out IAudioSessionEnumerator SessionEnum);
  }

  [ComImport]
  [Guid("E2F5BB11-0570-40CA-ACDD-3AA01277DEE8")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioSessionEnumerator {
    int GetCount(out int SessionCount);
    int GetSession(int SessionCount, out IAudioSessionControl Session);
  }

  [ComImport]
  [Guid("F4B1A599-7266-4319-A8CA-E70ACB11E8CD")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioSessionControl {
    int GetState(out AudioSessionState pRetVal);
    int GetDisplayName(out IntPtr pRetVal);
    int SetDisplayName(string Value, ref Guid EventContext);
    int GetIconPath(out IntPtr pRetVal);
    int SetIconPath(string Value, ref Guid EventContext);
    int GetGroupingParam(out Guid pRetVal);
    int SetGroupingParam(ref Guid Override, ref Guid EventContext);
    int RegisterAudioSessionNotification(IntPtr NewNotifications);
    int UnregisterAudioSessionNotification(IntPtr NewNotifications);
  }

  [ComImport]
  [Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D")]
  [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IAudioSessionControl2 {
    int GetState(out AudioSessionState pRetVal);
    int GetDisplayName(out IntPtr pRetVal);
    int SetDisplayName(string Value, ref Guid EventContext);
    int GetIconPath(out IntPtr pRetVal);
    int SetIconPath(string Value, ref Guid EventContext);
    int GetGroupingParam(out Guid pRetVal);
    int SetGroupingParam(ref Guid Override, ref Guid EventContext);
    int RegisterAudioSessionNotification(IntPtr NewNotifications);
    int UnregisterAudioSessionNotification(IntPtr NewNotifications);
    int GetSessionIdentifier(out IntPtr pRetVal);
    int GetSessionInstanceIdentifier(out IntPtr pRetVal);
    int GetProcessId(out uint pRetVal);
    int IsSystemSoundsSession();
    int SetDuckingPreference(bool optOut);
  }

  public class SessionInfo {
    public uint ProcessId;
    public string ProcessName;
    public bool IsRecording;
  }

  public static class CaptureSessionReader {
    public static List<SessionInfo> GetActiveCaptureSessions() {
      var output = new List<SessionInfo>();
      var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
      IMMDevice device;
      int hr = enumerator.GetDefaultAudioEndpoint(EDataFlow.eCapture, ERole.eCommunications, out device);
      if (hr != 0 || device == null) {
        hr = enumerator.GetDefaultAudioEndpoint(EDataFlow.eCapture, ERole.eMultimedia, out device);
      }
      if (hr != 0 || device == null) {
        return output;
      }

      Guid iid = typeof(IAudioSessionManager2).GUID;
      object managerObj;
      hr = device.Activate(ref iid, 23, IntPtr.Zero, out managerObj);
      if (hr != 0 || managerObj == null) {
        return output;
      }

      var manager = (IAudioSessionManager2)managerObj;
      IAudioSessionEnumerator sessionEnumerator;
      hr = manager.GetSessionEnumerator(out sessionEnumerator);
      if (hr != 0 || sessionEnumerator == null) {
        return output;
      }

      int count;
      sessionEnumerator.GetCount(out count);
      for (int i = 0; i < count; i++) {
        IAudioSessionControl session;
        if (sessionEnumerator.GetSession(i, out session) != 0 || session == null) {
          continue;
        }
        AudioSessionState state;
        if (session.GetState(out state) != 0 || state != AudioSessionState.AudioSessionStateActive) {
          continue;
        }
        var session2 = session as IAudioSessionControl2;
        if (session2 == null) {
          continue;
        }
        uint pid;
        if (session2.GetProcessId(out pid) != 0 || pid == 0) {
          continue;
        }
        string name = "";
        try {
          name = Process.GetProcessById((int)pid).ProcessName;
        } catch {
          name = "unknown";
        }
        output.Add(new SessionInfo {
          ProcessId = pid,
          ProcessName = name,
          IsRecording = true
        });
      }
      return output;
    }
  }
}
"@

if (-not ("HawkAudioSessions.CaptureSessionReader" -as [type])) {
  Add-Type -TypeDefinition $source -Language CSharp
}

$sessions = [HawkAudioSessions.CaptureSessionReader]::GetActiveCaptureSessions()

if ($format -eq "json") {
  $sessions | ConvertTo-Json -Compress
  exit 0
}

"ProcessId ProcessName IsRecording"
foreach ($session in $sessions) {
  "{0} {1} {2}" -f $session.ProcessId, $session.ProcessName, $session.IsRecording
}
