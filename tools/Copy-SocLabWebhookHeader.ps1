#requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateRange(30,300)][int]$ClearAfterSeconds = 120,
    [string]$SecretRoot = '',
    [string]$ConfirmCopy = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'automation\SocLab.Security.psm1') -Force

Write-Host 'SOC Webhook Header protected clipboard preview'
Write-Host 'The DPAPI value is copied only after explicit confirmation.'
Write-Host 'Windows Clipboard History and Cloud Clipboard exclusion metadata is applied.'
Write-Host "The clipboard is cleared after $ClearAfterSeconds seconds only if it still contains this value."
Write-Host 'No plaintext value is printed or persisted by this command.'
if ($ConfirmCopy -cne 'COPY SOC HEADER TO CLIPBOARD') {
    throw "Preview only. Re-run with -ConfirmCopy 'COPY SOC HEADER TO CLIPBOARD'."
}

if (-not ('SocLabProtectedClipboard' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

public static class SocLabProtectedClipboard
{
    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr owner);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint RegisterClipboardFormat(string format);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint format, IntPtr memory);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint format);
    [DllImport("user32.dll")]
    private static extern bool IsClipboardFormatAvailable(uint format);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);

    private static void OpenWithRetry()
    {
        for (int attempt = 0; attempt < 20; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero)) return;
            Thread.Sleep(25);
        }
        throw new Win32Exception(Marshal.GetLastWin32Error(), "The Windows clipboard is busy.");
    }

    private static IntPtr Allocate(byte[] bytes)
    {
        IntPtr handle = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)bytes.Length);
        if (handle == IntPtr.Zero) throw new OutOfMemoryException();
        IntPtr pointer = GlobalLock(handle);
        if (pointer == IntPtr.Zero)
        {
            GlobalFree(handle);
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try { Marshal.Copy(bytes, 0, pointer, bytes.Length); }
        finally { GlobalUnlock(handle); }
        return handle;
    }

    public static void SetSecretText(string value)
    {
        if (String.IsNullOrEmpty(value)) throw new ArgumentException("Secret text is empty.");
        byte[] textBytes = System.Text.Encoding.Unicode.GetBytes(value + "\0");
        IntPtr exclusionHandle = IntPtr.Zero;
        IntPtr textHandle = IntPtr.Zero;
        OpenWithRetry();
        try
        {
            if (!EmptyClipboard()) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint exclusionFormat = RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing");
            if (exclusionFormat == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            exclusionHandle = Allocate(new byte[] { 1 });
            if (SetClipboardData(exclusionFormat, exclusionHandle) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            exclusionHandle = IntPtr.Zero;
            textHandle = Allocate(textBytes);
            if (SetClipboardData(CF_UNICODETEXT, textHandle) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            textHandle = IntPtr.Zero;
        }
        finally
        {
            if (exclusionHandle != IntPtr.Zero) GlobalFree(exclusionHandle);
            if (textHandle != IntPtr.Zero) GlobalFree(textHandle);
            Array.Clear(textBytes, 0, textBytes.Length);
            CloseClipboard();
        }
    }

    public static bool ClearIfMatches(string expected)
    {
        OpenWithRetry();
        try
        {
            if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return false;
            IntPtr handle = GetClipboardData(CF_UNICODETEXT);
            if (handle == IntPtr.Zero) return false;
            IntPtr pointer = GlobalLock(handle);
            if (pointer == IntPtr.Zero) return false;
            string current;
            try { current = Marshal.PtrToStringUni(pointer); }
            finally { GlobalUnlock(handle); }
            if (!String.Equals(current, expected, StringComparison.Ordinal)) return false;
            if (!EmptyClipboard()) throw new Win32Exception(Marshal.GetLastWin32Error());
            return true;
        }
        finally { CloseClipboard(); }
    }
}
'@
}

$secret = $null
try {
    $secret = Unprotect-SocSecret -Name 'shuffle_webhook_header_key' `
        -SecretRoot $SecretRoot
    if ($secret -cnotmatch '^[A-Za-z0-9.*+?-]{24,128}$') {
        throw 'The protected Shuffle Webhook Header value is invalid.'
    }
    [SocLabProtectedClipboard]::SetSecretText($secret)
    Write-Host 'SOC_WEBHOOK_HEADER_CLIPBOARD_READY=yes'
    Write-Host 'Paste it only into the Shuffle Trigger required Header value now.'
    Start-Sleep -Seconds $ClearAfterSeconds
} finally {
    if ($secret) {
        $cleared = [SocLabProtectedClipboard]::ClearIfMatches($secret)
        Write-Host "SOC_WEBHOOK_HEADER_CLIPBOARD_CLEARED=$($cleared.ToString().ToLowerInvariant())"
    }
    $secret = $null
}
