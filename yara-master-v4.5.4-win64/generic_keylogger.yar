rule Detect_Keylogger_Behavior
{
    meta:
        author = "Gemini"
        description = "Detects common keylogger behaviors by looking for combinations of API calls, logging artifacts, and exfiltration strings."
        date = "2025-10-03"
        reference = "MITRE ATT&CK T1056.001"

    strings:
        // --- 1. Input Capture APIs ---
        // Functions used to monitor or intercept keystrokes.
        $api1 = "GetAsyncKeyState" nocase
        $api2 = "SetWindowsHookExA" nocase
        $api3 = "SetWindowsHookExW" nocase
        $api4 = "GetKeyState" nocase
        $api5 = "GetKeyboardState" nocase
        $api6 = "RegisterHotKey" nocase

        // --- 2. Data Staging / Logging ---
        // Common filenames and patterns for storing keystrokes.
        $log1 = "keylog.txt" nocase
        $log2 = "keystrokes.log" nocase
        $log3 = "session.log" nocase
        $log4 = "[BACKSPACE]" nocase
        $log5 = "[ENTER]" nocase
        $log6 = "[SHIFT]" nocase
        $log7 = "Window:" nocase // Often used to log the active window title

        // --- 3. Data Exfiltration ---
        // Strings related to sending data over the network.
        $exfil1 = "Invoke-WebRequest" nocase wide ascii
        $exfil2 = "HttpSendRequest" nocase
        $exfil3 = "wininet.dll" nocase
        $exfil4 = "InternetOpenUrlA" nocase
        $exfil5 = "POST" fullword

        // --- 4. Stealth ---
        // Hiding the application's window
        $stealth1 = "ShowWindow" nocase
        $stealth2 = "SW_HIDE" nocase

    condition:
        // Must be a Windows PE file (starts with "MZ")
        uint16(0) == 0x5a4d and
        (
            // --- Detection Logic ---
            // A combination of different suspicious behaviors is a much stronger indicator
            // than any single string.

            // Combination 1: Captures keys AND logs them.
            (1 of ($api*)) and (2 of ($log*)) or

            // Combination 2: Captures keys AND sends them over the network.
            (1 of ($api*)) and (1 of ($exfil*)) or

            // Combination 3: Uses multiple capture methods AND tries to hide.
            (2 of ($api*)) and (1 of ($stealth*))
        )
}