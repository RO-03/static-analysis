import pefile

# Use a raw string (r"...") for Windows paths
file_path = r"C:\Users\Surya HT\OneDrive\Documents\malware\keylogger.exe"

try:
    pe = pefile.PE(file_path)

    print("[*] Imported DLLs and Functions:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\n--- {entry.dll.decode()} ---")
            for imp in entry.imports:
                if imp.name:
                    print(f"  - {imp.name.decode()}")

except Exception as e:
    print(f"[!] An error occurred: {e}")