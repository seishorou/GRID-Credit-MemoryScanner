// GRID Credit Memory Scanner v1.0
// Windows 7+ / x86 or x64 build
// Read-only process memory scanner for GRID.exe
//
// Keys:
// CTRL+SHIFT+F6 = baseline snapshot
// CTRL+SHIFT+F7 = snapshot after COIN
// CTRL+SHIFT+F8 = snapshot after START + compare
// CTRL+SHIFT+F12 = finish
//
// Build as Win32/x86 for best compatibility with 32-bit GRID.exe.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

static const wchar_t* kProcessName = L"GRID.exe";
static const SIZE_T kMaxRegionSize = 64u * 1024u * 1024u;
static const size_t kMaxChangeRows = 300000;
static const size_t kMaxCandidateRows = 100000;

struct RegionInfo {
    uintptr_t base = 0;
    SIZE_T size = 0;
    DWORD state = 0;
    DWORD protect = 0;
    DWORD type = 0;
};

struct RegionSnapshot {
    RegionInfo info;
    std::vector<uint8_t> bytes;
};

using Snapshot = std::map<uintptr_t, RegionSnapshot>;

static std::ofstream gLog;

static std::string Hex(uintptr_t value) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << value;
    return ss.str();
}

static std::string TypeName(DWORD type) {
    switch (type) {
    case MEM_IMAGE: return "MEM_IMAGE";
    case MEM_MAPPED: return "MEM_MAPPED";
    case MEM_PRIVATE: return "MEM_PRIVATE";
    default: return "UNKNOWN";
    }
}

static std::string ProtectName(DWORD p) {
    p &= 0xFF;
    switch (p) {
    case PAGE_READONLY: return "R";
    case PAGE_READWRITE: return "RW";
    case PAGE_WRITECOPY: return "WC";
    case PAGE_EXECUTE: return "X";
    case PAGE_EXECUTE_READ: return "XR";
    case PAGE_EXECUTE_READWRITE: return "XRW";
    case PAGE_EXECUTE_WRITECOPY: return "XWC";
    default: return "?";
    }
}

static void Log(const std::string& msg) {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char stamp[64]{};
    std::snprintf(stamp, sizeof(stamp), "[%04u-%02u-%02u %02u:%02u:%02u] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::cout << stamp << msg << std::endl;
    if (gLog.is_open()) {
        gLog << stamp << msg << "\n";
        gLog.flush();
    }
}

static DWORD FindProcessId(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

static bool IsReadable(DWORD protect) {
    if (protect & PAGE_GUARD) return false;
    if ((protect & 0xFF) == PAGE_NOACCESS) return false;

    DWORD p = protect & 0xFF;
    return p == PAGE_READONLY ||
           p == PAGE_READWRITE ||
           p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritable(DWORD protect) {
    DWORD p = protect & 0xFF;
    return p == PAGE_READWRITE ||
           p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

static std::vector<RegionInfo> EnumerateRegions(HANDLE process) {
    std::vector<RegionInfo> out;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T got = VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (!got) {
            addr += 0x1000;
            continue;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T size = mbi.RegionSize;

        bool useful =
            mbi.State == MEM_COMMIT &&
            IsReadable(mbi.Protect) &&
            IsWritable(mbi.Protect) &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) &&
            size > 0 &&
            size <= kMaxRegionSize;

        if (useful) {
            RegionInfo r;
            r.base = base;
            r.size = size;
            r.state = mbi.State;
            r.protect = mbi.Protect;
            r.type = mbi.Type;
            out.push_back(r);
        }

        uintptr_t next = base + size;
        if (next <= addr) next = addr + 0x1000;
        addr = next;
    }

    return out;
}

static bool ReadRegion(HANDLE process, const RegionInfo& r, std::vector<uint8_t>& bytes) {
    bytes.assign(r.size, 0);
    SIZE_T total = 0;
    const SIZE_T chunk = 64u * 1024u;

    while (total < r.size) {
        SIZE_T toRead = std::min(chunk, r.size - total);
        SIZE_T got = 0;
        BOOL ok = ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(r.base + total),
            bytes.data() + total,
            toRead,
            &got
        );

        if (!ok && got == 0) {
            // Retry in 4 KiB pieces.
            SIZE_T sub = 0;
            while (sub < toRead) {
                SIZE_T small = std::min<SIZE_T>(0x1000, toRead - sub);
                SIZE_T smallGot = 0;
                BOOL smallOk = ReadProcessMemory(
                    process,
                    reinterpret_cast<LPCVOID>(r.base + total + sub),
                    bytes.data() + total + sub,
                    small,
                    &smallGot
                );
                if (!smallOk || smallGot != small) return false;
                sub += small;
            }
        } else if (got != toRead) {
            return false;
        }

        total += toRead;
    }

    return true;
}

static Snapshot CaptureSnapshot(HANDLE process, const char* label) {
    Snapshot snap;
    auto regions = EnumerateRegions(process);

    SIZE_T totalBytes = 0;
    size_t failed = 0;

    Log(std::string("Capturando snapshot ") + label + "...");
    Log("Regioes candidatas: " + std::to_string(regions.size()));

    for (const auto& r : regions) {
        RegionSnapshot rs;
        rs.info = r;

        if (!ReadRegion(process, r, rs.bytes)) {
            ++failed;
            continue;
        }

        totalBytes += rs.bytes.size();
        snap.emplace(r.base, std::move(rs));
    }

    std::ostringstream ss;
    ss << "Snapshot " << label << " concluido: "
       << snap.size() << " regioes, "
       << std::fixed << std::setprecision(2)
       << (static_cast<double>(totalBytes) / 1048576.0) << " MiB, "
       << failed << " falhas.";
    Log(ss.str());

    return snap;
}

static uint32_t ReadU32(const std::vector<uint8_t>& v, size_t i) {
    return static_cast<uint32_t>(v[i]) |
           (static_cast<uint32_t>(v[i + 1]) << 8) |
           (static_cast<uint32_t>(v[i + 2]) << 16) |
           (static_cast<uint32_t>(v[i + 3]) << 24);
}

static void WriteCsvHeader(std::ofstream& f) {
    f << "Category,MemoryType,Protection,Address,Offset,Width,"
         "Initial,Coin,Start,Pattern\n";
}

static void CompareSnapshots(
    const Snapshot& initial,
    const Snapshot& coin,
    const Snapshot& start,
    const std::string& folder
) {
    std::ofstream changes(folder + "\\GRID_Memory_Changes.csv", std::ios::binary);
    std::ofstream candidates(folder + "\\GRID_Credit_Candidates.csv", std::ios::binary);
    WriteCsvHeader(changes);
    WriteCsvHeader(candidates);

    size_t changeRows = 0;
    size_t candidateRows = 0;
    size_t changedBytesInitialCoin = 0;
    size_t changedBytesCoinStart = 0;
    size_t commonRegions = 0;

    Log("Comparando snapshots...");

    for (const auto& kv : initial) {
        const uintptr_t base = kv.first;
        auto itCoin = coin.find(base);
        auto itStart = start.find(base);
        if (itCoin == coin.end() || itStart == start.end()) continue;

        const RegionSnapshot& a = kv.second;
        const RegionSnapshot& b = itCoin->second;
        const RegionSnapshot& c = itStart->second;

        size_t n = std::min(a.bytes.size(), std::min(b.bytes.size(), c.bytes.size()));
        if (n == 0) continue;
        ++commonRegions;

        for (size_t i = 0; i < n; ++i) {
            uint8_t av = a.bytes[i];
            uint8_t bv = b.bytes[i];
            uint8_t cv = c.bytes[i];

            if (av != bv) ++changedBytesInitialCoin;
            if (bv != cv) ++changedBytesCoinStart;

            if ((av != bv || bv != cv) && changeRows < kMaxChangeRows) {
                changes << "BYTE,"
                        << TypeName(a.info.type) << ","
                        << ProtectName(a.info.protect) << ","
                        << Hex(base + i) << ","
                        << Hex(i) << ",8,"
                        << static_cast<unsigned>(av) << ","
                        << static_cast<unsigned>(bv) << ","
                        << static_cast<unsigned>(cv) << ","
                        << "\"changed\"\n";
                ++changeRows;
            }

            bool classic = (bv == static_cast<uint8_t>(av + 1) && cv == av);
            bool increaseThenDecrease = (bv > av && cv < bv);
            bool zeroOneZero = (av == 0 && bv == 1 && cv == 0);

            if ((classic || increaseThenDecrease || zeroOneZero) &&
                candidateRows < kMaxCandidateRows) {
                std::string pattern = zeroOneZero ? "0->1->0" :
                                      classic ? "N->N+1->N" :
                                      "increase->decrease";

                candidates << "BYTE,"
                           << TypeName(a.info.type) << ","
                           << ProtectName(a.info.protect) << ","
                           << Hex(base + i) << ","
                           << Hex(i) << ",8,"
                           << static_cast<unsigned>(av) << ","
                           << static_cast<unsigned>(bv) << ","
                           << static_cast<unsigned>(cv) << ","
                           << "\"" << pattern << "\"\n";
                ++candidateRows;
            }
        }

        // 32-bit little-endian candidates, aligned and unaligned.
        if (n >= 4) {
            for (size_t i = 0; i + 4 <= n; ++i) {
                uint32_t av = ReadU32(a.bytes, i);
                uint32_t bv = ReadU32(b.bytes, i);
                uint32_t cv = ReadU32(c.bytes, i);

                bool classic32 = (bv == av + 1 && cv == av);
                bool incDec32 = (bv > av && cv < bv && (bv - av) <= 1000);
                bool zeroOneZero32 = (av == 0 && bv == 1 && cv == 0);

                if ((classic32 || incDec32 || zeroOneZero32) &&
                    candidateRows < kMaxCandidateRows) {
                    std::string pattern = zeroOneZero32 ? "0->1->0" :
                                          classic32 ? "N->N+1->N" :
                                          "increase->decrease";

                    candidates << "DWORD,"
                               << TypeName(a.info.type) << ","
                               << ProtectName(a.info.protect) << ","
                               << Hex(base + i) << ","
                               << Hex(i) << ",32,"
                               << av << "," << bv << "," << cv << ","
                               << "\"" << pattern << "\"\n";
                    ++candidateRows;
                }
            }
        }
    }

    changes.flush();
    candidates.flush();

    Log("Regioes presentes nos tres snapshots: " + std::to_string(commonRegions));
    Log("Bytes alterados INITIAL->COIN: " + std::to_string(changedBytesInitialCoin));
    Log("Bytes alterados COIN->START: " + std::to_string(changedBytesCoinStart));
    Log("Linhas gravadas em GRID_Memory_Changes.csv: " + std::to_string(changeRows));
    Log("Candidatos gravados em GRID_Credit_Candidates.csv: " + std::to_string(candidateRows));

    if (changeRows >= kMaxChangeRows) {
        Log("AVISO: limite de linhas do relatorio geral atingido.");
    }
    if (candidateRows >= kMaxCandidateRows) {
        Log("AVISO: limite de candidatos atingido.");
    }
}

static std::string ExecutableFolder() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    return pos == std::string::npos ? "." : s.substr(0, pos);
}

static bool ComboPressed(int vk) {
    static SHORT last[256]{};
    const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    SHORT now = GetAsyncKeyState(vk);
    const bool down = (now & 0x8000) != 0;
    const bool pressed = ctrl && shift && down && !(last[vk] & 0x8000);
    last[vk] = now;
    return pressed;
}

int main() {
    const std::string folder = ExecutableFolder();
    gLog.open(folder + "\\GRID_Credit_MemoryScanner.log", std::ios::binary);

    Log("GRID Credit Memory Scanner v2.0");
    Log("Modo SOMENTE LEITURA.");
    Log("CTRL+SHIFT+F6=Inicial | CTRL+SHIFT+F7=Coin | CTRL+SHIFT+F8=Start+Comparar | CTRL+SHIFT+F12=Sair");
    Log("Aguardando GRID.exe...");

    DWORD pid = 0;
    while (!pid) {
        pid = FindProcessId(kProcessName);
        if (ComboPressed(VK_F12)) return 0;
        Sleep(500);
    }

    Log("GRID.exe encontrado. PID=" + std::to_string(pid));

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        Log("ERRO: OpenProcess falhou. Execute como administrador.");
        return 1;
    }

    BOOL wow64 = FALSE;
    IsWow64Process(process, &wow64);
    Log(std::string("Alvo WOW64: ") + (wow64 ? "sim" : "nao"));

    Snapshot initial, coin, start;
    bool haveInitial = false;
    bool haveCoin = false;
    bool finished = false;

    Log("Deixe o jogo parado na tela desejada e pressione CTRL+SHIFT+F6 para o snapshot INICIAL.");

    while (!finished) {
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            Log("GRID.exe foi encerrado.");
            break;
        }

        if (ComboPressed(VK_F6)) {
            initial = CaptureSnapshot(process, "INICIAL");
            haveInitial = !initial.empty();
            haveCoin = false;
            coin.clear();
            start.clear();
            if (haveInitial)
                Log("Agora insira 1 credito e pressione CTRL+SHIFT+F7 imediatamente.");
        }

        if (ComboPressed(VK_F7)) {
            if (!haveInitial) {
                Log("CTRL+SHIFT+F7 ignorado: faca CTRL+SHIFT+F6 primeiro.");
            } else {
                coin = CaptureSnapshot(process, "COIN");
                haveCoin = !coin.empty();
                if (haveCoin)
                    Log("Agora pressione START no jogo e pressione CTRL+SHIFT+F8 imediatamente.");
            }
        }

        if (ComboPressed(VK_F8)) {
            if (!haveInitial || !haveCoin) {
                Log("CTRL+SHIFT+F8 ignorado: faca CTRL+SHIFT+F6 e CTRL+SHIFT+F7 primeiro.");
            } else {
                start = CaptureSnapshot(process, "START");
                if (!start.empty()) {
                    CompareSnapshots(initial, coin, start, folder);
                    Log("Analise concluida. Pressione CTRL+SHIFT+F12 para sair.");
                }
            }
        }

        if (ComboPressed(VK_F12)) {
            finished = true;
        }

        Sleep(20);
    }

    CloseHandle(process);
    Log("Finalizado.");
    return 0;
}
