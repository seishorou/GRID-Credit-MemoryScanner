#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

static const wchar_t* kProcessNames[] = {L"GRID.exe", L"GRID1.exe"};
static const SIZE_T kMaxRegionSize = 64u * 1024u * 1024u;
static const size_t kMaxChangeRows = 500000;
static const size_t kMaxCandidateRows = 200000;

struct RegionInfo {
    uintptr_t base = 0;
    SIZE_T size = 0;
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

static std::string ExecutableFolder() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    return pos == std::string::npos ? "." : s.substr(0, pos);
}

static DWORD FindGridProcess(std::wstring& foundName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            for (const wchar_t* wanted : kProcessNames) {
                if (_wcsicmp(pe.szExeFile, wanted) == 0) {
                    pid = pe.th32ProcessID;
                    foundName = pe.szExeFile;
                    break;
                }
            }
            if (pid) break;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

static bool IsReadable(DWORD protect) {
    if (protect & PAGE_GUARD) return false;
    DWORD p = protect & 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritable(DWORD protect) {
    DWORD p = protect & 0xFF;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
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
        bool useful = mbi.State == MEM_COMMIT && IsReadable(mbi.Protect) &&
            IsWritable(mbi.Protect) &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) &&
            size > 0 && size <= kMaxRegionSize;

        if (useful) out.push_back({base, size, mbi.Protect, mbi.Type});

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
        BOOL ok = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(r.base + total),
            bytes.data() + total, toRead, &got);

        if (!ok || got != toRead) {
            SIZE_T sub = 0;
            while (sub < toRead) {
                SIZE_T small = std::min<SIZE_T>(0x1000, toRead - sub);
                SIZE_T smallGot = 0;
                BOOL smallOk = ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(r.base + total + sub),
                    bytes.data() + total + sub, small, &smallGot);
                if (!smallOk || smallGot != small) return false;
                sub += small;
            }
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
    int lastPercent = -1;

    Log(std::string("Capturando snapshot ") + label + "...");
    Log("Regioes candidatas: " + std::to_string(regions.size()));

    for (size_t index = 0; index < regions.size(); ++index) {
        const auto& r = regions[index];
        RegionSnapshot rs;
        rs.info = r;
        if (ReadRegion(process, r, rs.bytes)) {
            totalBytes += rs.bytes.size();
            snap.emplace(r.base, std::move(rs));
        } else {
            ++failed;
        }

        int percent = regions.empty() ? 100 : static_cast<int>(((index + 1) * 100) / regions.size());
        if (percent / 10 != lastPercent / 10 || percent == 100) {
            std::cout << "\rProgresso: " << std::setw(3) << percent << "%" << std::flush;
            lastPercent = percent;
        }
    }
    std::cout << "\rProgresso: 100%\n";

    std::ostringstream ss;
    ss << "Snapshot " << label << " concluido: " << snap.size() << " regioes, "
       << std::fixed << std::setprecision(2)
       << (static_cast<double>(totalBytes) / 1048576.0) << " MiB, "
       << failed << " falhas.";
    Log(ss.str());
    return snap;
}

template <typename T>
static T ReadLE(const std::vector<uint8_t>& v, size_t i) {
    T value{};
    std::memcpy(&value, v.data() + i, sizeof(T));
    return value;
}

static bool SmallReasonable(uint64_t v) {
    return v <= 9999;
}

static int ScoreUnsigned(uint64_t a, uint64_t b, uint64_t c, std::string& pattern) {
    if (a == 0 && b == 1 && c == 0) { pattern = "0->1->0"; return 100; }
    if (b == a + 1 && c == a) { pattern = "N->N+1->N"; return 95; }
    if (b == a + 1 && c + 1 == b) { pattern = "+1 then -1"; return 90; }
    if (b > a && c < b && SmallReasonable(a) && SmallReasonable(b) && SmallReasonable(c)) {
        pattern = "increase->decrease"; return 70;
    }
    if (b != a && c == a && SmallReasonable(a) && SmallReasonable(b)) {
        pattern = "changed then restored"; return 60;
    }
    return 0;
}

static void WriteCandidate(std::ofstream& f, int score, const char* valueType,
    const RegionSnapshot& region, uintptr_t address, size_t offset,
    int width, int64_t a, int64_t b, int64_t c, const std::string& pattern) {
    f << score << ',' << valueType << ',' << TypeName(region.info.type) << ','
      << ProtectName(region.info.protect) << ',' << Hex(address) << ',' << Hex(offset)
      << ',' << width << ',' << a << ',' << b << ',' << c << ",\"" << pattern << "\"\n";
}

static void CompareSnapshots(const Snapshot& initial, const Snapshot& coin,
    const Snapshot& start, const std::string& folder) {
    std::ofstream changes(folder + "\\GRID_Memory_Changes.csv", std::ios::binary);
    std::ofstream candidates(folder + "\\GRID_Credit_Candidates.csv", std::ios::binary);
    changes << "MemoryType,Protection,Address,Offset,InitialByte,CoinByte,StartByte\n";
    candidates << "Score,ValueType,MemoryType,Protection,Address,Offset,WidthBits,Initial,Coin,Start,Pattern\n";

    size_t commonRegions = 0, changedBytesAB = 0, changedBytesBC = 0;
    size_t changeRows = 0, candidateRows = 0;
    size_t regionIndex = 0;

    Log("Comparando os tres snapshots...");

    for (const auto& kv : initial) {
        auto itB = coin.find(kv.first);
        auto itC = start.find(kv.first);
        if (itB == coin.end() || itC == start.end()) continue;

        const RegionSnapshot& a = kv.second;
        const RegionSnapshot& b = itB->second;
        const RegionSnapshot& c = itC->second;
        size_t n = std::min(a.bytes.size(), std::min(b.bytes.size(), c.bytes.size()));
        if (!n) continue;
        ++commonRegions;
        ++regionIndex;

        for (size_t i = 0; i < n; ++i) {
            uint8_t av = a.bytes[i], bv = b.bytes[i], cv = c.bytes[i];
            if (av != bv) ++changedBytesAB;
            if (bv != cv) ++changedBytesBC;

            if ((av != bv || bv != cv) && changeRows < kMaxChangeRows) {
                changes << TypeName(a.info.type) << ',' << ProtectName(a.info.protect) << ','
                        << Hex(a.info.base + i) << ',' << Hex(i) << ','
                        << static_cast<unsigned>(av) << ',' << static_cast<unsigned>(bv) << ','
                        << static_cast<unsigned>(cv) << '\n';
                ++changeRows;
            }

            std::string pattern;
            int score = ScoreUnsigned(av, bv, cv, pattern);
            if (score && candidateRows < kMaxCandidateRows) {
                WriteCandidate(candidates, score, "uint8", a, a.info.base + i, i, 8,
                    av, bv, cv, pattern);
                ++candidateRows;
            }
        }

        const size_t widths[] = {2, 4};
        for (size_t width : widths) {
            if (n < width) continue;
            for (size_t i = 0; i + width <= n; ++i) {
                uint64_t av = width == 2 ? ReadLE<uint16_t>(a.bytes, i) : ReadLE<uint32_t>(a.bytes, i);
                uint64_t bv = width == 2 ? ReadLE<uint16_t>(b.bytes, i) : ReadLE<uint32_t>(b.bytes, i);
                uint64_t cv = width == 2 ? ReadLE<uint16_t>(c.bytes, i) : ReadLE<uint32_t>(c.bytes, i);
                std::string pattern;
                int score = ScoreUnsigned(av, bv, cv, pattern);
                if (score && candidateRows < kMaxCandidateRows) {
                    WriteCandidate(candidates, score, width == 2 ? "uint16" : "uint32", a,
                        a.info.base + i, i, static_cast<int>(width * 8),
                        static_cast<int64_t>(av), static_cast<int64_t>(bv), static_cast<int64_t>(cv), pattern);
                    ++candidateRows;
                }
            }
        }
    }

    changes.flush();
    candidates.flush();
    Log("Regioes presentes nos tres snapshots: " + std::to_string(commonRegions));
    Log("Bytes alterados INICIAL->COIN: " + std::to_string(changedBytesAB));
    Log("Bytes alterados COIN->START: " + std::to_string(changedBytesBC));
    Log("Linhas em GRID_Memory_Changes.csv: " + std::to_string(changeRows));
    Log("Candidatos em GRID_Credit_Candidates.csv: " + std::to_string(candidateRows));
    if (changeRows >= kMaxChangeRows) Log("AVISO: limite do relatorio geral atingido.");
    if (candidateRows >= kMaxCandidateRows) Log("AVISO: limite de candidatos atingido.");
}

static int ReadChoice() {
    std::cout << "\nEscolha: " << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) return 0;
    if (line.empty()) return -1;
    return line[0] - '0';
}

static void PrintMenu(bool haveInitial, bool haveCoin, bool compared) {
    std::cout << "\n========================================\n"
              << " GRID Credit Memory Scanner v3.0\n"
              << "========================================\n"
              << " 1 - Snapshot INICIAL" << (haveInitial ? " [OK]" : "") << "\n"
              << " 2 - Snapshot apos COIN" << (haveCoin ? " [OK]" : "") << "\n"
              << " 3 - Snapshot apos START + COMPARAR" << (compared ? " [OK]" : "") << "\n"
              << " 4 - Reexibir instrucoes\n"
              << " 0 - Sair\n";
}

int main() {
    SetConsoleTitleA("GRID Credit Memory Scanner v3.0");
    const std::string folder = ExecutableFolder();
    gLog.open(folder + "\\GRID_Credit_MemoryScanner.log", std::ios::binary);

    Log("GRID Credit Memory Scanner v3.0");
    Log("Modo SOMENTE LEITURA. Nenhuma memoria sera alterada.");
    Log("Procurando GRID.exe ou GRID1.exe...");

    DWORD pid = 0;
    std::wstring foundName;
    while (!pid) {
        pid = FindGridProcess(foundName);
        if (!pid) Sleep(500);
    }

    std::string foundAnsi(foundName.begin(), foundName.end());
    Log(foundAnsi + " encontrado. PID=" + std::to_string(pid));

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        Log("ERRO: OpenProcess falhou. Execute o scanner como administrador.");
        std::cout << "Pressione Enter para sair.";
        std::cin.get();
        return 1;
    }

    BOOL wow64 = FALSE;
    IsWow64Process(process, &wow64);
    Log(std::string("Alvo WOW64: ") + (wow64 ? "sim" : "nao"));
    Log("Use ALT+TAB para alternar entre o jogo e esta janela.");

    Snapshot initial, coin, start;
    bool haveInitial = false, haveCoin = false, compared = false;

    for (;;) {
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            Log("O processo do GRID foi encerrado.");
            break;
        }

        PrintMenu(haveInitial, haveCoin, compared);
        int choice = ReadChoice();
        if (choice == 0) break;

        if (choice == 1) {
            Log("Mantenha o jogo parado na tela desejada durante a captura.");
            initial = CaptureSnapshot(process, "INICIAL");
            haveInitial = !initial.empty();
            haveCoin = false;
            compared = false;
            coin.clear();
            start.clear();
            if (haveInitial) Log("Agora volte ao jogo, insira exatamente 1 credito, retorne e escolha 2.");
        } else if (choice == 2) {
            if (!haveInitial) {
                Log("Opcao 2 ignorada: faca primeiro o snapshot INICIAL (opcao 1).");
                continue;
            }
            coin = CaptureSnapshot(process, "COIN");
            haveCoin = !coin.empty();
            compared = false;
            start.clear();
            if (haveCoin) Log("Agora volte ao jogo, pressione START, retorne imediatamente e escolha 3.");
        } else if (choice == 3) {
            if (!haveInitial || !haveCoin) {
                Log("Opcao 3 ignorada: conclua primeiro as opcoes 1 e 2.");
                continue;
            }
            start = CaptureSnapshot(process, "START");
            if (!start.empty()) {
                CompareSnapshots(initial, coin, start, folder);
                compared = true;
                Log("Analise concluida. Envie o LOG e o arquivo GRID_Credit_Candidates.csv.");
            }
        } else if (choice == 4) {
            Log("Sequencia: 1 no estado inicial; insira 1 credito; 2; pressione START; 3.");
        } else {
            Log("Opcao invalida.");
        }
    }

    CloseHandle(process);
    Log("Finalizado.");
    return 0;
}
