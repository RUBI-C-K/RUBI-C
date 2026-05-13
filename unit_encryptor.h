// unit_encryptor.h - 0.1 alpha

#ifndef UNIT_ENCRYPTOR_H
#define UNIT_ENCRYPTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <random>
#include <algorithm>
#include <map>
#include <set>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <mntent.h>
#include <cpuid.h>
#include <errno.h>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <stdlib.h>
#include <x86intrin.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/mac.h>
#include <botan/hex.h>
#include <botan/secmem.h>
#include <botan/kdf.h>
#include <botan/hash.h>

class KeyManager;

// CONSTANTES DE TAMAÑO
#define SECTOR_SIZE 512ULL
#define HEADER_OFFSET_SECTORS 2048ULL
#define HEADER_SECTORS 8ULL
#define DATA_OFFSET_SECTORS (HEADER_OFFSET_SECTORS + HEADER_SECTORS)
#define MIN_THREADS 1
#define MAX_THREADS 128
#define PROGRESS_UPDATE_MS 200
#define GB (1024ULL*1024ULL*1024ULL)
#define MB (1024ULL*1024ULL)
#define ALIGNMENT 4096ULL
#define HMAC_SIZE 64
#define KDF_SALT_SIZE 64
#define KEY_DERIVATION_INFO "RUBI-C-AES-XTS-KEY-V1-OFFSET-1MB"
#define PIPELINE_DEPTH 3
#define MAX_QUEUE_SIZE 2
#define HEADER_VERSION_CURRENT 3

// VERIFICACIÓN DE PERMISOS 
inline bool checkRoot() {
    if (geteuid() != 0) {   //not quitar esto ya el main verifica esto 
        std::cout << BRIGHT_RED << "\n✗ ERROR: SE REQUIEREN PERMISOS DE ROOT" << RESET << std::endl;
        std::cout << "Ejecute con: sudo" << RESET << std::endl;
        return false;
    }
    return true;
}

// DETECCIÓN DE HARDWARE 
class HWDetect {
public:
    static bool hasAESNI() { static bool aesni = check_aesni(); return aesni; }
    static bool hasAVX2() { static bool avx2 = check_avx2(); return avx2; }
    static bool hasAVX512() { static bool avx512 = check_avx512(); return avx512; }
    static int getCoreCount() { static int cores = std::thread::hardware_concurrency(); return cores > 0 ? cores : 4; }
    static std::string getCPUInfo() {
        std::stringstream ss;
        ss << "Núcleos: " << getCoreCount();
        if (hasAESNI()) ss << " | AES-NI: ✓";
        if (hasAVX2()) ss << " | AVX2: ✓";
        if (hasAVX512()) ss << " | AVX-512: ✓";     //nota meter opciones arm xd
        return ss.str();
    }
    static size_t getOptimalAlignment() { return ALIGNMENT; }
    static const char* getSIMDLevel() {
        if (hasAVX512()) return "AVX-512";
        if (hasAVX2()) return "AVX2";
        return "SSE";
    }
private:
    static bool check_aesni() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 1) {
            __cpuid_count(1, 0, eax, ebx, ecx, edx);
            return (ecx & (1 << 25)) != 0;
        }
        return false;
    }
    static bool check_avx2() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 7) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            return (ebx & (1 << 5)) != 0;
        }
        return false;
    }
    static bool check_avx512() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) >= 7) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            return (ebx & ((1 << 16) | (1 << 30))) == ((1 << 16) | (1 << 30));
        }
        return false;
    }
};

// DERIVACIÓN DE CLAVES
class KeyDeriv {
public:
    static Botan::secure_vector<uint8_t> deriveSubKey(
        const Botan::secure_vector<uint8_t>& master_key,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_length = 64) {
        try {
            auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
            Botan::secure_vector<uint8_t> derived_key(key_length);
            std::vector<uint8_t> secret(master_key.begin(), master_key.end());
            std::vector<uint8_t> salt_vec(salt.begin(), salt.end());
            std::vector<uint8_t> info(reinterpret_cast<const uint8_t*>(KEY_DERIVATION_INFO),
                                       reinterpret_cast<const uint8_t*>(KEY_DERIVATION_INFO) + strlen(KEY_DERIVATION_INFO));
            kdf->derive_key(derived_key, secret, salt_vec, info);
            return derived_key;
        } catch (const std::exception& e) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static Botan::secure_vector<uint8_t> generateSalt(size_t size = KDF_SALT_SIZE) {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> salt(size);
            rng.randomize(salt.data(), salt.size());
            return salt;
        } catch (const std::exception& e) {
            return Botan::secure_vector<uint8_t>();
        }
    }
};

// CONFIGURACIÓN
struct CustCfg {
    size_t buffer_size_mb;
    int io_threads;
    int crypto_threads;
    bool use_direct_io;
    bool custom_mode;
    
    CustCfg() : buffer_size_mb(64), io_threads(2), crypto_threads(4), 
                use_direct_io(true), custom_mode(false) {}
    
    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::istringstream iss(line);
                std::string key, value;
                if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                    if (key == "buffer_size_mb") buffer_size_mb = std::stoul(value);
                    else if (key == "io_threads") io_threads = std::stoi(value);
                    else if (key == "crypto_threads") crypto_threads = std::stoi(value);
                    else if (key == "use_direct_io") use_direct_io = (value == "true");
                    else if (key == "custom_mode") custom_mode = (value == "true");
                }
            }
            file.close();
        }
    }
    
    void saveToFile(const std::string& filename) {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "# Configuración personalizada de RUBI-C\n";
            file << "# Valores por defecto: buffer_size_mb=64, io_threads=2, crypto_threads=4\n\n";
            file << "buffer_size_mb=" << buffer_size_mb << "\n";
            file << "io_threads=" << io_threads << "\n";
            file << "crypto_threads=" << crypto_threads << "\n";
            file << "use_direct_io=" << (use_direct_io ? "true" : "false") << "\n";
            file << "custom_mode=" << (custom_mode ? "true" : "false") << "\n";
            file.close();
        }
    }
    
    void show() const {
        std::cout << BLUE << "\n  Configuración personalizada:" << RESET << std::endl;
        std::cout << "  " << GREEN << "Buffer:" << RESET << " " << buffer_size_mb << " MB" << std::endl;
        std::cout << "  " << GREEN << "I/O Threads:" << RESET << " " << io_threads << std::endl;
        std::cout << "  " << GREEN << "Crypto Threads:" << RESET << " " << crypto_threads << std::endl;
        std::cout << "  " << GREEN << "I/O Directo:" << RESET << " " << (use_direct_io ? "Si" : "No") << std::endl;
        std::cout << "  " << GREEN << "Modo personalizado:" << RESET << " " << (custom_mode ? "Activado" : "Desactivado") << std::endl;
    }
    
    void configure() {
        std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN PERSONALIZADA" << BLUE << "]────────────────────────────────────┐\n";
        std::string input;
        std::cout << BLUE << "│ " << RESET << "Tamaño de buffer (MB) [" << buffer_size_mb << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) buffer_size_mb = std::stoul(input);
        std::cout << BLUE << "│ " << RESET << "Hilos I/O [" << io_threads << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) io_threads = std::stoi(input);
        std::cout << BLUE << "│ " << RESET << "Hilos cifrado [" << crypto_threads << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) crypto_threads = std::stoi(input);
        std::cout << BLUE << "│ " << RESET << "Usar I/O Directo (s/n) [" << (use_direct_io ? "s" : "n") << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) use_direct_io = (input == "s" || input == "S");
        std::cout << BLUE << "│ " << RESET << "Activar modo personalizado (s/n) [" << (custom_mode ? "s" : "n") << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) custom_mode = (input == "s" || input == "S");
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
        saveToFile("rubic_config.cfg");
        std::cout << GREEN << "\n✓ Configuración guardada en rubic_config.cfg" << RESET << std::endl;
    }
};

// BUFFER  PARA I/O DIRECTO
class AlignBuf {
private:
    void* data_ptr;
    size_t size_bytes;
public:
    AlignBuf(size_t size);
    ~AlignBuf();
    AlignBuf(AlignBuf&& other) noexcept;
    AlignBuf& operator=(AlignBuf&& other) noexcept;
    AlignBuf(const AlignBuf&) = delete;
    AlignBuf& operator=(const AlignBuf&) = delete;
    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
};

AlignBuf::AlignBuf(size_t size) : data_ptr(nullptr), size_bytes(size) {
    if (posix_memalign(&data_ptr, ALIGNMENT, size) != 0) throw std::bad_alloc();
    memset(data_ptr, 0, size);
}

AlignBuf::~AlignBuf() { if (data_ptr) free(data_ptr); }

AlignBuf::AlignBuf(AlignBuf&& other) noexcept : data_ptr(other.data_ptr), size_bytes(other.size_bytes) {
    other.data_ptr = nullptr;
    other.size_bytes = 0;
}

AlignBuf& AlignBuf::operator=(AlignBuf&& other) noexcept {
    if (this != &other) {
        if (data_ptr) free(data_ptr);
        data_ptr = other.data_ptr;
        size_bytes = other.size_bytes;
        other.data_ptr = nullptr;
        other.size_bytes = 0;
    }
    return *this;
}

uint8_t* AlignBuf::data() { return static_cast<uint8_t*>(data_ptr); }
const uint8_t* AlignBuf::data() const { return static_cast<const uint8_t*>(data_ptr); }
size_t AlignBuf::size() const { return size_bytes; }

// PROCESAMIENTO AVX2/AVX-512
class SIMDProc {
public:
    static void xor_blocks(uint8_t* dst, const uint8_t* src, size_t blocks) {
        size_t i = 0;
        size_t total_bytes = blocks * 16;
#ifdef __AVX512F__
        if (HWDetect::hasAVX512()) {
            for (; i + 64 <= total_bytes; i += 64) {
                __m512i vdst = _mm512_loadu_si512((__m512i*)(dst + i));
                __m512i vsrc = _mm512_loadu_si512((__m512i*)(src + i));
                vdst = _mm512_xor_si512(vdst, vsrc);
                _mm512_storeu_si512((__m512i*)(dst + i), vdst);
            }
        } else 
#endif
#ifdef __AVX2__
        if (HWDetect::hasAVX2()) {
            for (; i + 32 <= total_bytes; i += 32) {
                __m256i vdst = _mm256_loadu_si256((__m256i*)(dst + i));
                __m256i vsrc = _mm256_loadu_si256((__m256i*)(src + i));
                vdst = _mm256_xor_si256(vdst, vsrc);
                _mm256_storeu_si256((__m256i*)(dst + i), vdst);
            }
        } else 
#endif
        {
            for (; i + 16 <= total_bytes; i += 16) {
                __m128i vdst = _mm_loadu_si128((__m128i*)(dst + i));
                __m128i vsrc = _mm_loadu_si128((__m128i*)(src + i));
                vdst = _mm_xor_si128(vdst, vsrc);
                _mm_storeu_si128((__m128i*)(dst + i), vdst);
            }
        }
        for (; i < total_bytes; i++) dst[i] ^= src[i];
    }
    
    static void fill_tweak(uint8_t* tweak, uint64_t start_sector, size_t num_blocks) {
        for (size_t i = 0; i < num_blocks; i++) {
            uint64_t sector = start_sector + i;
            memcpy(tweak + i * 16, &sector, 8);
            memset(tweak + i * 16 + 8, 0, 8);
        }
    }
};

// DETECTOR DE TIPO DE DISPOSITIVO
enum class DevType {
    UNKNOWN, USB2, USB3, NVME, SSD_SATA, HDD, SD_CARD
};

class DevDetect {
private:
    static std::string getSysPath(const std::string& device) {
        std::string devname = device;
        if (devname.find("/dev/") == 0) devname = devname.substr(5);
        while (!devname.empty() && isdigit(devname.back())) devname.pop_back();
        return "/sys/block/" + devname;
    }
    
    static bool checkUSB(const std::string& syspath) {
        std::string uevent = syspath + "/device/uevent";
        FILE* f = fopen(uevent.c_str(), "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "USB") || strstr(line, "usb")) { fclose(f); return true; }
            }
            fclose(f);
        }
        char buf[256];
        ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf)-1);
        if (len != -1) { buf[len] = '\0'; if (std::string(buf).find("usb") != std::string::npos) return true; }
        return false;
    }
    
    static std::string readSpeed(const std::string& syspath) {
        std::string speed_file = syspath + "/device/speed";
        FILE* f = fopen(speed_file.c_str(), "r");
        if (!f) return "";
        char speed[32];
        if (fgets(speed, sizeof(speed), f)) { speed[strcspn(speed, "\n")] = 0; fclose(f); return speed; }
        fclose(f);
        return "";
    }
    
    static bool checkNVMe(const std::string& device) { return device.find("nvme") != std::string::npos; }
    static bool checkSD(const std::string& device) { return device.find("mmcblk") != std::string::npos; }
    
    static bool isRemovable(const std::string& syspath) {
        std::string removable_file = syspath + "/removable";
        FILE* f = fopen(removable_file.c_str(), "r");
        if (f) { char rem; if (fscanf(f, "%c", &rem) == 1) { fclose(f); return (rem == '1'); } fclose(f); }
        return false;
    }
    
public:
    static DevType detect(const std::string& device) {
        std::string devname = device;
        if (devname.find("/dev/") == 0) devname = devname.substr(5);
        if (checkNVMe(devname)) return DevType::NVME;
        if (checkSD(devname)) return DevType::SD_CARD;
        std::string syspath = getSysPath(device);
        bool usb = checkUSB(syspath);
        bool removable = isRemovable(syspath);
        if (usb || removable) {
            std::string speed = readSpeed(syspath);
            if (!speed.empty()) { int speed_val = atoi(speed.c_str()); return speed_val >= 500 ? DevType::USB3 : DevType::USB2; }
            return DevType::USB2;
        }
        std::string rotational_file = syspath + "/queue/rotational";
        FILE* f = fopen(rotational_file.c_str(), "r");
        if (f) { char rot; if (fscanf(f, "%c", &rot) == 1) { fclose(f); return (rot == '0') ? DevType::SSD_SATA : DevType::HDD; } fclose(f); }
        return DevType::UNKNOWN;
    }
    
    static std::string devTypeToStr(DevType type) {
        switch(type) {
            case DevType::USB2: return "USB 2.0";
            case DevType::USB3: return "USB 3.0";
            case DevType::NVME: return "NVMe SSD";
            case DevType::SSD_SATA: return "SSD SATA";
            case DevType::HDD: return "HDD";
            case DevType::SD_CARD: return "Tarjeta SD";
            default: return "Desconocido";
        }
    }
    
    static const char* devTypeColor(DevType type) {
        switch(type) {
            case DevType::NVME: return BRIGHT_GREEN;
            case DevType::USB3: return BRIGHT_CYAN;
            case DevType::SSD_SATA: return BRIGHT_BLUE;
            case DevType::USB2: return YELLOW;
            case DevType::HDD: return BRIGHT_YELLOW;
            case DevType::SD_CARD: return MAGENTA;
            default: return RESET;
        }
    }
    
    static size_t getOptimalChunkMB(DevType type) {
        switch(type) {
            case DevType::HDD: return 128;
            case DevType::USB2: return 128;
            case DevType::USB3: return 64;
            case DevType::SSD_SATA: return 64;
            case DevType::NVME: return 64;
            case DevType::SD_CARD: return 64;
            default: return 64;
        }
    }
    
    static bool useDirectIO(DevType type) {
        switch(type) {
            case DevType::USB2:
            case DevType::SD_CARD: return false;
            default: return true;
        }
    }
};

// CONFIGURACIÓN DE HILOS
struct FixedThCfg {
    int io_threads;
    int crypto_threads;
    int reserved_os;
    
    FixedThCfg() : io_threads(1), crypto_threads(1), reserved_os(0) {}
    
    static FixedThCfg getConfigForSystem() {
        FixedThCfg config;
        int system_threads = HWDetect::getCoreCount(); //meter de 6 hilos xd
        int available_threads = system_threads > 1 ? system_threads - 1 : system_threads;
        if (available_threads <= 1) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
        else if (available_threads <= 2) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
        else if (available_threads <= 4) { config.io_threads = 1; config.crypto_threads = 2; config.reserved_os = 1; }
        else if (available_threads <= 8) { config.io_threads = 2; config.crypto_threads = 5; config.reserved_os = 1; }
        else if (available_threads <= 16) { config.io_threads = 3; config.crypto_threads = 11; config.reserved_os = 2; }
        else if (available_threads <= 32) { config.io_threads = 4; config.crypto_threads = 24; config.reserved_os = 4; }
        else { config.io_threads = 6; config.crypto_threads = available_threads - 8; config.reserved_os = 2; }
        return config;
    }
};

struct ThCfg {
    int num_threads;
    size_t chunk_size_mb;
    bool use_direct_io;
    
    ThCfg() { num_threads = HWDetect::getCoreCount(); chunk_size_mb = 64; use_direct_io = true; }
    
    void applyFixedConfig(const FixedThCfg& fixed_cfg, DevType device_type) {
        num_threads = fixed_cfg.io_threads + fixed_cfg.crypto_threads + fixed_cfg.reserved_os;
        chunk_size_mb = DevDetect::getOptimalChunkMB(device_type);
        use_direct_io = DevDetect::useDirectIO(device_type);
    }
    
    void applyCustomConfig(const CustCfg& custom_cfg) {
        num_threads = custom_cfg.io_threads + custom_cfg.crypto_threads;
        chunk_size_mb = custom_cfg.buffer_size_mb;
        use_direct_io = custom_cfg.use_direct_io;
    }
    
    void validate() {
        if (num_threads < MIN_THREADS) num_threads = MIN_THREADS;
        if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
        if (chunk_size_mb < 1) chunk_size_mb = 1;
        if (chunk_size_mb > 1024) chunk_size_mb = 1024;
        size_t chunk_bytes = chunk_size_mb * MB;
        if (chunk_bytes % ALIGNMENT != 0) chunk_size_mb = ((chunk_bytes + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT / MB;
    }
    
    size_t getChunkSize() const {
        size_t size = chunk_size_mb * MB;
        if (size % ALIGNMENT != 0) size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
        return size;
    }
    
    std::string getDesc() const {
        std::stringstream ss;
        ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
        if (use_direct_io) ss << " | I/O DIRECTO";
        return ss.str();
    }
};

// MEDIDOR DE VELOCIDAD
class SpeedMtr {
private:
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_time;
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> last_bytes{0};
    std::atomic<double> current_speed{0};
    std::atomic<double> peak_speed{0};
    
public:
    SpeedMtr() { reset(); }
    void addBytes(uint64_t bytes) { total_bytes += bytes; }
    double getCurrentSpeed() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();
        if (elapsed >= 200) {
            uint64_t current = total_bytes.load();
            uint64_t diff = current - last_bytes;
            double speed = (diff / 1048576.0) / (elapsed / 1000.0);
            current_speed = speed;
            if (speed > peak_speed) peak_speed = speed;
            last_bytes = current;
            last_time = now;
        }
        return current_speed.load();
    }
    double getAvgSpeed() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        return elapsed > 0 ? (total_bytes / 1048576.0) / (elapsed / 1000.0) : 0;
    }
    double getPeakSpeed() { return peak_speed.load(); }
    uint64_t getTotalBytes() { return total_bytes.load(); }
    void reset() {
        start_time = std::chrono::steady_clock::now();
        last_time = start_time;
        total_bytes = 0;
        last_bytes = 0;
        current_speed = 0;
        peak_speed = 0;
    }
};

// INFORMACIÓN DEL SISTEMA DE ARCHIVOS
struct FSInfo {
    char fstype[32];
    char uuid[64];
    char label[256];
    FSInfo() { memset(fstype, 0, sizeof(fstype)); memset(uuid, 0, sizeof(uuid)); memset(label, 0, sizeof(label)); }
};

// HEADER 
#pragma pack(push, 1)
struct EncUnitHdr {
    uint8_t kdf_salt[KDF_SALT_SIZE];
    uint32_t version;
    uint64_t data_start_sector;
    uint64_t total_sectors;
    FSInfo fs_info;
    uint8_t hmac[HMAC_SIZE];
    
    bool isValid() const {
        if (version < 2 || version > HEADER_VERSION_CURRENT) return false;
        if (data_start_sector < HEADER_OFFSET_SECTORS + HEADER_SECTORS) return false;
        if (data_start_sector > total_sectors) return false;
        bool all_zero = true;
        for (size_t i = 0; i < KDF_SALT_SIZE; i++) {
            if (kdf_salt[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) return false;
        if (strlen(fs_info.fstype) > 31) return false;
        if (strlen(fs_info.label) > 255) return false;
        return true;
    }
};
#pragma pack(pop)

// GESTOR DE BACKUP
class HdrBackup {
private:
    std::string getBackupPath(const std::string& device_path) {
        std::string devname = device_path;
        if (devname.find("/dev/") == 0) devname = devname.substr(5);
        std::replace(devname.begin(), devname.end(), '/', '_');
        std::string hashed = std::to_string(std::hash<std::string>{}(devname));
        return "/var/tmp/.rubic_" + hashed + ".dat";
    }
    
    Botan::secure_vector<uint8_t> encryptBackup(const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
        try {
            auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
            if (!cipher) return {};
            Botan::secure_vector<uint8_t> data(sizeof(header));
            memcpy(data.data(), &header, sizeof(header));
            cipher->set_key(key);
            Botan::secure_vector<uint8_t> nonce(12);
            Botan::AutoSeeded_RNG rng;
            rng.randomize(nonce.data(), nonce.size());
            cipher->start(nonce);
            cipher->finish(data);
            Botan::secure_vector<uint8_t> result;
            result.insert(result.end(), nonce.begin(), nonce.end());
            result.insert(result.end(), data.begin(), data.end());
            return result;
        } catch (...) { return {}; }
    }
    
    bool decryptBackup(const std::string& backup_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
        std::ifstream file(backup_path, std::ios::binary);
        if (!file.is_open()) return false;
        Botan::secure_vector<uint8_t> encrypted_data;
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        encrypted_data.resize(size);
        file.read(reinterpret_cast<char*>(encrypted_data.data()), size);
        file.close();
        if (encrypted_data.size() < 12 + 16) return false;
        try {
            auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
            if (!cipher) return false;
            Botan::secure_vector<uint8_t> nonce(encrypted_data.begin(), encrypted_data.begin() + 12);
            Botan::secure_vector<uint8_t> ciphertext(encrypted_data.begin() + 12, encrypted_data.end());
            cipher->set_key(key);
            cipher->start(nonce);
            cipher->finish(ciphertext);
            if (ciphertext.size() != sizeof(header)) return false;
            memcpy(&header, ciphertext.data(), sizeof(header));
            return true;
        } catch (...) { return false; }
    }
    
    Botan::secure_vector<uint8_t> deriveBackupKey(const std::string& device_path) {
        Botan::secure_vector<uint8_t> key(32);
        auto hash = Botan::HashFunction::create("SHA-512");
        if (!hash) return {};
        hash->update(device_path);
        auto digest = hash->final();
        for (size_t i = 0; i < 32; i++) key[i] = digest[i];
        return key;
    }
    
public:
    bool saveHeader(const std::string& device_path, const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
        auto backup_key = deriveBackupKey(device_path);
        auto encrypted = encryptBackup(header, backup_key);
        if (encrypted.empty()) return false;
        std::string backup_path = getBackupPath(device_path);
        std::ofstream file(backup_path, std::ios::binary);
        if (!file.is_open()) return false;
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        file.close();
        chmod(backup_path.c_str(), 0600);
        return true;
    }
    
    bool loadHeader(const std::string& device_path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& master_key) {
        auto backup_key = deriveBackupKey(device_path);
        std::string backup_path = getBackupPath(device_path);
        return decryptBackup(backup_path, header, backup_key);
    }
    
    bool backupExists(const std::string& device_path) {
        std::string backup_path = getBackupPath(device_path);
        struct stat st;
        return (stat(backup_path.c_str(), &st) == 0);
    }
    
    bool removeBackup(const std::string& device_path) {
        std::string backup_path = getBackupPath(device_path);
        return (unlink(backup_path.c_str()) == 0);
    }
};

// ESTRUCTURA DE UNIDAD
struct StorUnit {
    std::string device_path;
    std::string mount_point;
    std::string label;
    std::string uuid;
    uint64_t total_size;
    std::string filesystem;
    bool is_mounted;
    bool is_encrypted;
    bool is_partition;
    bool is_system_disk;
    std::string parent_device;
    FSInfo fs_info;
    DevType device_type;
    bool has_header_backup;
    
    StorUnit() : total_size(0), is_mounted(false), is_encrypted(false), 
                 is_partition(false), is_system_disk(false), 
                 device_type(DevType::UNKNOWN), has_header_backup(false) {}
    
    std::string getSizeStr() const { return formatBytes(total_size); }
    std::string getDevTypeStr() const { return DevDetect::devTypeToStr(device_type); }
    const char* getDevTypeColor() const { return DevDetect::devTypeColor(device_type); }
    
    static std::string formatBytes(uint64_t bytes) {
        const char* sizes[] = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double dbl = bytes;
        while (dbl >= 1024.0 && i < 4) { dbl /= 1024.0; i++; }
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << dbl << " " << sizes[i];
        return ss.str();
    }
    
    std::string getSafeFSType() const {
        if (strlen(fs_info.fstype) > 0) {
            bool valid = true;
            for (size_t i = 0; i < strlen(fs_info.fstype); i++) {
                if (!isprint(fs_info.fstype[i])) { valid = false; break; }
            }
            if (valid) return std::string(fs_info.fstype);
        }
        return "";
    }
};

// BUFFER-sec
class SecBuf {
private:
    Botan::secure_vector<uint8_t> buffer_data;
    std::unique_ptr<AlignBuf> aligned_cache;
    bool use_aligned;
    
public:
    SecBuf(size_t size, bool aligned_mode = false) : use_aligned(aligned_mode) {
        if (use_aligned) aligned_cache = std::make_unique<AlignBuf>(size);
        else buffer_data.resize(size);
    }
    uint8_t* data() { return use_aligned ? aligned_cache->data() : buffer_data.data(); }
    const uint8_t* data() const { return use_aligned ? aligned_cache->data() : buffer_data.data(); }
    size_t size() const { return use_aligned ? aligned_cache->size() : buffer_data.size(); }
    uint8_t* secure_data() { return buffer_data.data(); }
    void sync_from_aligned() { if (use_aligned && !buffer_data.empty()) memcpy(buffer_data.data(), aligned_cache->data(), buffer_data.size()); }
    void sync_to_aligned() { if (use_aligned && !buffer_data.empty()) memcpy(aligned_cache->data(), buffer_data.data(), buffer_data.size()); }
};

// PROCESADOR HMAC  //IDEA METER kmac 
class HMACProc {
private:
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
    Botan::secure_vector<uint8_t> key;
    
public:
    HMACProc(const Botan::secure_vector<uint8_t>& key_data) {
        key = key_data;
        hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
        if (!hmac) throw std::runtime_error("No se pudo crear HMAC-SHA512");
        hmac->set_key(key);
    }
    Botan::secure_vector<uint8_t> calculate(const uint8_t* data, size_t size) {
        hmac->update(data, size);
        return hmac->final();
    }
    bool verify(const uint8_t* data, size_t size, const uint8_t* expected_hmac, size_t hmac_size) {
        auto calculated = calculate(data, size);
        if (calculated.size() != hmac_size) return false;
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < hmac_size; i++) diff |= (calculated[i] ^ expected_hmac[i]);
        return diff == 0;
    }
};

// PROCESADOR AES-XTS
class AESXTSProc {
private:
    std::unique_ptr<Botan::Cipher_Mode> cipher;
    Botan::secure_vector<uint8_t> key;
    Botan::secure_vector<uint8_t> tweak_buffer;
    Botan::secure_vector<uint8_t> sector_buffer;
    size_t sector_buffer_size;
    
public:
    AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt) {
        sector_buffer_size = 0;
        if (key_data.size() == 32) {
            key.resize(64);
            memcpy(key.data(), key_data.data(), 32);
            memcpy(key.data() + 32, key_data.data(), 32);
        } else {
            key = key_data;
        }
        cipher = Botan::Cipher_Mode::create("AES-256/XTS", encrypt ? Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption);
        if (!cipher) throw std::runtime_error("No se pudo crear el cifrador");
        cipher->set_key(key);
        sector_buffer.resize(SECTOR_SIZE);
        sector_buffer_size = SECTOR_SIZE;
    }
    
    bool processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
        try {
            size_t num_sectors = size / SECTOR_SIZE;
            const size_t BATCH_SIZE = 64;
            if (tweak_buffer.size() < BATCH_SIZE * 16) tweak_buffer.resize(BATCH_SIZE * 16);
            for (size_t i = 0; i < num_sectors; i += BATCH_SIZE) {
                size_t batch = std::min(BATCH_SIZE, num_sectors - i);
                SIMDProc::fill_tweak(tweak_buffer.data(), start_sector + i, batch);
                for (size_t j = 0; j < batch; j++) {
                    cipher->start(tweak_buffer.data() + j * 16, 16);
                    sector_buffer.assign(data + (i + j) * SECTOR_SIZE, data + (i + j + 1) * SECTOR_SIZE);
                    cipher->finish(sector_buffer);
                    memcpy(data + (i + j) * SECTOR_SIZE, sector_buffer.data(), SECTOR_SIZE);
                }
            }
            return true;
        } catch (const std::exception& e) { return false; }
    }
    
    bool processSecBuf(SecBuf& buffer, uint64_t start_sector) {
        return processBuffer(buffer.data(), buffer.size(), start_sector);
    }
};

// PIPELINE CHUNK
struct PipeChunk {
    uint64_t index;
    uint64_t offset;
    uint64_t size;
    uint64_t start_sector;
    std::unique_ptr<SecBuf> data;
    
    PipeChunk(size_t chunk_size, bool use_direct_io) : index(0), offset(0), size(0), start_sector(0) {
        data = std::make_unique<SecBuf>(chunk_size, use_direct_io);
    }
    PipeChunk(PipeChunk&& other) noexcept : index(other.index), offset(other.offset), size(other.size), 
        start_sector(other.start_sector), data(std::move(other.data)) {}
    void operator=(PipeChunk&& other) noexcept {
        index = other.index; offset = other.offset; size = other.size;
        start_sector = other.start_sector; data = std::move(other.data);
    }
    PipeChunk(const PipeChunk&) = delete;
    PipeChunk& operator=(const PipeChunk&) = delete;
};

// LIMITED QUEUE
template<typename T>
class LimQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable not_full;
    std::condition_variable not_empty;
    size_t max_size;
    bool closed = false;
    
public:
    LimQueue(size_t max) : max_size(max) {}
    void push(T&& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_full.wait(lock, [this] { return queue.size() < max_size || closed; });
        if (closed) return;
        queue.push(std::move(item));
        not_empty.notify_one();
    }
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_empty.wait(lock, [this] { return !queue.empty() || closed; });
        if (queue.empty()) return false;
        item = std::move(queue.front());
        queue.pop();
        not_full.notify_one();
        return true;
    }
    void close() {
        std::lock_guard<std::mutex> lock(mutex);
        closed = true;
        not_full.notify_all();
        not_empty.notify_all();
    }
    size_t size() { std::lock_guard<std::mutex> lock(mutex); return queue.size(); }
};

// FORMATEADOR
class Formatter {
private:
    static int safeSystem(const std::string& cmd) {
        int ret = system(cmd.c_str());
        if (ret == -1) std::cerr << RED << "Error ejecutando comando: " << strerror(errno) << RESET << std::endl;
        return ret;
    }
    
public:
    static bool cleanHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key = {}) {
        std::cout << YELLOW << "\nLimpiando header..." << RESET << std::endl;
        int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
        if (fd < 0) { std::cout << RED << "No se puede abrir: " << strerror(errno) << RESET << std::endl; return false; }
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(header_size, 0);
        ssize_t written = pwrite(fd, zeros.data(), header_size, header_offset);
        fsync(fd);
        close(fd);
        if (written == (ssize_t)header_size) {
            std::cout << GREEN << "✓ Header eliminado" << RESET << std::endl;
            HdrBackup backup_mgr;
            if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
                std::cout << GREEN << "✓ Backup eliminado" << RESET << std::endl;
            return true;
        } else {
            std::cout << RED << "✗ Error limpiando header" << RESET << std::endl;
            return false;
        }
    }
    
    static bool quickFormat(const StorUnit& unit, const std::string& fstype) {
        std::cout << YELLOW << "\n⚠ FORMATEO RÁPIDO" << RESET << std::endl;
        std::cout << "Unidad: " << unit.device_path << std::endl;
        std::cout << "Tamaño: " << unit.getSizeStr() << std::endl;
        std::cout << "Formato: " << fstype << std::endl;
        std::cout << "\nEscriba 'FORMATEAR' para confirmar: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "FORMATEAR") { std::cout << "Cancelado." << std::endl; return false; }
        std::cout << YELLOW << "Formateando..." << RESET << std::endl;
        std::string cmd;
        if (fstype == "vfat" || fstype == "fat32") cmd = "mkfs.vfat -F 32 " + unit.device_path + " 2>/dev/null";
        else if (fstype == "ntfs") cmd = "mkfs.ntfs -f " + unit.device_path + " 2>/dev/null";
        else if (fstype == "ext4") cmd = "mkfs.ext4 -F " + unit.device_path + " 2>/dev/null";
        else cmd = "mkfs." + fstype + " " + unit.device_path + " 2>/dev/null";
        int res = safeSystem(cmd);
        if (res == 0) { std::cout << GREEN << "✓ Formateado correctamente" << RESET << std::endl; return true; }
        else { std::cout << RED << "✗ Error formateando (código: " << res << ")" << RESET << std::endl; return false; }
    }
    
    static void showMenu(StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key = {}) {
        std::cout << BLUE << "\n┌─[" << MAGENTA << "FORMATO DE UNIDAD" << BLUE << "]────────────────────────────────────────┐\n";
        if (unit.is_encrypted) {
            std::cout << BLUE << "│ " << YELLOW << "⚠ La unidad está marcada como CIFRADA" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Limpiar solo header (quitar marca)" << RESET << std::endl;
        }
        std::cout << BLUE << "│ " << RESET << "\n";
        std::cout << BLUE << "│ " << MAGENTA << "SISTEMA DE ARCHIVOS:" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "FAT32 (USB, compatible)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "NTFS (Windows)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "ext4 (Linux)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "exFAT (grandes)" << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        std::cout << BRIGHT_GREEN << "\nSeleccione opción [" << BRIGHT_MAGENTA << "0-5" << BRIGHT_GREEN << "]: " << RESET;
        std::string c;
        std::getline(std::cin, c);
        if (c == "0") return;
        if (c == "1" && unit.is_encrypted) {
            if (cleanHeader(unit, master_key)) {
                unit.is_encrypted = false;
                unit.has_header_backup = false;
                std::cout << GREEN << "\n✓ Unidad marcada como NO CIFRADA" << RESET << std::endl;
            }
            return;
        }
        std::string fstype;
        if (c == "2") fstype = "vfat";
        else if (c == "3") fstype = "ntfs";
        else if (c == "4") fstype = "ext4";
        else if (c == "5") fstype = "exfat";
        else return;
        if (quickFormat(unit, fstype)) {
            unit.is_encrypted = false;
            unit.has_header_backup = false;
            unit.filesystem = fstype;
            std::cout << GREEN << "\n✓ Unidad formateada y marcada como NO CIFRADA" << RESET << std::endl;
        }
    }
};

// BARRA DE PROGRESO
class ProgBar {
private:
    int width;
    std::string prefix;
    std::string suffix;
    std::chrono::steady_clock::time_point start_time;
    uint64_t total_bytes;
    uint64_t current_bytes;
    double last_speed;
    
public:
    ProgBar(int bar_width = 50, const std::string& pre = "", const std::string& suf = "") 
        : width(bar_width), prefix(pre), suffix(suf), total_bytes(0), current_bytes(0), last_speed(0) {
        start_time = std::chrono::steady_clock::now();
    }
    
    void setTotal(uint64_t total) { total_bytes = total; }
    
    void update(uint64_t current) {
        current_bytes = current;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed > 0) last_speed = (current_bytes / 1048576.0) / (elapsed / 1000.0);
        render();
    }
    
    void render() {
        if (total_bytes == 0) return;
        double progress = (double)current_bytes / total_bytes;
        int pos = (int)(width * progress);
        double gb_done = current_bytes / (double)GB;
        double gb_total = total_bytes / (double)GB;
        int percent = (int)(progress * 100);
        
        auto now = std::chrono::steady_clock::now();
        std::string eta = "calculando";
        if (last_speed > 0 && current_bytes > 0) {
            uint64_t remaining_bytes = total_bytes - current_bytes;
            double remaining_secs = remaining_bytes / (last_speed * 1048576.0);
            if (remaining_secs < 3600) {
                int minutes = (int)remaining_secs / 60;
                int seconds = (int)remaining_secs % 60;
                std::stringstream ss;
                ss << minutes << "m " << seconds << "s";
                eta = ss.str();
            } else {
                int hours = (int)remaining_secs / 3600;
                int minutes = ((int)remaining_secs % 3600) / 60;
                std::stringstream ss;
                ss << hours << "h " << minutes << "m";
                eta = ss.str();
            }
        }
        
        std::cout << "\r" << prefix << " " << BLUE << "[" << RESET;
        for (int i = 0; i < width; ++i) {
            if (i < pos) std::cout << GREEN << "█" << RESET;
            else if (i == pos) std::cout << BLUE << "█" << RESET;
            else std::cout << "░";
        }
        std::cout << BLUE << "]" << RESET;
        std::cout << " " << GREEN << std::setw(3) << percent << "%" << RESET;
        std::cout << " " << BLUE << std::fixed << std::setprecision(2) << gb_done << "/" << gb_total << " GB" << RESET;
        std::cout << " " << GREEN << std::fixed << std::setprecision(2) << last_speed << " MB/s" << RESET;
        std::cout << " " << BLUE << "ETA: " << eta << RESET;
        std::cout << suffix;
        std::cout.flush();
    }
    
    void finish() { std::cout << std::endl; }
};

// CIFRADOR - CLASE PRINCIPAL
class UnitEncryptor {
private:
    KeyManager* keyManager = nullptr;
    std::string currentKeyName;
    
    Botan::secure_vector<uint8_t> directKey;
    bool useDirectKey = false;
    
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> processing_active{false};
    SpeedMtr speed_meter;
    FixedThCfg fixed_config;
    CustCfg custom_config;
    bool use_custom_config;
    HdrBackup backup_mgr;
    std::vector<StorUnit> cached_units;
    time_t last_refresh;
    
    struct Stats {
        uint64_t total_bytes = 0;
        uint64_t total_time_ms = 0;
        uint64_t errors = 0;
        void print(double avg, double peak) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << "ESTADÍSTICAS" << BLUE << "]─────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << RESET << "Total: " << GREEN << StorUnit::formatBytes(total_bytes) << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Tiempo: " << GREEN << (total_time_ms / 1000) << "s" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Velocidad: " << GREEN << std::fixed << std::setprecision(2) << avg << " MB/s" << RESET;
            std::cout << " (pico: " << GREEN << std::fixed << std::setprecision(2) << peak << " MB/s" << RESET << ")" << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
        }
    } stats;
    
    void refreshUnits() {
        time_t now = time(nullptr);
        if (now - last_refresh > 2) {
            cached_units = detectUnits();
            last_refresh = now;
        }
    }
    
    bool isPhysicalDevice(const std::string& path) {
        if (path.find("/dev/loop") != std::string::npos) return false;
        if (path.find("/dev/ram") != std::string::npos) return false;
        return true;
    }
    
    std::string getParentDevice(const std::string& path) {
        std::string dev = path.substr(5);
        size_t p = dev.find_first_of("0123456789");
        if (p != std::string::npos) return "/dev/" + dev.substr(0, p);
        return "";
    }
    
    bool isSystemDisk(const std::string& path) {
        FILE* fp = popen("df / | tail -1 | awk '{print $1}'", "r");
        if (!fp) return false;
        char buf[256];
        if (!fgets(buf, sizeof(buf), fp)) { pclose(fp); return false; }
        pclose(fp);
        std::string root_dev = buf;
        if (!root_dev.empty() && root_dev.back() == '\n') root_dev.pop_back();
        return (path == root_dev);
    }
    
    FSInfo getFileSystemInfo(const std::string& path) {
        FSInfo info;
        FILE* fp = popen(("blkid -o value -s TYPE " + path + " 2>/dev/null").c_str(), "r");
        if (fp) {
            if (fgets(info.fstype, sizeof(info.fstype), fp)) {
                info.fstype[strcspn(info.fstype, "\n")] = 0;
            }
            pclose(fp);
        }
        fp = popen(("blkid -o value -s LABEL " + path + " 2>/dev/null").c_str(), "r");
        if (fp) {
            if (fgets(info.label, sizeof(info.label), fp)) {
                info.label[strcspn(info.label, "\n")] = 0;
            }
            pclose(fp);
        }
        return info;
    }
    
    bool isUnitEncrypted(const std::string& device_path) {
        int fd = open(device_path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        
        EncUnitHdr hdr;
        bool has_valid_header = false;
        
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        ssize_t read_bytes = pread(fd, &hdr, sizeof(hdr), header_offset);
        
        if (read_bytes == sizeof(hdr)) {
            has_valid_header = hdr.isValid();
        }
        
        close(fd);
        return has_valid_header;
    }
    
    bool readHeaderFromDevice(int fd, EncUnitHdr& hdr) {
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        ssize_t read_bytes = pread(fd, &hdr, sizeof(hdr), header_offset);
        if (read_bytes != sizeof(hdr)) return false;
        return hdr.isValid();
    }
    
    bool writeHeaderToDevice(int fd, const EncUnitHdr& hdr) {
        int flags = fcntl(fd, F_GETFL);
        if (flags == -1) return false;
        bool was_direct = (flags & O_DIRECT);
        if (was_direct) { int new_flags = flags & ~O_DIRECT; fcntl(fd, F_SETFL, new_flags); }
        off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
        ssize_t written = pwrite(fd, &hdr, sizeof(hdr), header_offset);
        if (was_direct) fcntl(fd, F_SETFL, flags);
        return (written == sizeof(hdr));
    }
    
    std::vector<StorUnit> detectUnits() {
        std::vector<StorUnit> units;
        std::map<std::string, StorUnit> unique_by_device;
        std::set<std::string> seen_devices;
        
        std::string root_dev;
        FILE* fp = popen("df / | tail -1 | awk '{print $1}'", "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp)) { buf[strcspn(buf, "\n")] = 0; root_dev = buf; }
            pclose(fp);
        }
        
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (mounts) {
            struct mntent* ent;
            while ((ent = getmntent(mounts))) {
                std::string dev = ent->mnt_fsname;
                if (dev.find("/dev/") == 0 && isPhysicalDevice(dev)) {
                    
                    StorUnit u;
                    u.device_path = dev;
                    u.mount_point = ent->mnt_dir;
                    u.filesystem = ent->mnt_type;
                    u.is_mounted = true;
                    u.is_partition = (dev.find_first_of("0123456789") != std::string::npos);
                    u.parent_device = getParentDevice(dev);
                    u.is_system_disk = (dev == root_dev);
                    
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        if (ioctl(fd, BLKGETSIZE64, &u.total_size) != 0) u.total_size = 0;
                        
                        u.is_encrypted = isUnitEncrypted(dev);
                        if (u.is_encrypted) {
                            EncUnitHdr hdr;
                            if (readHeaderFromDevice(fd, hdr)) {
                                u.fs_info = hdr.fs_info;
                            }
                        }
                        close(fd);
                    }
                    
                    if (!u.is_encrypted) {
                        u.fs_info = getFileSystemInfo(dev);
                        u.label = u.fs_info.label;
                    } else {
                        u.label = u.fs_info.label;
                    }
                    
                    u.device_type = DevDetect::detect(dev);
                    u.has_header_backup = backup_mgr.backupExists(dev);
                    
                    std::string key = dev;
                    unique_by_device[key] = u;
                    seen_devices.insert(dev);
                }
            }
            endmntent(mounts);
        }
        
        DIR* dir = opendir("/dev");
        if (dir) {
            struct dirent* e;
            while ((e = readdir(dir))) {
                std::string name = e->d_name;
                std::string dev = "/dev/" + name;
                
                if ((name.find("sd") == 0 || name.find("hd") == 0 || name.find("nvme") == 0 || name.find("mmcblk") == 0) &&
                    !seen_devices.count(dev) && isPhysicalDevice(dev)) {
                    
                    bool is_part = (name.find_first_of("0123456789") != std::string::npos);
                    std::string parent = getParentDevice(dev);
                    
                    if (!is_part) {
                        bool has_parts = false;
                        for (const auto& pair : unique_by_device) {
                            if (pair.second.parent_device == dev) { has_parts = true; break; }
                        }
                        if (has_parts) continue;
                    }
                    
                    StorUnit u;
                    u.device_path = dev;
                    u.is_mounted = false;
                    u.is_partition = is_part;
                    u.parent_device = parent;
                    u.is_system_disk = (dev == root_dev);
                    
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        if (ioctl(fd, BLKGETSIZE64, &u.total_size) != 0) u.total_size = 0;
                        
                        u.is_encrypted = isUnitEncrypted(dev);
                        if (u.is_encrypted) {
                            EncUnitHdr hdr;
                            if (readHeaderFromDevice(fd, hdr)) {
                                u.fs_info = hdr.fs_info;
                            }
                        }
                        close(fd);
                    }
                    
                    if (u.total_size > 0) {
                        if (!u.is_encrypted) {
                            u.fs_info = getFileSystemInfo(dev);
                            u.label = u.fs_info.label;
                        } else {
                            u.label = u.fs_info.label;
                        }
                        
                        u.device_type = DevDetect::detect(dev);
                        u.has_header_backup = backup_mgr.backupExists(dev);
                        
                        std::string key = dev;
                        unique_by_device[key] = u;
                    }
                }
            }
            closedir(dir);
        }
        
        for (auto& pair : unique_by_device) {
            units.push_back(pair.second);
        }
        
        std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
            if (a.is_system_disk != b.is_system_disk) return a.is_system_disk > b.is_system_disk;
            return a.total_size > b.total_size;
        });
        
        return units;
    }
    
    std::string getInput(const std::string& prompt) {
        std::cout << prompt;
        std::string s;
        std::getline(std::cin, s);
        return s;
    }
    
    bool unmount(StorUnit& u) {
        if (!u.is_mounted) return true;
        std::cout << YELLOW << "Desmontando " << u.mount_point << "..." << RESET << std::endl;
        std::string cmd = "umount -l \"" + u.mount_point + "\" 2>/dev/null";
        int ret = system(cmd.c_str()); (void)ret;
        FILE* mounts = setmntent("/proc/mounts", "r");
        if (mounts) {
            struct mntent* ent;
            while ((ent = getmntent(mounts))) {
                if (u.device_path == ent->mnt_fsname) { endmntent(mounts); return false; }
            }
            endmntent(mounts);
        }
        u.is_mounted = false;
        u.mount_point.clear();
        std::cout << GREEN << "✓ Desmontado" << RESET << std::endl;
        return true;
    }
    
    bool ensureUnmounted(StorUnit& u) {
        if (!u.is_mounted) return true;
        std::cout << YELLOW << "⚠ La unidad está montada en " << u.mount_point << RESET << std::endl;
        std::cout << "¿Desmontar? (S/n): ";
        std::string resp = getInput("");
        if (resp.empty() || resp == "S" || resp == "s") return unmount(u);
        return false;
    }
    
    bool mount(const StorUnit& u, const std::string& point) {
        std::cout << YELLOW << "Montando en " << point << "..." << RESET << std::endl;
        std::string mkdir_cmd = "mkdir -p \"" + point + "\" 2>/dev/null";
        int ret = system(mkdir_cmd.c_str()); (void)ret;
        std::string fs = u.filesystem;
        if (fs.empty() && strlen(u.fs_info.fstype) > 0) {
            std::string safe_fs = u.getSafeFSType();
            if (!safe_fs.empty()) fs = safe_fs;
        }
        std::string cmd;
        if (!fs.empty()) cmd = "mount -t " + fs + " " + u.device_path + " \"" + point + "\" 2>/dev/null";
        else cmd = "mount " + u.device_path + " \"" + point + "\" 2>/dev/null";
        ret = system(cmd.c_str());
        if (ret == 0) { std::cout << GREEN << "✓ Montada en " << point << RESET << std::endl; return true; }
        std::cout << RED << "✗ Error (código: " << ret << ")" << RESET << std::endl;
        return false;
    }
    
    // Helper para convertir secure_vector a string hex
    std::string secureVectorToHex(const Botan::secure_vector<uint8_t>& data) {
        std::string result;
        result.reserve(data.size() * 2);
        for (size_t i = 0; i < data.size(); i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", data[i]);
            result += buf;
        }
        return result;
    }
    
    Botan::secure_vector<uint8_t> getMasterKey() {
        if (useDirectKey) return directKey;
        if (!keyManager) return {};
        
        std::string keyName = currentKeyName;
        if (keyName.empty()) {
            keyName = selectKeyFromManager();
            if (keyName.empty()) return {};
            currentKeyName = keyName;
        }
        
        // FIX: getKeyValue devuelve secure_vector, no string
        Botan::secure_vector<uint8_t> keyBytes = keyManager->getKeyValue(keyName);
        if (keyBytes.empty()) return {};
        
        if (keyBytes.size() != 32) {
            std::cout << RED << "Error: Clave inválida (debe ser 32 bytes, actual: " << keyBytes.size() << ")" << RESET << std::endl;
            return {};
        }
        
        return keyBytes;
    }
    
    std::string selectKeyFromManager() {
        if (!keyManager) return "";
        auto keys = keyManager->getActiveKeys();
        if (keys.empty()) {
            std::cout << YELLOW << "No hay claves activas" << RESET << std::endl;
            return "";
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "CLAVES" << BLUE << "]──────────────────────────────────────────────┐\n";
        for (size_t i = 0; i < keys.size(); i++)
            std::cout << BLUE << "│ " << GREEN << " [" << i+1 << "] " << MAGENTA << keys[i] << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(keys.size()) + BRIGHT_GREEN + "]: " + RESET;
        std::string c = getInput(prompt);
        if (c == "0") return "";
        try {
            int idx = std::stoi(c) - 1;
            if (idx >= 0 && idx < (int)keys.size()) return keys[idx];
        } catch (...) {}
        return "";
    }
    
    void showConfigMenu() {
        while (true) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN" << BLUE << "]──────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << MAGENTA << "CONFIGURACIÓN POR DEFECTO:" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Núcleos: " << GREEN << HWDetect::getCoreCount() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  I/O Threads: " << GREEN << fixed_config.io_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Crypto Threads: " << GREEN << fixed_config.crypto_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Reserved OS: " << GREEN << fixed_config.reserved_os << RESET << std::endl;
            
            if (use_custom_config && custom_config.custom_mode) custom_config.show();
            else std::cout << BLUE << "│ " << YELLOW << "  Modo personalizado: INACTIVO" << RESET << std::endl;
            
            std::cout << BLUE << "│ " << RESET << "\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Configuración personalizada" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Alternar modo personalizado" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione opción [" + BRIGHT_MAGENTA + "0-2" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "1") custom_config.configure();
            else if (c == "2") {
                use_custom_config = !use_custom_config;
                custom_config.custom_mode = use_custom_config;
                custom_config.saveToFile("rubic_config.cfg");
                std::cout << GREEN << "\n✓ Modo personalizado " << (use_custom_config ? "activado" : "desactivado") << RESET << std::endl;
            }
        }
    }
    
    bool processUnit(StorUnit& unit, bool encrypt) {
        if (!checkRoot()) return false;
        
        if (encrypt && unit.is_encrypted) { 
            std::cout << YELLOW << "La unidad ya está cifrada" << RESET << std::endl; 
            return false; 
        }
        if (!encrypt && !unit.is_encrypted) { 
            std::cout << YELLOW << "La unidad no está cifrada" << RESET << std::endl; 
            return false; 
        }
        if (unit.is_system_disk) { 
            std::cout << BRIGHT_RED << "\n⚠ NO SE PUEDE CIFRAR EL DISCO DEL SISTEMA" << RESET << std::endl; 
            return false; 
        }
        if (unit.is_mounted && !ensureUnmounted(unit)) { 
            std::cout << RED << "No se puede continuar con la unidad montada" << RESET << std::endl; 
            return false; 
        }
        
        Botan::secure_vector<uint8_t> master_key = getMasterKey();
        
        if (master_key.empty() || master_key.size() != 32) {
            std::cout << RED << "No se pudo obtener la clave maestra" << RESET << std::endl;
            return false;
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << (encrypt ? "CIFRAR" : "DESCIFRAR") << BLUE << "]─────────────────────────────────────────┐\n";
        std::cout << BLUE << "│ " << RESET << "Unidad: " << CYAN << unit.device_path << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Tamaño: " << YELLOW << unit.getSizeStr() << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Tipo: " << unit.getDevTypeColor() << unit.getDevTypeStr() << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string confirm = getInput("\nEscriba '" + std::string(encrypt ? "CIFRAR" : "DESCIFRAR") + "': ");
        if ((encrypt && confirm != "CIFRAR") || (!encrypt && confirm != "DESCIFRAR")) return false;
        
        stop_requested = false;
        processing_active = true;
        speed_meter.reset();
        stats = Stats();
        
        auto start = std::chrono::high_resolution_clock::now();
        bool ok = doProcess(unit, master_key, encrypt);
        auto end = std::chrono::high_resolution_clock::now();
        
        processing_active = false;
        
        if (ok) {
            stats.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            stats.total_bytes = speed_meter.getTotalBytes();
            stats.print(speed_meter.getAvgSpeed(), speed_meter.getPeakSpeed());
            
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            
            if (!encrypt) {
                std::cout << "\n¿Montar la unidad descifrada? (s/N): ";
                std::string resp;
                std::getline(std::cin, resp);
                if (resp == "s" || resp == "S") {
                    std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                    mount(unit, mp);
                }
            }
            refreshUnits();
        }
        return ok;
    }
    
    bool doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
        ThCfg proc_config;
        if (use_custom_config && custom_config.custom_mode) proc_config.applyCustomConfig(custom_config);
        else proc_config.applyFixedConfig(fixed_config, unit.device_type);
        proc_config.validate();
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "PROCESANDO" << BLUE << "]───────────────────────────────────────────┐\n";
        std::cout << BLUE << "│ " << RESET << "Tipo detectado: " << unit.getDevTypeColor() << unit.getDevTypeStr() << RESET << std::endl;
        
        if (use_custom_config && custom_config.custom_mode) {
            std::cout << BLUE << "│ " << MAGENTA << "Modo: PERSONALIZADO" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Buffer: " << GREEN << custom_config.buffer_size_mb << " MB" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  I/O Threads: " << GREEN << custom_config.io_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Crypto Threads: " << GREEN << custom_config.crypto_threads << RESET << std::endl;
        } else {
            std::cout << BLUE << "│ " << MAGENTA << "Modo: AUTOMÁTICO" << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  I/O Threads: " << GREEN << fixed_config.io_threads << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "  Crypto Threads: " << GREEN << fixed_config.crypto_threads << RESET << std::endl;
        }
        
        std::cout << BLUE << "│ " << RESET << "Chunk: " << YELLOW << proc_config.chunk_size_mb << " MB" << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Modo I/O: " << (proc_config.use_direct_io ? GREEN "DIRECTO" : YELLOW "NORMAL") << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
        
        int flags = O_RDWR | O_SYNC;
        if (proc_config.use_direct_io) flags |= O_DIRECT;
        
        int fd = open(unit.device_path.c_str(), flags);
        if (fd < 0) {
            std::cout << RED << "No se puede abrir: " << strerror(errno) << RESET << std::endl;
            if (proc_config.use_direct_io && errno == EINVAL) {
                std::cout << YELLOW << "Reintentando sin O_DIRECT..." << RESET << std::endl;
                flags &= ~O_DIRECT;
                fd = open(unit.device_path.c_str(), flags);
                if (fd < 0) return false;
                proc_config.use_direct_io = false;
            } else return false;
        }
        
        uint64_t total_size = 0;
        if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) { 
            std::cout << RED << "Error obteniendo tamaño" << RESET << std::endl; 
            close(fd); 
            return false; 
        }
        
        uint64_t total_sectors = total_size / SECTOR_SIZE;
        uint64_t data_start_sector = DATA_OFFSET_SECTORS;
        uint64_t data_sectors = total_sectors - data_start_sector;
        uint64_t data_size = data_sectors * SECTOR_SIZE;
        
        Botan::secure_vector<uint8_t> kdf_salt;
        Botan::secure_vector<uint8_t> xts_key;
        FSInfo fs_info = unit.fs_info;
        
        if (encrypt) {
            std::cout << YELLOW << "\nGenerando salt KDF..." << RESET << std::endl;
            kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
            if (kdf_salt.empty()) { 
                std::cout << RED << "Error generando salt KDF" << RESET << std::endl; 
                close(fd); 
                return false; 
            }
            
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { 
                std::cout << RED << "Error derivando clave secundaria" << RESET << std::endl; 
                close(fd); 
                return false; 
            }
            std::cout << GREEN << "✓ Clave derivada" << RESET << std::endl;
            
            if (strlen(fs_info.fstype) == 0) fs_info = getFileSystemInfo(unit.device_path);
            
            EncUnitHdr hdr;
            memset(&hdr, 0, sizeof(hdr));
            memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
            hdr.version = HEADER_VERSION_CURRENT;
            hdr.data_start_sector = data_start_sector;
            hdr.total_sectors = total_sectors;
            hdr.fs_info = fs_info;
            
            try {
                HMACProc hmac(master_key);
                auto hmac_result = hmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, hmac));
                if (hmac_result.size() == HMAC_SIZE) memcpy(hdr.hmac, hmac_result.data(), HMAC_SIZE);
                else { 
                    std::cout << RED << "Error: Tamaño de HMAC incorrecto" << RESET << std::endl; 
                    close(fd); 
                    return false; 
                }
            } catch (const std::exception& e) {
                std::cout << RED << "Error calculando HMAC: " << e.what() << RESET << std::endl; 
                close(fd); 
                return false;
            }
            
            if (!backup_mgr.saveHeader(unit.device_path, hdr, master_key))
                std::cout << YELLOW << "Advertencia: No se pudo guardar backup" << RESET << std::endl;
            
            if (!writeHeaderToDevice(fd, hdr)) {
                std::cout << RED << "Error escribiendo header: " << strerror(errno) << RESET << std::endl; 
                close(fd); 
                return false;
            }
            fsync(fd);
            std::cout << GREEN << "✓ Header escrito" << RESET << std::endl;
        } else {
            EncUnitHdr hdr;
            if (!readHeaderFromDevice(fd, hdr)) {
                if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
                    std::cout << YELLOW << "Header recuperado desde backup" << RESET << std::endl;
                else { 
                    std::cout << RED << "No se pudo leer header" << RESET << std::endl; 
                    close(fd); 
                    return false; 
                }
            }
            
            if (hdr.version < 2) {
                std::cout << YELLOW << "Versión antigua (sin KDF)" << RESET << std::endl;
                xts_key.resize(64);
                memcpy(xts_key.data(), master_key.data(), 32);
                memcpy(xts_key.data() + 32, master_key.data(), 32);
            } else {
                kdf_salt.resize(KDF_SALT_SIZE);
                memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
                xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
                if (xts_key.empty()) { 
                    std::cout << RED << "Error derivando clave" << RESET << std::endl; 
                    close(fd); 
                    return false; 
                }
                std::cout << GREEN << "✓ Clave derivada" << RESET << std::endl;
            }
            
            try {
                HMACProc hmac(master_key);
                if (!hmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, hmac), hdr.hmac, HMAC_SIZE)) {
                    std::cout << RED << "Error: Autenticación HMAC falló" << RESET << std::endl; 
                    close(fd); 
                    return false;
                }
            } catch (const std::exception& e) {
                std::cout << RED << "Error verificando HMAC: " << e.what() << RESET << std::endl; 
                    close(fd); 
                return false;
            }
            std::cout << GREEN << "✓ Header verificado" << RESET << std::endl;
            
            fs_info = hdr.fs_info;
            data_start_sector = hdr.data_start_sector;
            data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
        }
        
        std::cout << "\nDatos a procesar: " << GREEN << StorUnit::formatBytes(data_size) << RESET << std::endl;
        
        size_t chunk_size = proc_config.getChunkSize();
        uint64_t total_chunks = (data_size + chunk_size - 1) / chunk_size;
        
        std::cout << "Procesando " << total_chunks << " chunks..." << std::endl;
        std::cout << (proc_config.use_direct_io ? "Usando I/O Directo" : "Usando I/O normal") << RESET << std::endl << std::endl;
        
        LimQueue<PipeChunk> read_queue(MAX_QUEUE_SIZE);
        LimQueue<PipeChunk> write_queue(MAX_QUEUE_SIZE);
        
        std::atomic<uint64_t> chunks_done{0};
        std::atomic<uint64_t> bytes_processed{0};
        std::atomic<bool> error{false};
        
        ProgBar progress_bar(50, "", "");
        progress_bar.setTotal(data_size);
        
        std::thread reader_thread([&]() {
            for (uint64_t c = 0; c < total_chunks && !error && !stop_requested; c++) {
                PipeChunk chunk(chunk_size, proc_config.use_direct_io);
                chunk.index = c;
                chunk.offset = (data_start_sector * SECTOR_SIZE) + (c * chunk_size);
                chunk.size = chunk_size;
                if (chunk.offset + chunk.size > total_size) chunk.size = total_size - chunk.offset;
                chunk.start_sector = chunk.offset / SECTOR_SIZE;
                
                ssize_t bytes_read = pread(fd, chunk.data->data(), chunk.size, chunk.offset);
                if (bytes_read != (ssize_t)chunk.size) {
                    std::cout << RED << "\nError de lectura en chunk " << c << ": " << strerror(errno) << RESET << std::endl;
                    error = true;
                    break;
                }
                read_queue.push(std::move(chunk));
            }
            read_queue.close();
        });
        
        int num_cpu_threads = (use_custom_config && custom_config.custom_mode) ? custom_config.crypto_threads : fixed_config.crypto_threads;
        std::vector<std::thread> cpu_threads;
        
        for (int t = 0; t < num_cpu_threads; t++) {
            cpu_threads.emplace_back([&, t]() {
                AESXTSProc proc(xts_key, encrypt);
                PipeChunk chunk(chunk_size, proc_config.use_direct_io);
                while (read_queue.pop(chunk) && !error && !stop_requested) {
                    if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                        std::cout << RED << "\nError procesando chunk " << chunk.index << RESET << std::endl;
                        error = true;
                        break;
                    }
                    write_queue.push(std::move(chunk));
                    chunk = PipeChunk(chunk_size, proc_config.use_direct_io);
                }
            });
        }
        
        std::thread writer_thread([&]() {
            PipeChunk chunk(chunk_size, proc_config.use_direct_io);
            uint64_t expected_index = 0;
            std::vector<PipeChunk> out_of_order;
            
            while (!error && !stop_requested && expected_index < total_chunks) {
                if (write_queue.pop(chunk)) {
                    if (chunk.index == expected_index) {
                        ssize_t bytes_written = pwrite(fd, chunk.data->data(), chunk.size, chunk.offset);
                        if (bytes_written != (ssize_t)chunk.size) {
                            std::cout << RED << "\nError de escritura en chunk " << chunk.index << ": " << strerror(errno) << RESET << std::endl;
                            error = true;
                            break;
                        }
                        chunks_done++;
                        bytes_processed += chunk.size;
                        speed_meter.addBytes(chunk.size);
                        progress_bar.update(bytes_processed.load());
                        expected_index++;
                        
                        int flush_interval = (unit.device_type == DevType::HDD || unit.device_type == DevType::USB2) ? 2 : 1;
                        if (chunk.index % flush_interval == 0) fsync(fd);
                        
                        auto it = out_of_order.begin();
                        while (it != out_of_order.end()) {
                            if (it->index == expected_index) {
                                bytes_written = pwrite(fd, it->data->data(), it->size, it->offset);
                                if (bytes_written != (ssize_t)it->size) { error = true; break; }
                                chunks_done++;
                                bytes_processed += it->size;
                                speed_meter.addBytes(it->size);
                                progress_bar.update(bytes_processed.load());
                                expected_index++;
                                it = out_of_order.erase(it);
                            } else ++it;
                        }
                    } else if (chunk.index > expected_index) {
                        out_of_order.push_back(std::move(chunk));
                        chunk = PipeChunk(chunk_size, proc_config.use_direct_io);
                    }
                }
            }
            write_queue.close();
        });
        
        auto last_prog = std::chrono::steady_clock::now();
        int last_prog_value = -1;
        
        while (!error && !stop_requested && chunks_done < total_chunks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_prog).count() >= PROGRESS_UPDATE_MS) {
                uint64_t done = chunks_done;
                int prog = (done * 100) / total_chunks;
                if (prog != last_prog_value) { progress_bar.update(bytes_processed.load()); last_prog_value = prog; }
                last_prog = now;
            }
        }
        
        progress_bar.finish();
        read_queue.close();
        write_queue.close();
        
        if (reader_thread.joinable()) reader_thread.join();
        for (auto& t : cpu_threads) if (t.joinable()) t.join();
        if (writer_thread.joinable()) writer_thread.join();
        
        fsync(fd);
        
        if (!encrypt && !error && !stop_requested) {
            std::cout << YELLOW << "\nEliminando header y backup..." << RESET << std::endl;
            off_t header_offset = HEADER_OFFSET_SECTORS * SECTOR_SIZE;
            size_t header_size = HEADER_SECTORS * SECTOR_SIZE;
            std::vector<uint8_t> zeros(header_size, 0);
            if (pwrite(fd, zeros.data(), header_size, header_offset) == (ssize_t)header_size) {
                fsync(fd);
                std::cout << GREEN << "✓ Header eliminado" << RESET << std::endl;
            }
            if (backup_mgr.removeBackup(unit.device_path)) std::cout << GREEN << "✓ Backup eliminado" << RESET << std::endl;
        }
        
        close(fd);
        stats.total_bytes = bytes_processed.load();
        
        if (error) std::cout << RED << "\n✗ Error durante el procesamiento" << RESET << std::endl;
        else if (stop_requested) std::cout << YELLOW << "\n⚠ Procesamiento detenido" << RESET << std::endl;
        else std::cout << GREEN << "\n✓ Procesamiento completado" << RESET << std::endl;
        
        return !error && (chunks_done == total_chunks) && !stop_requested;
    }
    
public:
    UnitEncryptor() : keyManager(nullptr), use_custom_config(false), last_refresh(0), useDirectKey(false) {
        fixed_config = FixedThCfg::getConfigForSystem();
        custom_config.loadFromFile("rubic_config.cfg");
        use_custom_config = custom_config.custom_mode;
        refreshUnits();
    }
    
    void setKeyManager(KeyManager* km) { 
        keyManager = km; 
        useDirectKey = false;
    }
    
    void setDirectKey(const Botan::secure_vector<uint8_t>& key) {
        directKey = key;
        useDirectKey = true;
        keyManager = nullptr;
    }
    
    void setDirectKeyHex(const std::string& hexKey) {
        try {
            Botan::secure_vector<uint8_t> key(32);
            for (size_t i = 0; i < 32 && i + 1 < hexKey.length(); i += 2) {
                key[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
            }
            directKey = key;
            useDirectKey = true;
            keyManager = nullptr;
        } catch (...) {
            useDirectKey = false;
        }
    }
    
    bool hasKey() const {
        if (useDirectKey) return !directKey.empty();
        return keyManager != nullptr && !keyManager->getActiveKeys().empty();
    }
    
    void showMenu() {
        while (true) {
            if (geteuid() != 0) {
                std::cout << BRIGHT_RED << "\nRequiere root" << RESET << std::endl;
                getInput("Enter...");
                break;
            }
            
            refreshUnits();
            
            std::cout << BLUE;
            std::cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│" << GREEN << BOLD << "                       CIFRADOR DE UNIDADES                          " << BLUE << "│\n";
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << "│" << MAGENTA << "  " << HWDetect::getCPUInfo() << BLUE << "                                          │\n";
            if (use_custom_config && custom_config.custom_mode)
                std::cout << "│" << YELLOW << "  Modo personalizado activo                                          " << BLUE << "│\n";
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            if (cached_units.empty()) {
                std::cout << YELLOW << "\nNo hay unidades detectadas" << RESET << std::endl;
            } else {
                std::cout << GREEN << "\nUNIDADES DETECTADAS:" << RESET << std::endl;
                for (size_t i = 0; i < cached_units.size(); i++) {
                    auto& u = cached_units[i];
                    std::string icon = u.is_system_disk ? "S" : (u.is_encrypted ? "E" : "N");
                    if (u.has_header_backup && u.is_encrypted) icon += "B";
                    
                    std::cout << "  [" << GREEN << i+1 << RESET << "] " << icon << " ";
                    std::cout << (u.is_encrypted ? BRIGHT_RED : GREEN) << std::setw(7) 
                              << (u.is_system_disk ? "SISTEMA" : (u.is_encrypted ? "CIFRADA" : "NORMAL")) << RESET;
                    std::cout << " " << CYAN << u.device_path << RESET;
                    
                    if (!u.label.empty()) std::cout << " (" << u.label << ")";
                    std::cout << " - " << u.getSizeStr();
                    std::cout << " " << u.getDevTypeColor() << "[" << u.getDevTypeStr() << "]" << RESET;
                    if (u.is_mounted) std::cout << " (M)";
                    if (u.has_header_backup) std::cout << " [B]";
                    
                    std::string safe_fs = u.getSafeFSType();
                    if (u.is_encrypted && !safe_fs.empty()) {
                        std::cout << " → " << GREEN << safe_fs << RESET;
                    } else if (!u.is_encrypted && !u.filesystem.empty()) {
                        std::cout << " → " << GREEN << u.filesystem << RESET;
                    }
                    
                    std::cout << std::endl;
                }
            }
            
            std::cout << BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << GREEN << " [" << MAGENTA << "1-" << cached_units.size() << GREEN << "] " << MAGENTA << "Seleccionar unidad" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [C] " << MAGENTA << "Configuración" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [R] " << MAGENTA << "Refrescar" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Salir" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(cached_units.size()) + ",C,R" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "R" || c == "r") { refreshUnits(); continue; }
            else if (c == "C" || c == "c") showConfigMenu();
            else {
                try {
                    int idx = std::stoi(c) - 1;
                    if (idx >= 0 && idx < (int)cached_units.size()) {
                        unitMenu(cached_units[idx]);
                        refreshUnits();
                    }
                } catch (...) {}
            }
        }
    }
    
    void unitMenu(StorUnit& u) {
        while (true) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << u.device_path << BLUE << "]────────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << RESET << "Tamaño: " << GREEN << u.getSizeStr() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Tipo: " << u.getDevTypeColor() << u.getDevTypeStr() << RESET << std::endl;
            std::cout << BLUE << "│ " << RESET << "Estado: " << (u.is_encrypted ? BRIGHT_RED "CIFRADA" : GREEN "SIN CIFRAR") << RESET << std::endl;
            
            if (u.has_header_backup && u.is_encrypted)
                std::cout << BLUE << "│ " << GREEN << "Backup disponible" << RESET << std::endl;
            if (!u.mount_point.empty())
                std::cout << BLUE << "│ " << RESET << "Montada en: " << YELLOW << u.mount_point << RESET << std::endl;
            if (u.is_system_disk)
                std::cout << BLUE << "│ " << BRIGHT_RED << "⚠ DISCO DEL SISTEMA - OPERACIONES RESTRINGIDAS" << RESET << std::endl;
            
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            
            if (!u.is_system_disk)
                std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << (u.is_encrypted ? "Descifrar unidad" : "Cifrar unidad") << RESET << std::endl;
            
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Montar unidad" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "Desmontar unidad" << RESET << std::endl;
            
            if (!u.is_system_disk)
                std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "Formatear unidad" << RESET << std::endl;
            if (u.is_encrypted && u.has_header_backup)
                std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "Restaurar header desde backup" << RESET << std::endl;
            
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-5" + BRIGHT_GREEN + "]: " + RESET;
            std::string c = getInput(prompt);
            
            if (c == "0") break;
            else if (c == "1" && !u.is_system_disk) {
                if (processUnit(u, !u.is_encrypted)) getInput("\nPresione Enter para continuar...");
                refreshUnits();
            }
            else if (c == "2") {
                if (!u.is_mounted) {
                    std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                    std::cout << "Punto de montaje [" << mp << "]: ";
                    std::string input;
                    std::getline(std::cin, input);
                    if (!input.empty()) mp = input;
                    if (mount(u, mp)) { u.is_mounted = true; u.mount_point = mp; }
                } else std::cout << YELLOW << "Ya montada en " << u.mount_point << RESET << std::endl;
                getInput("\nPresione Enter para continuar...");
            }
            else if (c == "3") {
                if (u.is_mounted) unmount(u);
                else std::cout << YELLOW << "La unidad no está montada" << RESET << std::endl;
                getInput("\nPresione Enter para continuar...");
            }
            else if (c == "4" && !u.is_system_disk) {
                if (u.is_mounted) unmount(u);
                Botan::secure_vector<uint8_t> key = getMasterKey();
                Formatter::showMenu(u, key);
                getInput("\nPresione Enter para continuar...");
                refreshUnits();
            }
            else if (c == "5" && u.is_encrypted && u.has_header_backup) {
                std::cout << YELLOW << "Restaurando header desde backup..." << RESET << std::endl;
                Botan::secure_vector<uint8_t> master_key = getMasterKey();
                if (master_key.empty()) { 
                    std::cout << RED << "No se pudo obtener la clave" << RESET << std::endl; 
                    continue; 
                }
                
                EncUnitHdr hdr;
                if (backup_mgr.loadHeader(u.device_path, hdr, master_key)) {
                    int fd = open(u.device_path.c_str(), O_RDWR | O_SYNC);
                    if (fd >= 0) {
                        if (writeHeaderToDevice(fd, hdr)) 
                            std::cout << GREEN << "✓ Header restaurado correctamente" << RESET << std::endl;
                        else 
                            std::cout << RED << "✗ Error escribiendo header" << RESET << std::endl;
                        close(fd);
                    } else 
                        std::cout << RED << "✗ No se pudo abrir dispositivo" << RESET << std::endl;
                } else 
                    std::cout << RED << "✗ No se pudo cargar backup" << RESET << std::endl;
                getInput("\nPresione Enter para continuar...");
                refreshUnits();
            }
        }
    }
    
    void stop() { if (processing_active) stop_requested = true; }
};

#endif // UNIT_ENCRYPTOR_H