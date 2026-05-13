// universal_cipher.h - 0.1 alpha

#ifndef UNIVERSAL_CIPHER_H
#define UNIVERSAL_CIPHER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <future>
#include <memory>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <random>
#include <filesystem>
#include <algorithm>
#include <limits>
#include <array>
#include <map>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <deque>
#include <list>
#include <fcntl.h>
#include <errno.h>
#include <csignal>
#include <botan/auto_rng.h>
#include <botan/secmem.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/aead.h>
#include <botan/stream_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/version.h>
#include <botan/base64.h>
#include <botan/system_rng.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>

// Forward declaration
class KeyManager;

// PERMISOS //quitarlo poque main verifica
class UserPermissions {
public:
    static void fixFilePermissions(const std::string& path) {
        const char* sudo_uid = getenv("SUDO_UID");
        uid_t uid = sudo_uid ? static_cast<uid_t>(std::stoul(sudo_uid)) : getuid();
        const char* sudo_gid = getenv("SUDO_GID");
        gid_t gid = sudo_gid ? static_cast<gid_t>(std::stoul(sudo_gid)) : getgid();
        
        // Intentar cambiar permisos, ignorar errores (best effort)
        chown(path.c_str(), uid, gid);
        chmod(path.c_str(), S_IRUSR | S_IWUSR);
    }
};

// ***************************************************
// CLASE RAII PARA OPERACIONES CON ARCHIVOS

class FileRAII {
private:
    int fd;
    std::string path;
    bool is_open;
    
public:
    FileRAII() : fd(-1), is_open(false) {}
    
    explicit FileRAII(const std::string& file_path, int flags, mode_t mode = 0644) 
        : fd(-1), path(file_path), is_open(false) {
        open(file_path, flags, mode);
    }
    
    ~FileRAII() {
        close();
    }
    
    bool open(const std::string& file_path, int flags, mode_t mode = 0644) {
        if (is_open) close();
        
        fd = ::open(file_path.c_str(), flags, mode);
        if (fd >= 0) {
            is_open = true;
            path = file_path;
        }
        return is_open;
    }
    
    void close() {
        if (is_open && fd >= 0) {
            ::close(fd);
            fd = -1;
            is_open = false;
        }
    }
    
    int get() const { return fd; }
    bool valid() const { return is_open && fd >= 0; }
    
    FileRAII(FileRAII&& other) noexcept 
        : fd(other.fd), path(std::move(other.path)), is_open(other.is_open) {
        other.fd = -1;
        other.is_open = false;
    }
    
    FileRAII& operator=(FileRAII&& other) noexcept {
        if (this != &other) {
            close();
            fd = other.fd;
            path = std::move(other.path);
            is_open = other.is_open;
            other.fd = -1;
            other.is_open = false;
        }
        return *this;
    }
    
    FileRAII(const FileRAII&) = delete;
    FileRAII& operator=(const FileRAII&) = delete;
};

//*************************************** 
// RAII MAPEAR MEMORIA
class MMapRAII {
private:
    void* data;
    size_t size;
    int fd;
    bool is_mapped;
    
public:
    MMapRAII() : data(nullptr), size(0), fd(-1), is_mapped(false) {}
    
    ~MMapRAII() {
        unmap();
    }
    
    bool map(int file_fd, size_t file_size, int prot = PROT_READ, int flags = MAP_PRIVATE) {
        if (is_mapped) unmap();
        
        data = mmap(nullptr, file_size, prot, flags, file_fd, 0);
        if (data == MAP_FAILED) {
            data = nullptr;
            return false;
        }
        
        size = file_size;
        fd = file_fd;
        is_mapped = true;
        
        madvise(data, size, MADV_SEQUENTIAL);
        
        return true;
    }
    
    void unmap() {
        if (is_mapped && data && data != MAP_FAILED) {
            munmap(data, size);
            data = nullptr;
            is_mapped = false;
        }
    }
    
    void* get() const { return data; }
    size_t get_size() const { return size; }
    bool valid() const { return is_mapped && data && data != MAP_FAILED; }
    
    MMapRAII(MMapRAII&& other) noexcept 
        : data(other.data), size(other.size), fd(other.fd), is_mapped(other.is_mapped) {
        other.data = nullptr;
        other.is_mapped = false;
    }
    
    MMapRAII& operator=(MMapRAII&& other) noexcept {
        if (this != &other) {
            unmap();
            data = other.data;
            size = other.size;
            fd = other.fd;
            is_mapped = other.is_mapped;
            other.data = nullptr;
            other.is_mapped = false;
        }
        return *this;
    }
    
    MMapRAII(const MMapRAII&) = delete;
    MMapRAII& operator=(const MMapRAII&) = delete;
};

// *******************************************
//  BLOQUEO DE MEMORIA

class MemoryLockRAII {
private:
    void* ptr;
    size_t size;
    bool locked;
    
public:
    MemoryLockRAII(void* memory_ptr, size_t memory_size) 
        : ptr(memory_ptr), size(memory_size), locked(false) {
        lock();
    }
    
    ~MemoryLockRAII() {
        unlock();
    }
    
    bool lock() {
        if (locked || !ptr || size == 0) return false;
        
#ifdef __unix__
        if (mlock(ptr, size) == 0) {
            locked = true;
            return true;
        }
#endif
        return false;
    }
    
    void unlock() {
        if (locked && ptr && size > 0) {
#ifdef __unix__
            munlock(ptr, size);
#endif
            locked = false;
        }
    }
    
    MemoryLockRAII(const MemoryLockRAII&) = delete;
    MemoryLockRAII& operator=(const MemoryLockRAII&) = delete;
};
//************************************************ */
// CONFIGURACIÓN DE HILOS

struct ThreadCfg {
    size_t total_system_threads;
    size_t crypto_threads;
    size_t io_threads;
    size_t reserved_os;
    
    static ThreadCfg getConfig(size_t system_threads) {
        ThreadCfg config;
        config.total_system_threads = system_threads;
        
        if (system_threads <= 2) {
            config.io_threads = 1;
            config.crypto_threads = 1;
            config.reserved_os = 0;
        }
        else if (system_threads <= 4) {
            config.io_threads = 2;
            config.crypto_threads = 2;
            config.reserved_os = 0;
        }//meter de 6 hilos xd
        else if (system_threads <= 8) {
            config.io_threads = 2;
            config.crypto_threads = 5;
            config.reserved_os = 1;
        }
        else if (system_threads <= 16) {
            config.io_threads = 3;
            config.crypto_threads = 11;
            config.reserved_os = 2;
        }
        else if (system_threads <= 32) {
            config.io_threads = 4;
            config.crypto_threads = 24;
            config.reserved_os = 4;
        }
        else {
            config.io_threads = 6;
            config.crypto_threads = system_threads - 8;
            config.reserved_os = 2;
        }
        
        return config;
    }
    
    void print() const {
        std::cout << BLUE << "│ " << RESET << "  Hilos sistema: " << GREEN << total_system_threads << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "  → Cifrado: " << GREEN << crypto_threads << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "  → I/O: " << GREEN << io_threads << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "  → Reservados SO: " << YELLOW << reserved_os << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "  → Total usado: " << CYAN << (crypto_threads + io_threads) << RESET << std::endl;
    }
};

// *******************************************
// CONFIGURACIÓN

struct SystemConfig {
    ThreadCfg thread_config;
    
    size_t min_buffer_size = 512 * 1024;
    size_t max_buffer_size = 8 * 1024 * 1024;
    size_t optimal_buffer_size = 2 * 1024 * 1024;
    
    size_t queue_size = 64;
    size_t max_files_per_second = 1000;
    size_t max_bytes_per_second = 1024 * 1024 * 1024;
    
    bool verify_integrity = true;
    bool use_hardware_rng = true;
    size_t nonce_size = 12;
    bool use_header_hmac = true;
    
    bool show_progress = true;
    bool show_detailed_stats = false;
    
    uint64_t max_file_size = std::numeric_limits<uint64_t>::max();
    std::string output_extension = ".enc";
    
    size_t name_cache_size = 1024;
    size_t max_retries = 3;
    size_t retry_delay_ms = 100;
    
    static constexpr size_t GCM_TAG_SIZE = 16;
    size_t max_parallel_files = 4;
    size_t mmap_threshold = 1024 * 1024;
    
    std::string counter_file_path = ".cipher_counters.dat";
    std::string name_key_file_path = ".cipher_namekey.dat";
    
    size_t get_dynamic_buffer_size(uint64_t file_size) const {
        if (file_size < 1024 * 1024) return min_buffer_size;
        if (file_size < 10 * 1024 * 1024) return optimal_buffer_size;
        return max_buffer_size;
    }
    
    bool should_use_mmap(uint64_t file_size) const {
        return file_size >= mmap_threshold;
    }
    
    void autoConfigure(size_t system_threads) {
        thread_config = ThreadCfg::getConfig(system_threads);
        queue_size = thread_config.crypto_threads * 8;
        max_parallel_files = thread_config.crypto_threads;
    }
    
    void print() const {
        std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
        std::cout << BLUE << "│ " << MAGENTA << "CONFIGURACIÓN ACTUAL:" << RESET << std::endl;
        thread_config.print();
        std::cout << BLUE << "│ " << RESET << "Buffer: " << GREEN << (min_buffer_size/1024) << "KB - " 
                  << (max_buffer_size/(1024*1024)) << "MB" << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Reintentos: " << GREEN << max_retries << RESET 
                  << " (delay " << retry_delay_ms << "ms)" << std::endl;
        std::cout << BLUE << "│ " << RESET << "mmap (> " << (mmap_threshold/(1024*1024)) << "MB): " 
                  << GREEN << (should_use_mmap(mmap_threshold) ? "✓" : "✗") << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Archivos paralelos: " << GREEN << max_parallel_files << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "HMAC header: " << GREEN << (use_header_hmac ? "Sí" : "No") << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
    }
};

// **********************************
// UTILIDAD DE COMPARACIÓN CONSTANTE

class ConstantTime {
public:
    static bool compare(const uint8_t* a, const uint8_t* b, size_t len) {
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < len; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
};

//************************ */
// MEMORIA SEGURA

class SecMemGuard {
public:
    static bool lock_memory(void* ptr, size_t size) {
        if (ptr && size > 0) {
            MemoryLockRAII lock(ptr, size);
            return lock.lock();
        }
        return false;
    }
    
    static void secure_memset(void* ptr, int value, size_t num) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (num--) *p++ = static_cast<unsigned char>(value);
    }
};

// *****************************************
// GENERADOR DE NÚMEROS ALEATORIOS

class SecureRandom {
private:
    static Botan::AutoSeeded_RNG& getBotanRNG() {
        static Botan::AutoSeeded_RNG rng;
        return rng;
    }
    
    static Botan::System_RNG& getHardwareRNG() {
        static Botan::System_RNG rng;
        return rng;
    }
    
    static bool use_hardware;
    
public:
    static void setUseHardware(bool use) { use_hardware = use; }
    
    static void generate_bytes(uint8_t* data, size_t size) {
        if (use_hardware) {
            getHardwareRNG().randomize(data, size);
        } else {
            getBotanRNG().randomize(data, size);
        }
    }
    
    static Botan::secure_vector<uint8_t> secure_random(size_t size) {
        Botan::secure_vector<uint8_t> result(size);
        generate_bytes(result.data(), size);
        return result;
    }
    
    static uint64_t random_uint64() {
        uint64_t value;
        generate_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        return value;
    }
};

bool SecureRandom::use_hardware = true;

// **********************************
// HMAC PARA HEADER

class HeaderHMAC {
private:
    Botan::secure_vector<uint8_t> hmac_key;
    
public:
    HeaderHMAC() = default;
    
    void set_key(const Botan::secure_vector<uint8_t>& master_key) {
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(master_key);
        hash->update("HEADER_HMAC");
        hmac_key = hash->final();
    }
    
    Botan::secure_vector<uint8_t> calculate(const uint8_t* data, size_t len) {
        auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
        hmac->set_key(hmac_key);
        hmac->update(data, len);
        return hmac->final();
    }
    
    bool verify(const uint8_t* data, size_t len, const uint8_t* mac, size_t mac_len) {
        auto calculated = calculate(data, len);
        if (calculated.size() != mac_len) return false;
        return ConstantTime::compare(calculated.data(), mac, mac_len);
    }
};

// ****************************************
// RATE LIMITER

class RateLimiter {
private:
    std::chrono::steady_clock::time_point window_start;
    std::atomic<size_t> files_processed;
    std::atomic<size_t> bytes_processed;
    size_t max_files_per_second;
    size_t max_bytes_per_second;
    std::mutex rate_mutex;
    
public:
    RateLimiter(size_t max_files = 1000, size_t max_bytes = 1024 * 1024 * 1024)
        : max_files_per_second(max_files), max_bytes_per_second(max_bytes) {
        reset();
    }
    
    void reset() {
        window_start = std::chrono::steady_clock::now();
        files_processed = 0;
        bytes_processed = 0;
    }
    
    void wait_if_needed(size_t bytes = 0) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - window_start).count();
        
        if (elapsed >= 1000) {
            window_start = now;
            files_processed = 0;
            bytes_processed = 0;
        }
        
        files_processed++;
        bytes_processed += bytes;
        
        if (files_processed > max_files_per_second || bytes_processed > max_bytes_per_second) {
            size_t wait_ms = 1000 - elapsed;
            if (wait_ms > 0 && wait_ms < 1000) {
                std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
            }
        }
    }
    
    void setLimits(size_t max_files, size_t max_bytes) {
        max_files_per_second = max_files;
        max_bytes_per_second = max_bytes;
    }
};

// ***********************************
// COLA DE TRABAJO

template<typename T>
class WorkQueue {
private:
    std::deque<T> queue;
    std::mutex mutex;
    std::condition_variable not_empty;
    std::condition_variable not_full;
    std::atomic<bool> stopped{false};
    size_t max_size;
    std::atomic<size_t> queue_size{0};
    
public:
    WorkQueue(size_t max_sz = 64) : max_size(max_sz) {}
    
    ~WorkQueue() {
        stop();
    }
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_full.wait(lock, [this]() { return queue.size() < max_size || stopped; });
        if (stopped) return;
        queue.push_back(std::move(item));
        queue_size++;
        not_empty.notify_one();
    }
    
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_empty.wait(lock, [this]() { return !queue.empty() || stopped; });
        if (stopped && queue.empty()) return false;
        item = std::move(queue.front());
        queue.pop_front();
        queue_size--;
        not_full.notify_one();
        return true;
    }
    
    void stop() {
        stopped = true;
        not_empty.notify_all();
        not_full.notify_all();
    }
    
    size_t size() const { return queue_size.load(); }
};

// ********************************************
// ESTRUCTURA  DE ARCHIVO

struct FileWork {
    std::string input_path;
    std::string output_path;
    bool is_encrypt;
    std::promise<bool> result_promise;
    uint64_t file_size;
    int retry_count;
    
    FileWork() : is_encrypt(true), file_size(0), retry_count(0) {}
    
    FileWork(FileWork&& other) noexcept 
        : input_path(std::move(other.input_path)),
          output_path(std::move(other.output_path)),
          is_encrypt(other.is_encrypt),
          result_promise(std::move(other.result_promise)),
          file_size(other.file_size),
          retry_count(other.retry_count) {}
    
    FileWork& operator=(FileWork&& other) noexcept {
        if (this != &other) {
            input_path = std::move(other.input_path);
            output_path = std::move(other.output_path);
            is_encrypt = other.is_encrypt;
            result_promise = std::move(other.result_promise);
            file_size = other.file_size;
            retry_count = other.retry_count;
        }
        return *this;
    }
    
    FileWork(const FileWork&) = delete;
    FileWork& operator=(const FileWork&) = delete;
};

// *******************************************
// GESTOR DE CLAVE PARA NOMBRES

class NameKeyMgr {
private:
    std::string key_file_path;
    Botan::secure_vector<uint8_t> master_key;
    Botan::secure_vector<uint8_t> name_key;
    bool initialized = false;
    
    Botan::secure_vector<uint8_t> derive_name_key(const Botan::secure_vector<uint8_t>& master) {
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(master);
        hash->update("NAME_OBFUSCATION_KEY_V1");
        return hash->final();
    }
    
    bool write_full(int fd, const void* data, size_t size) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        size_t remaining = size;
        while (remaining > 0) {
            ssize_t written = write(fd, ptr, remaining);
            if (written <= 0) return false;
            ptr += written;
            remaining -= written;
        }
        return true;
    }
    
    bool read_full(int fd, void* data, size_t size) {
        uint8_t* ptr = static_cast<uint8_t*>(data);
        size_t remaining = size;
        while (remaining > 0) {
            ssize_t read_bytes = read(fd, ptr, remaining);
            if (read_bytes <= 0) return false;
            ptr += read_bytes;
            remaining -= read_bytes;
        }
        return true;
    }
    
    bool save_master_key() {
        FileRAII file(key_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (!file.valid()) return false;
        
        Botan::secure_vector<uint8_t> salt = SecureRandom::secure_random(16);
        
        auto pbkdf2_family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
        auto pbkdf2 = pbkdf2_family->from_params(100000);
        
        Botan::secure_vector<uint8_t> storage_key(32);
        std::string machine_id = "RUBIC_CIPHER_V1";
        
        pbkdf2->hash(storage_key, machine_id, salt);
        
        auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
        cipher->set_key(storage_key);
        Botan::secure_vector<uint8_t> iv = SecureRandom::secure_random(16);
        cipher->start(iv);
        
        Botan::secure_vector<uint8_t> encrypted = master_key;
        cipher->finish(encrypted);
        
        if (!write_full(file.get(), salt.data(), 16) ||
            !write_full(file.get(), iv.data(), 16) ||
            !write_full(file.get(), encrypted.data(), encrypted.size())) {
            return false;
        }
        
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(salt);
        hash->update(iv);
        hash->update(encrypted);
        auto checksum = hash->final();
        
        if (!write_full(file.get(), checksum.data(), checksum.size())) {
            return false;
        }
        
        fsync(file.get());
        return true;
    }
    
    bool load_master_key() {
        FileRAII file(key_file_path, O_RDONLY);
        if (!file.valid()) return false;
        
        struct stat st;
        if (fstat(file.get(), &st) != 0) return false;
        if (st.st_size < 112) return false;
        
        std::vector<uint8_t> buffer(st.st_size);
        if (!read_full(file.get(), buffer.data(), buffer.size())) return false;
        
        size_t pos = 0;
        
        Botan::secure_vector<uint8_t> salt(16);
        std::memcpy(salt.data(), buffer.data() + pos, 16);
        pos += 16;
        
        Botan::secure_vector<uint8_t> iv(16);
        std::memcpy(iv.data(), buffer.data() + pos, 16);
        pos += 16;
        
        size_t encrypted_size = st.st_size - pos - 32;
        Botan::secure_vector<uint8_t> encrypted(encrypted_size);
        std::memcpy(encrypted.data(), buffer.data() + pos, encrypted_size);
        pos += encrypted_size;
        
        Botan::secure_vector<uint8_t> stored_checksum(32);
        std::memcpy(stored_checksum.data(), buffer.data() + pos, 32);
        
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(salt);
        hash->update(iv);
        hash->update(encrypted);
        auto calculated_checksum = hash->final();
        
        if (calculated_checksum.size() != stored_checksum.size() ||
            !ConstantTime::compare(calculated_checksum.data(), stored_checksum.data(), 32)) {
            return false;
        }
        
        auto pbkdf2_family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
        auto pbkdf2 = pbkdf2_family->from_params(100000);
        
        Botan::secure_vector<uint8_t> storage_key(32);
        std::string machine_id = "RUBIC_CIPHER_V1";
        
        pbkdf2->hash(storage_key, machine_id, salt);
        
        auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
        cipher->set_key(storage_key);
        cipher->start(iv);
        
        try {
            cipher->finish(encrypted);
            master_key = encrypted;
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
    
public:
    NameKeyMgr(const std::string& key_file) : key_file_path(key_file) {
        if (load_master_key()) {
            name_key = derive_name_key(master_key);
            initialized = true;
        } else {
            master_key = SecureRandom::secure_random(32);
            name_key = derive_name_key(master_key);
            if (save_master_key()) {
                initialized = true;
            }
        }
    }
    
    ~NameKeyMgr() {
        if (!master_key.empty()) {
            SecMemGuard::secure_memset(master_key.data(), 0, master_key.size());
        }
        if (!name_key.empty()) {
            SecMemGuard::secure_memset(name_key.data(), 0, name_key.size());
        }
    }
    
    const Botan::secure_vector<uint8_t>& get_name_key() const {
        return name_key;
    }
    
    bool is_initialized() const {
        return initialized && name_key.size() == 32;
    }
};

// **************************************
// CONTADORES 

class PersistCounter {
private:
    std::map<std::string, uint64_t> counters;
    mutable std::shared_timed_mutex counters_mutex;
    std::string storage_file;
    std::atomic<bool> dirty{false};
    std::atomic<uint64_t> save_counter{0};
    std::atomic<bool> is_saving{false};
    std::condition_variable save_cv;
    std::mutex save_mutex;
    std::thread auto_save_thread;
    std::atomic<bool> auto_save_running{false};
    static constexpr uint64_t SAVE_THRESHOLD = 5;
    static constexpr int AUTO_SAVE_INTERVAL_MS = 3000;
    
    bool write_full(int fd, const void* data, size_t size) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        size_t remaining = size;
        while (remaining > 0) {
            ssize_t written = write(fd, ptr, remaining);
            if (written <= 0) return false;
            ptr += written;
            remaining -= written;
        }
        return true;
    }
    
    bool read_full(int fd, void* data, size_t size) {
        uint8_t* ptr = static_cast<uint8_t*>(data);
        size_t remaining = size;
        while (remaining > 0) {
            ssize_t read_bytes = read(fd, ptr, remaining);
            if (read_bytes <= 0) return false;
            ptr += read_bytes;
            remaining -= read_bytes;
        }
        return true;
    }
    
    void load_from_file() {
        FileRAII file(storage_file, O_RDONLY);
        if (!file.valid()) return;
        
        try {
            struct stat st;
            if (fstat(file.get(), &st) != 0 || st.st_size == 0) return;
            
            std::vector<uint8_t> buffer(st.st_size);
            if (!read_full(file.get(), buffer.data(), buffer.size())) return;
            
            size_t pos = 0;
            if (buffer.size() < sizeof(uint32_t)) return;
            
            uint32_t count;
            std::memcpy(&count, buffer.data() + pos, sizeof(count));
            pos += sizeof(count);
            
            for (uint32_t i = 0; i < count && pos < buffer.size(); i++) {
                if (pos + sizeof(uint16_t) > buffer.size()) break;
                
                uint16_t name_len;
                std::memcpy(&name_len, buffer.data() + pos, sizeof(name_len));
                pos += sizeof(name_len);
                
                if (name_len == 0 || name_len > 1024 || pos + name_len > buffer.size()) break;
                
                std::string name(reinterpret_cast<const char*>(buffer.data() + pos), name_len);
                pos += name_len;
                
                if (pos + sizeof(uint64_t) > buffer.size()) break;
                
                uint64_t counter;
                std::memcpy(&counter, buffer.data() + pos, sizeof(counter));
                pos += sizeof(counter);
                
                counters[name] = counter;
            }
            
        } catch (const std::exception& e) {}
    }
    
    bool save_to_file_internal() {
        if (is_saving.exchange(true)) return true;
        
        std::string temp_file = storage_file + ".tmp";
        bool success = false;
        
        try {
            FileRAII file(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (!file.valid()) {
                is_saving = false;
                return false;
            }
            
            std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);
            
            uint32_t count = static_cast<uint32_t>(counters.size());
            if (!write_full(file.get(), &count, sizeof(count))) {
                is_saving = false;
                return false;
            }
            
            for (const auto& [name, counter] : counters) {
                uint16_t name_len = static_cast<uint16_t>(name.size());
                if (!write_full(file.get(), &name_len, sizeof(name_len))) {
                    is_saving = false;
                    return false;
                }
                
                if (!write_full(file.get(), name.c_str(), name_len)) {
                    is_saving = false;
                    return false;
                }
                
                if (!write_full(file.get(), &counter, sizeof(counter))) {
                    is_saving = false;
                    return false;
                }
            }
            
            fsync(file.get());
            file.close();
            
            if (rename(temp_file.c_str(), storage_file.c_str()) != 0) {
                is_saving = false;
                return false;
            }
            
            dirty = false;
            success = true;
            
        } catch (const std::exception& e) {}
        
        is_saving = false;
        save_cv.notify_all();
        return success;
    }
    
    void auto_save_loop() {
        while (auto_save_running.load()) {
            std::unique_lock<std::mutex> lock(save_mutex);
            save_cv.wait_for(lock, std::chrono::milliseconds(AUTO_SAVE_INTERVAL_MS),
                            [this]() { return !auto_save_running.load(); });
            
            if (!auto_save_running.load()) break;
            
            if (dirty.load() && !is_saving.load()) {
                save_to_file_internal();
            }
        }
    }
    
public:
    PersistCounter(const std::string& file_path) : storage_file(file_path) {
        load_from_file();
        auto_save_running = true;
        auto_save_thread = std::thread(&PersistCounter::auto_save_loop, this);
    }
    
    ~PersistCounter() {
        auto_save_running = false;
        save_cv.notify_all();
        if (auto_save_thread.joinable()) auto_save_thread.join();
        std::unique_lock<std::mutex> lock(save_mutex);
        save_cv.wait(lock, [this]() { return !is_saving.load(); });
        if (dirty.load()) save_to_file_internal();
    }
    
    uint64_t get_and_increment(const std::string& key) {
        std::unique_lock<std::shared_timed_mutex> lock(counters_mutex);
        uint64_t& counter = counters[key];
        uint64_t result = counter++;
        dirty = true;
        
        uint64_t current_save = ++save_counter;
        if (current_save >= SAVE_THRESHOLD) {
            save_counter = 0;
            lock.unlock();
            if (!is_saving.load()) {
                std::thread([this]() { save_to_file_internal(); }).detach();
            }
        }
        
        return result;
    }
    
    uint64_t get(const std::string& key) const {
        std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);
        auto it = counters.find(key);
        return it != counters.end() ? it->second : 0;
    }
    
    bool force_save() { return save_to_file_internal(); }
    size_t size() const { std::shared_lock<std::shared_timed_mutex> lock(counters_mutex); return counters.size(); }
    
    void print_stats() const {
        std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);
        std::cout << BLUE << "│ " << GREEN << "Contadores persistentes: " << counters.size() << RESET << std::endl;
        
        if (!counters.empty()) {
            std::cout << BLUE << "│ " << RESET << "Top 10 contadores:" << std::endl;
            std::vector<std::pair<std::string, uint64_t>> sorted(counters.begin(), counters.end());
            std::sort(sorted.begin(), sorted.end(), 
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            
            for (size_t i = 0; i < std::min(size_t(10), sorted.size()); i++) {
                std::cout << BLUE << "│   " << RESET << sorted[i].first << ": " << CYAN << sorted[i].second << RESET << std::endl;
            }
        }
    }
};

// *********************************************
// CIFRADO DE NOMBRES 

class NameObfus {
private:
    Botan::secure_vector<uint8_t> name_key;
    std::unique_ptr<PersistCounter> persistent_counter;
    std::unique_ptr<NameKeyMgr> key_manager;
    
    struct NameCacheEntry {
        std::string original;
        std::string obfuscated;
        std::chrono::steady_clock::time_point timestamp;
        std::atomic<uint64_t> hits;
        NameCacheEntry() : hits(0) { timestamp = std::chrono::steady_clock::now(); }
    };
    
    std::vector<std::unique_ptr<NameCacheEntry>> name_cache;
    std::shared_mutex cache_mutex;
    std::atomic<size_t> cache_index{0};
    size_t cache_size;
    
    static std::string base64_url_encode(const std::string& data) {
        std::string encoded = Botan::base64_encode(
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        std::replace(encoded.begin(), encoded.end(), '+', '-');
        std::replace(encoded.begin(), encoded.end(), '/', '_');
        encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
        return encoded;
    }
    
    static std::string base64_url_decode(const std::string& encoded) {
        std::string base64 = encoded;
        std::replace(base64.begin(), base64.end(), '-', '+');
        std::replace(base64.begin(), base64.end(), '/', '_');
        while (base64.length() % 4) base64 += '=';
        
        try {
            auto vec = Botan::base64_decode(base64);
            return std::string(vec.begin(), vec.end());
        } catch (const std::exception& e) {
            return "";
        }
    }
    
    struct EncryptedName {
        std::vector<uint8_t> nonce;
        std::string ciphertext;
        
        std::string serialize() const {
            std::string result;
            result.reserve(nonce.size() + ciphertext.size());
            result.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
            result.append(ciphertext);
            return result;
        }
        
        static EncryptedName deserialize(const std::string& data) {
            EncryptedName result;
            if (data.size() < 16) throw std::runtime_error("Datos muy pequeños");
            result.nonce.assign(data.begin(), data.begin() + 16);
            result.ciphertext = data.substr(16);
            return result;
        }
    };
    
public:
    NameObfus(size_t cache_sz = 1024, 
              const std::string& counter_file = ".cipher_counters.dat",
              const std::string& key_file = ".cipher_namekey.dat")
        : cache_size(cache_sz) {
        
        key_manager = std::make_unique<NameKeyMgr>(key_file);
        
        if (key_manager->is_initialized()) {
            name_key = key_manager->get_name_key();
        } else {
            name_key = SecureRandom::secure_random(32);
        }
        
        persistent_counter = std::make_unique<PersistCounter>(counter_file);
        
        name_cache.reserve(cache_size);
        for (size_t i = 0; i < cache_size; i++) {
            name_cache.push_back(std::make_unique<NameCacheEntry>());
        }
    }
    
    ~NameObfus() {
        if (persistent_counter) persistent_counter->force_save();
        if (!name_key.empty()) {
            SecMemGuard::secure_memset(name_key.data(), 0, name_key.size());
            name_key.clear();
        }
    }
    
    std::string obfuscate_name(const std::string& original_name) {
        if (original_name.empty()) return "";
        
        {
            std::shared_lock<std::shared_mutex> lock(cache_mutex);
            for (const auto& entry : name_cache) {
                if (entry->original == original_name && !entry->original.empty()) {
                    entry->hits++;
                    return entry->obfuscated;
                }
            }
        }
        
        try {
            uint64_t counter = persistent_counter->get_and_increment(original_name);
            
            auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-256)");
            cipher->set_key(name_key);
            
            EncryptedName enc_name;
            enc_name.nonce.resize(16);
            
            std::memcpy(enc_name.nonce.data(), &counter, 8);
            uint64_t random_part = SecureRandom::random_uint64();
            std::memcpy(enc_name.nonce.data() + 8, &random_part, 8);
            
            cipher->set_iv(enc_name.nonce);
            
            Botan::secure_vector<uint8_t> name_bytes(original_name.begin(), original_name.end());
            cipher->cipher(name_bytes.data(), name_bytes.data(), name_bytes.size());
            
            enc_name.ciphertext.assign(name_bytes.begin(), name_bytes.end());
            
            std::string serialized = enc_name.serialize();
            std::string base64_name = base64_url_encode(serialized);
            
            if (base64_name.length() > 251) base64_name = base64_name.substr(0, 251);
            
            std::string result = base64_name + ".enc";
            
            {
                std::unique_lock<std::shared_mutex> lock(cache_mutex);
                size_t idx = (cache_index++) % cache_size;
                name_cache[idx]->original = original_name;
                name_cache[idx]->obfuscated = result;
                name_cache[idx]->timestamp = std::chrono::steady_clock::now();
                name_cache[idx]->hits = 1;
            }
            
            return result;
            
        } catch (const std::exception& e) {
            return "file_" + std::to_string(SecureRandom::random_uint64()) + ".enc";
        }
    }
    
    std::string deobfuscate_name(const std::string& obfuscated_name) {
        if (obfuscated_name.empty()) return obfuscated_name;
        
        {
            std::shared_lock<std::shared_mutex> lock(cache_mutex);
            for (const auto& entry : name_cache) {
                if (entry->obfuscated == obfuscated_name && !entry->obfuscated.empty()) {
                    entry->hits++;
                    return entry->original;
                }
            }
        }
        
        try {
            if (obfuscated_name.length() <= 4 || 
                obfuscated_name.substr(obfuscated_name.length() - 4) != ".enc") {
                return obfuscated_name;
            }
            
            std::string base64_part = obfuscated_name.substr(0, obfuscated_name.length() - 4);
            std::string serialized = base64_url_decode(base64_part);
            
            if (serialized.empty()) return "restored_" + obfuscated_name;
            
            EncryptedName enc_name = EncryptedName::deserialize(serialized);
            if (enc_name.nonce.size() != 16) return "restored_" + obfuscated_name;
            
            auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-256)");
            cipher->set_key(name_key);
            cipher->set_iv(enc_name.nonce);
            
            Botan::secure_vector<uint8_t> encrypted_bytes(enc_name.ciphertext.begin(), enc_name.ciphertext.end());
            cipher->cipher(encrypted_bytes.data(), encrypted_bytes.data(), encrypted_bytes.size());
            
            std::string original_name(encrypted_bytes.begin(), encrypted_bytes.end());
            
            {
                std::unique_lock<std::shared_mutex> lock(cache_mutex);
                size_t idx = (cache_index++) % cache_size;
                name_cache[idx]->original = original_name;
                name_cache[idx]->obfuscated = obfuscated_name;
                name_cache[idx]->timestamp = std::chrono::steady_clock::now();
                name_cache[idx]->hits = 1;
            }
            
            return original_name;
            
        } catch (const std::exception& e) {
            return "restored_" + obfuscated_name;
        }
    }
    
    void print_counter_stats() const { if (persistent_counter) persistent_counter->print_stats(); }
    void force_save_counters() { if (persistent_counter) persistent_counter->force_save(); }
};

// **********************************
// CIFRADOR AES-256-GCM

class AES256GCM {
private:
    Botan::secure_vector<uint8_t> key;
    std::vector<std::thread> file_workers;
    WorkQueue<FileWork> work_queue;
    std::atomic<bool> workers_running;
    std::unique_ptr<RateLimiter> rate_limiter;
    HeaderHMAC header_hmac;
    SystemConfig config;
    
    std::atomic<uint64_t> total_files_processed{0};
    std::atomic<uint64_t> total_bytes_processed{0};
    std::atomic<uint64_t> total_errors{0};
    std::atomic<uint64_t> total_retries{0};
    std::atomic<uint64_t> mmap_used{0};
    
    bool write_full_with_retry(int fd, const void* data, size_t size, int max_retries = 3) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        size_t remaining = size;
        int retries = 0;
        
        while (remaining > 0) {
            ssize_t written = write(fd, ptr, remaining);
            if (written <= 0) {
                if (written == -1 && (errno == EINTR || errno == EAGAIN)) {
                    if (retries++ < max_retries) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    return false;
                }
                return false;
            }
            ptr += written;
            remaining -= written;
            retries = 0;
        }
        return true;
    }
    
    bool read_full_with_retry(int fd, void* data, size_t size, int max_retries = 3) {
        uint8_t* ptr = static_cast<uint8_t*>(data);
        size_t remaining = size;
        int retries = 0;
        
        while (remaining > 0) {
            ssize_t read_bytes = read(fd, ptr, remaining);
            if (read_bytes <= 0) {
                if (read_bytes == -1 && (errno == EINTR || errno == EAGAIN)) {
                    if (retries++ < max_retries) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    return false;
                }
                return false;
            }
            ptr += read_bytes;
            remaining -= read_bytes;
            retries = 0;
        }
        return true;
    }
    
    bool validate_header_integrity(const uint8_t* data, size_t size) {
        if (size < config.nonce_size + 1 + 8) return false;
        uint8_t flags = data[config.nonce_size];
        if (flags != 0x01 && flags != 0x03) return false;
        return true;
    }
    
    bool encrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath) {
        Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
        SecureRandom::generate_bytes(file_nonce.data(), file_nonce.size());
        
        FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!out_file.valid()) return false;
        
        if (!write_full_with_retry(out_file.get(), file_nonce.data(), file_nonce.size())) return false;
        
        uint8_t flags = 0x01 | (config.use_header_hmac ? 0x02 : 0);
        if (!write_full_with_retry(out_file.get(), &flags, 1)) return false;
        
        uint64_t original_size = mapped.get_size();
        if (!write_full_with_retry(out_file.get(), &original_size, 8)) return false;
        
        Botan::secure_vector<uint8_t> header_data;
        header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
        header_data.push_back(flags);
        header_data.insert(header_data.end(), 
                          reinterpret_cast<uint8_t*>(&original_size),
                          reinterpret_cast<uint8_t*>(&original_size) + 8);
        
        if (config.use_header_hmac) {
            auto hmac = header_hmac.calculate(header_data.data(), header_data.size());
            if (!write_full_with_retry(out_file.get(), hmac.data(), hmac.size())) return false;
        }
        
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        cipher->set_key(key);
        cipher->set_associated_data(header_data.data(), header_data.size());
        cipher->start(file_nonce);
        
        size_t buffer_size = config.optimal_buffer_size;
        Botan::secure_vector<uint8_t> buffer;
        
        const uint8_t* data_ptr = static_cast<const uint8_t*>(mapped.get());
        size_t remaining = mapped.get_size();
        
        while (remaining > 0) {
            size_t chunk = std::min(buffer_size, remaining);
            buffer.assign(data_ptr, data_ptr + chunk);
            
            if (remaining <= chunk) cipher->finish(buffer);
            else cipher->update(buffer);
            
            if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size())) return false;
            
            data_ptr += chunk;
            remaining -= chunk;
            rate_limiter->wait_if_needed(chunk);
        }
        
        total_bytes_processed += mapped.get_size();
        return true;
    }
    
    bool decrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath) {
        const uint8_t* data = static_cast<const uint8_t*>(mapped.get());
        size_t total_size = mapped.get_size();
        
        if (!validate_header_integrity(data, total_size)) return false;
        
        size_t pos = 0;
        
        Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
        std::memcpy(file_nonce.data(), data + pos, config.nonce_size);
        pos += config.nonce_size;
        
        uint8_t flags = data[pos++];
        bool has_hmac = (flags & 0x02) != 0;
        
        uint64_t original_size;
        std::memcpy(&original_size, data + pos, 8);
        pos += 8;
        
        Botan::secure_vector<uint8_t> header_data;
        header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
        header_data.push_back(flags);
        header_data.insert(header_data.end(), 
                          reinterpret_cast<uint8_t*>(&original_size),
                          reinterpret_cast<uint8_t*>(&original_size) + 8);
        
        if (has_hmac) {
            if (pos + 32 > total_size) return false;
            Botan::secure_vector<uint8_t> file_hmac(32);
            std::memcpy(file_hmac.data(), data + pos, 32);
            pos += 32;
            
            if (!header_hmac.verify(header_data.data(), header_data.size(), 
                                    file_hmac.data(), file_hmac.size())) {
                return false;
            }
        }
        
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        cipher->set_key(key);
        cipher->set_associated_data(header_data.data(), header_data.size());
        cipher->start(file_nonce);
        
        FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!out_file.valid()) return false;
        
        if (total_size < pos + SystemConfig::GCM_TAG_SIZE) return false;
        
        size_t ciphertext_size = total_size - pos - SystemConfig::GCM_TAG_SIZE;
        size_t buffer_size = config.optimal_buffer_size;
        Botan::secure_vector<uint8_t> buffer;
        
        while (ciphertext_size > 0) {
            size_t chunk = std::min(buffer_size, ciphertext_size);
            buffer.assign(data + pos, data + pos + chunk);
            pos += chunk;
            
            if (chunk >= ciphertext_size) {
                if (pos + SystemConfig::GCM_TAG_SIZE > total_size) return false;
                buffer.insert(buffer.end(), data + pos, data + pos + SystemConfig::GCM_TAG_SIZE);
                cipher->finish(buffer);
            } else {
                cipher->update(buffer);
            }
            
            if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size())) return false;
            
            ciphertext_size -= chunk;
            rate_limiter->wait_if_needed(chunk);
        }
        
        total_bytes_processed += original_size;
        return true;
    }
    
    bool process_with_traditional_io(const std::string& inputPath, 
                                      const std::string& outputPath,
                                      bool encryptMode) {
        FileRAII in_file(inputPath, O_RDONLY);
        if (!in_file.valid()) return false;
        
        struct stat st;
        if (fstat(in_file.get(), &st) != 0) return false;
        size_t file_size = st.st_size;
        
        if (encryptMode) {
            FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (!out_file.valid()) return false;
            
            Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
            SecureRandom::generate_bytes(file_nonce.data(), file_nonce.size());
            
            if (!write_full_with_retry(out_file.get(), file_nonce.data(), file_nonce.size())) return false;
            
            uint8_t flags = 0x01 | (config.use_header_hmac ? 0x02 : 0);
            if (!write_full_with_retry(out_file.get(), &flags, 1)) return false;
            
            uint64_t original_size = file_size;
            if (!write_full_with_retry(out_file.get(), &original_size, 8)) return false;
            
            Botan::secure_vector<uint8_t> header_data;
            header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
            header_data.push_back(flags);
            header_data.insert(header_data.end(), 
                              reinterpret_cast<uint8_t*>(&original_size),
                              reinterpret_cast<uint8_t*>(&original_size) + 8);
            
            if (config.use_header_hmac) {
                auto hmac = header_hmac.calculate(header_data.data(), header_data.size());
                if (!write_full_with_retry(out_file.get(), hmac.data(), hmac.size())) return false;
            }
            
            auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
            cipher->set_key(key);
            cipher->set_associated_data(header_data.data(), header_data.size());
            cipher->start(file_nonce);
            
            size_t buffer_size = config.optimal_buffer_size;
            std::vector<uint8_t> buffer(buffer_size);
            size_t total_read = 0;
            
            while (total_read < file_size) {
                size_t to_read = std::min(buffer_size, file_size - total_read);
                if (!read_full_with_retry(in_file.get(), buffer.data(), to_read)) return false;
                
                Botan::secure_vector<uint8_t> secure_buf(buffer.data(), buffer.data() + to_read);
                
                if (total_read + to_read >= file_size) cipher->finish(secure_buf);
                else cipher->update(secure_buf);
                
                if (!write_full_with_retry(out_file.get(), secure_buf.data(), secure_buf.size())) return false;
                
                total_read += to_read;
                rate_limiter->wait_if_needed(to_read);
            }
        } else {
            FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (!out_file.valid()) return false;
            
            Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
            if (!read_full_with_retry(in_file.get(), file_nonce.data(), file_nonce.size())) return false;
            
            uint8_t flags;
            if (!read_full_with_retry(in_file.get(), &flags, 1)) return false;
            bool has_hmac = (flags & 0x02) != 0;
            
            uint64_t original_size;
            if (!read_full_with_retry(in_file.get(), &original_size, 8)) return false;
            
            Botan::secure_vector<uint8_t> header_data;
            header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
            header_data.push_back(flags);
            header_data.insert(header_data.end(), 
                              reinterpret_cast<uint8_t*>(&original_size),
                              reinterpret_cast<uint8_t*>(&original_size) + 8);
            
            if (has_hmac) {
                Botan::secure_vector<uint8_t> file_hmac(32);
                if (!read_full_with_retry(in_file.get(), file_hmac.data(), 32)) return false;
                if (!header_hmac.verify(header_data.data(), header_data.size(), 
                                        file_hmac.data(), file_hmac.size())) return false;
            }
            
            auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
            cipher->set_key(key);
            cipher->set_associated_data(header_data.data(), header_data.size());
            cipher->start(file_nonce);
            
            off_t current_pos = lseek(in_file.get(), 0, SEEK_CUR);
            off_t file_end = lseek(in_file.get(), 0, SEEK_END);
            lseek(in_file.get(), current_pos, SEEK_SET);
            
            size_t ciphertext_size = file_end - current_pos - SystemConfig::GCM_TAG_SIZE;
            size_t buffer_size = config.optimal_buffer_size;
            std::vector<uint8_t> buffer(buffer_size);
            size_t total_read = 0;
            
            while (total_read < ciphertext_size) {
                size_t to_read = std::min(buffer_size, ciphertext_size - total_read);
                if (!read_full_with_retry(in_file.get(), buffer.data(), to_read)) return false;
                
                Botan::secure_vector<uint8_t> secure_buf(buffer.data(), buffer.data() + to_read);
                
                if (total_read + to_read >= ciphertext_size) {
                    Botan::secure_vector<uint8_t> tag(SystemConfig::GCM_TAG_SIZE);
                    if (!read_full_with_retry(in_file.get(), tag.data(), tag.size())) return false;
                    secure_buf.insert(secure_buf.end(), tag.begin(), tag.end());
                    cipher->finish(secure_buf);
                } else {
                    cipher->update(secure_buf);
                }
                
                if (!write_full_with_retry(out_file.get(), secure_buf.data(), secure_buf.size())) return false;
                
                total_read += to_read;
                rate_limiter->wait_if_needed(to_read);
            }
        }
        
        total_files_processed++;
        total_bytes_processed += file_size;
        return true;
    }
    
    bool process_with_mmap_wrapper(const std::string& inputPath, const std::string& outputPath, bool encryptMode) {
        FileRAII in_file(inputPath, O_RDONLY);
        if (!in_file.valid()) return false;
        
        struct stat st;
        if (fstat(in_file.get(), &st) != 0) return false;
        
        MMapRAII mmap;
        if (!mmap.map(in_file.get(), st.st_size)) return false;
        
        mmap_used++;
        
        try {
            if (encryptMode) return encrypt_with_mmap(mmap, outputPath);
            else return decrypt_with_mmap(mmap, outputPath);
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    bool process_single_file_with_retry(const std::string& inputPath, 
                                        const std::string& outputPath,
                                        bool encryptMode) {
        int retries = 0;
        bool success = false;
        
        while (retries <= static_cast<int>(config.max_retries) && !success) {
            if (retries > 0) {
                total_retries++;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_delay_ms));
                std::remove(outputPath.c_str());
            }
            
            try {
                rate_limiter->wait_if_needed();
                
                struct stat st;
                if (stat(inputPath.c_str(), &st) != 0) return false;
                
                if (config.should_use_mmap(st.st_size)) {
                    success = process_with_mmap_wrapper(inputPath, outputPath, encryptMode);
                } else {
                    success = process_with_traditional_io(inputPath, outputPath, encryptMode);
                }
                
            } catch (const std::exception& e) {
                success = false;
            }
            
            retries++;
        }
        
        if (!success) total_errors++;
        return success;
    }
    
    void file_worker_function() {
        while (workers_running.load()) {
            FileWork work;
            if (work_queue.pop(work)) {
                bool result = process_single_file_with_retry(
                    work.input_path, work.output_path, work.is_encrypt);
                work.result_promise.set_value(result);
            }
        }
    }
    
public:
    AES256GCM(const uint8_t* key_data, size_t key_len, 
              size_t num_threads, size_t queue_sz, const SystemConfig& cfg) 
        : workers_running(true), work_queue(queue_sz), config(cfg) {
        
        key.assign(key_data, key_data + key_len);
        header_hmac.set_key(key);
        rate_limiter = std::make_unique<RateLimiter>();
        
        for (size_t i = 0; i < num_threads; i++) {
            file_workers.emplace_back(&AES256GCM::file_worker_function, this);
        }
    }
    
    ~AES256GCM() {
        workers_running = false;
        work_queue.stop();
        for (auto& thread : file_workers) {
            if (thread.joinable()) thread.join();
        }
        if (!key.empty()) {
            SecMemGuard::secure_memset(key.data(), 0, key.size());
        }
    }
    
    void setRateLimits(size_t max_files, size_t max_bytes) {
        rate_limiter->setLimits(max_files, max_bytes);
    }
    
    bool encrypt_file(const std::string& inputPath, const std::string& outputPath) {
        return process_single_file_with_retry(inputPath, outputPath, true);
    }
    
    bool decrypt_file(const std::string& inputPath, const std::string& outputPath) {
        return process_single_file_with_retry(inputPath, outputPath, false);
    }
    
    std::vector<bool> process_files_parallel(
        const std::vector<std::pair<std::string, std::string>>& files,
        bool encryptMode) {
        
        std::vector<std::future<bool>> futures;
        std::vector<bool> results;
        
        for (const auto& [input, output] : files) {
            std::promise<bool> promise;
            futures.push_back(promise.get_future());
            
            FileWork work;
            work.input_path = input;
            work.output_path = output;
            work.is_encrypt = encryptMode;
            work.result_promise = std::move(promise);
            
            work_queue.push(std::move(work));
        }
        
        for (auto& future : futures) {
            results.push_back(future.get());
        }
        
        return results;
    }
    
    std::string name() const { return "AES-256-GCM"; }
    
    std::string provider() const { 
        auto test = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        return test->provider();
    }
    
    bool has_aes_ni() const {
        std::string prov = provider();
        return prov.find("aes-ni") != std::string::npos || prov.find("clmul") != std::string::npos;
    }
    
    uint64_t get_files_processed() const { return total_files_processed.load(); }
    uint64_t get_bytes_processed() const { return total_bytes_processed.load(); }
    uint64_t get_errors() const { return total_errors.load(); }
    uint64_t get_retries() const { return total_retries.load(); }
    uint64_t get_mmap_used() const { return mmap_used.load(); }
    
    void print_stats() const {
        std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
        std::cout << BLUE << "│ " << MAGENTA << "ESTADÍSTICAS I/O:" << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "mmap usado: " << CYAN << mmap_used.load() << RESET << " archivos" << std::endl;
        std::cout << BLUE << "│ " << RESET << "Reintentos: " << YELLOW << total_retries.load() << RESET << std::endl;
    }
};

// *******************************************
// CIFRADOR UNIVERSAL - CLASE PRINCIPAL

class UniversalCipher {
private:
    SystemConfig config;
    KeyManager* keyManager;
    std::unique_ptr<NameObfus> name_obfuscator;
    std::unique_ptr<AES256GCM> cipher;
    std::string currentKeyName;
    std::atomic<bool> processing_active{false};
    std::atomic<bool> stop_requested{false};
    
    static UniversalCipher* instance;
    
    static void signalHandler(int signal) {
        if (instance && instance->name_obfuscator) {
            instance->name_obfuscator->force_save_counters();
        }
        exit(signal);
    }
    
    static void setupSignalHandlers() {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP, signalHandler);
        signal(SIGQUIT, signalHandler);
    }
    
    struct termios oldt, newt;
    
    void disable_echo() {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    
    void enable_echo() {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
    
    std::string get_secure_input(const std::string& prompt) {
        std::cout << prompt;
        disable_echo();
        std::string input;
        std::getline(std::cin, input);
        enable_echo();
        std::cout << std::endl;
        return input;
    }
    
    std::string getInput(const std::string& prompt) {
        std::cout << prompt;
        std::string input;
        std::getline(std::cin, input);
        return input;
    }
    
    bool fileExists(const std::string& path) {
        struct stat buffer;
        return stat(path.c_str(), &buffer) == 0;
    }
    
    bool isDirectory(const std::string& path) {
        struct stat st;
        return stat(path.c_str(), &st) == 0 && (st.st_mode & S_IFDIR);
    }
    
    uint64_t getFileSize(const std::string& path) {
        struct stat st;
        return stat(path.c_str(), &st) == 0 ? st.st_size : 0;
    }
    
    bool should_ignore_file(const std::string& filename) {
        std::string name = std::filesystem::path(filename).filename().string();
        static const std::vector<std::string> ignored = {
            ".cipher_counters.dat", ".cipher_namekey.dat", ".DS_Store", "Thumbs.db"
        };
        for (const auto& ign : ignored) {
            if (name == ign) return true;
        }
        return false;
    }
    
    bool is_already_encrypted(const std::string& filename) {
        if (filename.length() < 4) return false;
        std::string ext = filename.substr(filename.length() - 4);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext == ".enc";
    }
    
    std::vector<std::string> getAllFiles(const std::string& path, bool recursive = true) {
        std::vector<std::string> files;
        try {
            if (recursive) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                    if (entry.is_regular_file() && !should_ignore_file(entry.path().string())) {
                        files.push_back(entry.path().string());
                    }
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_regular_file() && !should_ignore_file(entry.path().string())) {
                        files.push_back(entry.path().string());
                    }
                }
            }
        } catch (const std::exception& e) {}
        return files;
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
    
    Botan::secure_vector<uint8_t> hexToSecureBytes(const std::string& hex) {
        Botan::secure_vector<uint8_t> result;
        result.reserve(hex.length() / 2);
        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            char hex_byte[3] = {hex[i], hex[i+1], '\0'};
            char* endptr;
            long val = strtol(hex_byte, &endptr, 16);
            if (endptr == hex_byte + 2) {
                result.push_back(static_cast<uint8_t>(val));
            }
        }
        return result;
    }
    
    bool initializeCipherWithKey(const std::string& keyName) {
        if (!keyManager) {
            std::cout << RED << "✗ Gestor de claves no disponible" << RESET << std::endl;
            return false;
        }
        
        if (!keyManager->hasKey(keyName)) {
            std::cout << RED << "✗ Clave no encontrada: " << keyName << RESET << std::endl;
            return false;
        }
        
        if (!keyManager->isKeyActive(keyName)) {
            std::cout << YELLOW << "\n⚠ La clave '" << keyName << "' está INACTIVA" << RESET << std::endl;
            if (keyManager->keyRequiresActivation(keyName)) {
                std::string activationCode = get_secure_input("Clave de activación: ");
                Botan::secure_vector<uint8_t> code(activationCode.begin(), activationCode.end());
                if (!keyManager->activateKey(keyName, code)) {
                    std::cout << RED << "✗ Clave de activación incorrecta" << RESET << std::endl;
                    return false;
                }
            } else {
                Botan::secure_vector<uint8_t> emptyCode;
                if (!keyManager->activateKey(keyName, emptyCode)) {
                    std::cout << RED << "✗ No se pudo activar la clave" << RESET << std::endl;
                    return false;
                }
            }
            std::cout << GREEN << "✓ Clave activada exitosamente" << RESET << std::endl;
        }
        
        // FIX: getKeyValue devuelve secure_vector, no string
        Botan::secure_vector<uint8_t> keyBytes = keyManager->getKeyValue(keyName);
        if (keyBytes.empty()) {
            std::cout << RED << "✗ No se pudo obtener el valor de la clave" << RESET << std::endl;
            return false;
        }
        
        if (keyBytes.size() != 32) {
            std::cout << RED << "✗ Longitud de clave incorrecta: " << keyBytes.size() << " bytes (deben ser 32)" << RESET << std::endl;
            return false;
        }
        
        cipher = std::make_unique<AES256GCM>(
            keyBytes.data(), keyBytes.size(),
            config.thread_config.crypto_threads,
            config.queue_size,
            config
        );
        
        cipher->setRateLimits(config.max_files_per_second, config.max_bytes_per_second);
        currentKeyName = keyName;
        
        return true;
    }
    
    std::string selectKey() {
        if (!keyManager) {
            std::cout << RED << "✗ Gestor de claves no disponible" << RESET << std::endl;
            return "";
        }
        
        std::vector<std::string> activeKeys = keyManager->getActiveKeys();
        if (activeKeys.empty()) {
            std::cout << YELLOW << "\nNo hay claves activas disponibles." << RESET << std::endl;
            return "";
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "CLAVES DISPONIBLES" << BLUE << "]──────────────────────────────────────┐\n";
        std::cout << BLUE << "│" << RESET << "\n";
        std::cout << BLUE << "│ " << GREEN << "CLAVES ACTIVAS:" << RESET << std::endl;
        for (size_t i = 0; i < activeKeys.size(); i++) {
            std::cout << BLUE << "│   [" << GREEN << i+1 << BLUE << "] " << CYAN << activeKeys[i] << RESET << std::endl;
        }
        std::cout << BLUE << "│   [" << GREEN << "0" << BLUE << "] " << MAGENTA << "Cancelar" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-" + std::to_string(activeKeys.size()) + BRIGHT_GREEN + "]: " + RESET;
        std::string choiceStr = getInput(prompt);
        if (choiceStr == "0") return "";
        
        try {
            int choice = std::stoi(choiceStr) - 1;
            if (choice >= 0 && choice < static_cast<int>(activeKeys.size())) {
                return activeKeys[choice];
            }
        } catch (...) {}
        
        std::cout << RED << "✗ Selección inválida" << RESET << std::endl;
        return "";
    }
    
    void waitForEnter() {
        std::cout << "\n" << YELLOW << "Presione Enter para continuar..." << RESET;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string dummy;
        std::getline(std::cin, dummy);
    }
    
    bool processDirectory(const std::string& path, bool encryptMode) {
        std::vector<std::string> files = getAllFiles(path, true);
        if (files.empty()) {
            std::cout << YELLOW << "\n⚠ No hay archivos" << RESET << std::endl;
            return false;
        }
        
        std::vector<std::pair<std::string, std::string>> toProcess;
        
        for (const auto& file : files) {
            std::string name = std::filesystem::path(file).filename().string();
            std::string dir = std::filesystem::path(file).parent_path().string();
            
            if (encryptMode && !is_already_encrypted(name)) {
                std::string obfuscated = name_obfuscator->obfuscate_name(name);
                toProcess.push_back({file, dir + "/" + obfuscated + ".tmp"});
            }
            else if (!encryptMode && is_already_encrypted(file)) {
                std::string original = name_obfuscator->deobfuscate_name(name);
                toProcess.push_back({file, dir + "/" + original + ".tmp"});
            }
        }
        
        if (toProcess.empty()) {
            std::cout << YELLOW << "\n⚠ No hay archivos para procesar" << RESET << std::endl;
            return false;
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << (encryptMode ? "CIFRAR DIRECTORIO" : "DESCIFRAR DIRECTORIO") << BLUE << "]─────────────────────────────────┐\n";
        std::cout << BLUE << "│ " << RESET << "Archivos: " << GREEN << toProcess.size() << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Modo: " << BRIGHT_MAGENTA << (encryptMode ? "CIFRADO" : "DESCIFRADO") << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Clave: " << BRIGHT_CYAN << currentKeyName << RESET << std::endl;
        config.thread_config.print();
        std::cout << BLUE << "│ " << RESET << "Archivos paralelos: " << GREEN << config.max_parallel_files << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Reintentos: " << GREEN << config.max_retries << RESET << " (delay " << config.retry_delay_ms << "ms)" << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string confirm = getInput("\n¿Continuar? (s/N): ");
        if (confirm != "s" && confirm != "S") {
            std::cout << "Cancelado." << std::endl;
            return false;
        }
        
        processing_active = true;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<bool> results;
        size_t processed = 0;
        
        while (processed < toProcess.size() && !stop_requested) {
            size_t batch_size = std::min(config.max_parallel_files, toProcess.size() - processed);
            std::vector<std::pair<std::string, std::string>> batch;
            
            for (size_t i = 0; i < batch_size; i++) {
                batch.push_back(toProcess[processed + i]);
            }
            
            auto batch_results = cipher->process_files_parallel(batch, encryptMode);
            
            for (size_t i = 0; i < batch_results.size(); i++) {
                size_t index = processed + i;
                std::cout << "\n[" << (index + 1) << "/" << toProcess.size() << "] "
                         << BRIGHT_WHITE << toProcess[index].first << RESET << std::endl;
                
                if (batch_results[i]) {
                    std::string final_path = toProcess[index].second;
                    final_path = final_path.substr(0, final_path.length() - 4);
                    
                    if (std::rename(toProcess[index].second.c_str(), final_path.c_str()) == 0) {
                        if (final_path != toProcess[index].first) {
                            std::remove(toProcess[index].first.c_str());
                        }
                        if (!encryptMode) {
                            UserPermissions::fixFilePermissions(final_path);
                        }
                        std::cout << GREEN << "  ✓ Completado" << RESET << std::endl;
                    } else {
                        std::cout << RED << "  ✗ Error moviendo archivo" << RESET << std::endl;
                        batch_results[i] = false;
                    }
                } else {
                    std::cout << RED << "  ✗ Error" << RESET << std::endl;
                }
            }
            
            results.insert(results.end(), batch_results.begin(), batch_results.end());
            processed += batch_size;
        }
        
        name_obfuscator->force_save_counters();
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        int success = 0, fail = 0;
        for (bool r : results) {
            if (r) success++; else fail++;
        }
        
        std::cout << BLUE << "\n┌─[" << MAGENTA << "RESULTADO" << BLUE << "]──────────────────────────────────────────────┐\n";
        std::cout << BLUE << "│ " << GREEN << "Exitosos: " << success << RESET << " | " << RED << "Fallidos: " << fail << RESET << std::endl;
        std::cout << BLUE << "│ " << RESET << "Tiempo total: " << CYAN << duration.count() << " ms" << RESET << std::endl;
        cipher->print_stats();
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
        
        processing_active = false;
        return success > 0;
    }
    
    bool encryptFileInPlace(const std::string& inputPath) {
        if (!cipher) return false;
        
        std::string dir = std::filesystem::path(inputPath).parent_path().string();
        std::string filename = std::filesystem::path(inputPath).filename().string();
        
        if (should_ignore_file(filename)) return true;
        
        std::string obfuscated = name_obfuscator->obfuscate_name(filename);
        std::string outputPath = dir + "/" + obfuscated;
        std::string tempPath = outputPath + ".tmp";
        
        bool success = cipher->encrypt_file(inputPath, tempPath);
        
        if (!success) {
            std::remove(tempPath.c_str());
            return false;
        }
        
        if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0) {
            std::remove(tempPath.c_str());
            return false;
        }
        
        if (outputPath != inputPath) {
            std::remove(inputPath.c_str());
        }
        
        return true;
    }
    
    bool decryptFileInPlace(const std::string& inputPath) {
        if (!cipher) return false;
        
        std::string dir = std::filesystem::path(inputPath).parent_path().string();
        std::string filename = std::filesystem::path(inputPath).filename().string();
        std::string outputFilename = name_obfuscator->deobfuscate_name(filename);
        std::string outputPath = dir + "/" + outputFilename;
        std::string tempPath = outputPath + ".tmp";
        
        bool success = cipher->decrypt_file(inputPath, tempPath);
        
        if (!success) {
            std::remove(tempPath.c_str());
            return false;
        }
        
        if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0) {
            std::remove(tempPath.c_str());
            return false;
        }
        
        if (outputPath != inputPath) {
            std::remove(inputPath.c_str());
        }
        UserPermissions::fixFilePermissions(outputPath);
        
        return true;
    }
    
    bool processPath(const std::string& path, bool encryptMode) {
        if (isDirectory(path)) {
            return processDirectory(path, encryptMode);
        } else if (fileExists(path)) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << (encryptMode ? "CIFRAR ARCHIVO" : "DESCIFRAR ARCHIVO") << BLUE << "]──────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << RESET << "Procesando..." << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
            return encryptMode ? encryptFileInPlace(path) : decryptFileInPlace(path);
        }
        std::cout << RED << "✗ Ruta inválida: " << path << RESET << std::endl;
        return false;
    }
    
public:
    UniversalCipher() : keyManager(nullptr) {
        instance = this;
        setupSignalHandlers();
        
        unsigned int system_threads = std::thread::hardware_concurrency();
        if (system_threads == 0) system_threads = 4;
        
        config.autoConfigure(system_threads);
        
        name_obfuscator = std::make_unique<NameObfus>(
            config.name_cache_size, 
            config.counter_file_path,
            config.name_key_file_path
        );
        SecureRandom::setUseHardware(config.use_hardware_rng);
    }
    
    ~UniversalCipher() {
        if (name_obfuscator) {
            name_obfuscator->force_save_counters();
        }
        instance = nullptr;
    }
    
    void setKeyManager(KeyManager* km) { keyManager = km; }
    void stop() { if (processing_active) stop_requested = true; }
    
    void showMenu() {
        while (true) {
            std::cout << BLUE;
            std::cout << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│" << GREEN << BOLD << "                       CIFRADO UNIVERSAL                            " << BLUE << "│\n";
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << "│" << MAGENTA << "  AES-256-GCM | " << (cipher && cipher->has_aes_ni() ? "AES-NI: ✓" : "AES-NI: ✗") << BLUE << "                              │\n";
            std::cout << "│" << CYAN << "  Hilos: " << config.thread_config.crypto_threads << " | Paralelo: " << config.max_parallel_files << " archivos" << BLUE << "                         │\n";
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::cout << BLUE << "\n┌─[" << MAGENTA << "MENÚ PRINCIPAL" << BLUE << "]───────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Cifrar archivo/directorio                                           " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Descifrar archivo/directorio                                        " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "Configuración                                                       " << BLUE << "│\n";
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Salir                                                               " << BLUE << "│\n";
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione opción [" + BRIGHT_MAGENTA + "0-3" + BRIGHT_GREEN + "]: " + RESET;
            std::string choice = getInput(prompt);
            
            if (choice == "1" || choice == "2") {
                std::string keyName = selectKey();
                if (keyName.empty()) {
                    waitForEnter();
                    continue;
                }
                
                if (!initializeCipherWithKey(keyName)) {
                    waitForEnter();
                    continue;
                }
                
                std::string path = getInput("\nRuta: ");
                bool result = processPath(path, choice == "1");
                
                name_obfuscator->force_save_counters();
                
                if (result) {
                    std::cout << GREEN << "\n✓ Operación completada" << RESET << std::endl;
                }
                waitForEnter();
                
            } else if (choice == "3") {
                showConfigMenu();
            } else if (choice == "0") {
                name_obfuscator->force_save_counters();
                break;
            }
        }
    }
    
    void showConfigMenu() {
        while (true) {
            std::cout << BLUE << "\n┌─[" << MAGENTA << "CONFIGURACIÓN" << BLUE << "]──────────────────────────────────────────┐\n";
            config.print();
            
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << BLUE << "│ " << GREEN << " [1] " << MAGENTA << "Buffer máximo (" << (config.max_buffer_size/(1024*1024)) << " MB)" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [2] " << MAGENTA << "Rate limit (" << (config.max_bytes_per_second/(1024*1024)) << " MB/s)" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [3] " << MAGENTA << "HMAC header (" << (config.use_header_hmac ? "Sí" : "No") << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [4] " << MAGENTA << "Archivos paralelos (" << config.max_parallel_files << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [5] " << MAGENTA << "Reintentos (" << config.max_retries << ")" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [6] " << MAGENTA << "Limpiar contadores" << RESET << std::endl;
            std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << "Volver" << RESET << std::endl;
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\nSeleccione [" + BRIGHT_MAGENTA + "0-6" + BRIGHT_GREEN + "]: " + RESET;
            std::string choice = getInput(prompt);
            
            if (choice == "0") break;
            else if (choice == "1") {
                std::string size = getInput("MB (2-32): ");
                try {
                    size_t s = std::stoul(size);
                    if (s >= 2 && s <= 32) {
                        config.max_buffer_size = s * 1024 * 1024;
                        config.optimal_buffer_size = config.max_buffer_size / 2;
                    }
                } catch (...) {}
            }
            else if (choice == "2") {
                std::string mb = getInput("MB/s (10-1000): ");
                try {
                    size_t m = std::stoul(mb);
                    if (m >= 10 && m <= 1000) {
                        config.max_bytes_per_second = m * 1024 * 1024;
                    }
                } catch (...) {}
            }
            else if (choice == "3") {
                config.use_header_hmac = !config.use_header_hmac;
            }
            else if (choice == "4") {
                std::string num = getInput("Número (1-16): ");
                try {
                    size_t n = std::stoul(num);
                    if (n >= 1 && n <= 16) {
                        config.max_parallel_files = n;
                    }
                } catch (...) {}
            }
            else if (choice == "5") {
                std::string num = getInput("Número (0-5): ");
                try {
                    size_t n = std::stoul(num);
                    if (n <= 5) {
                        config.max_retries = n;
                    }
                } catch (...) {}
            }
            else if (choice == "6") {
                std::string confirm = getInput("¿Eliminar todos los contadores? (s/N): ");
                if (confirm == "s" || confirm == "S") {
                    std::remove(config.counter_file_path.c_str());
                    std::remove(config.name_key_file_path.c_str());
                    name_obfuscator = std::make_unique<NameObfus>(
                        config.name_cache_size,
                        config.counter_file_path,
                        config.name_key_file_path
                    );
                    std::cout << GREEN << "✓ Contadores limpiados" << RESET << std::endl;
                }
            }
            
            waitForEnter();
        }
    }
};

UniversalCipher* UniversalCipher::instance = nullptr;

#endif // UNIVERSAL_CIPHER_H