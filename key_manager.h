#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <memory>
#include <sys/stat.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>
#include <thread>
#include <fcntl.h>

#include <botan/pwdhash.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <botan/hash.h>

using namespace std;

// Colores para la terminal
#ifndef COLORES_DEFINIDOS
#define COLORES_DEFINIDOS
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BRIGHT_RED     "\033[91m"
#define BRIGHT_GREEN   "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#define BRIGHT_BLUE    "\033[94m"
#define BRIGHT_MAGENTA "\033[95m"
#define BRIGHT_CYAN    "\033[96m"
#define BRIGHT_WHITE   "\033[97m"
#define BOLD    "\033[1m"
#endif

// ***********************************************
// CLASE  MLOCK PROTECION DE MEMORIA

class MemoryLC {
private:
    void* ptr;
    size_t size;
    bool locked;

public:
    MemoryLC() : ptr(nullptr), size(0), locked(false) {}
    
    explicit MemoryLC(void* memory_ptr, size_t memory_size) 
        : ptr(memory_ptr), size(memory_size), locked(false) {
        if (ptr && size > 0) {
            if (mlock(ptr, size) == 0) {
                locked = true;
            }
        }
    }
    
    MemoryLC(const MemoryLC&) = delete;
    MemoryLC& operator=(const MemoryLC&) = delete;
    
    MemoryLC(MemoryLC&& other) noexcept 
        : ptr(other.ptr), size(other.size), locked(other.locked) {
        other.ptr = nullptr;
        other.size = 0;
        other.locked = false;
    }
    
    MemoryLC& operator=(MemoryLC&& other) noexcept {
        if (this != &other) {
            unlock();
            ptr = other.ptr;
            size = other.size;
            locked = other.locked;
            other.ptr = nullptr;
            other.size = 0;
            other.locked = false;
        }
        return *this;
    }
    
    void unlock() {
        if (locked && ptr && size > 0) {
            munlock(ptr, size);
            locked = false;
        }
    }
    
    ~MemoryLC() {
        unlock();
    }
    
    bool isLocked() const { return locked; }
};

// ************************************
// COMPARACION
inline bool secure_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

// ******************************************************
// SISTEMA DE CONTRASEÑAS SEMI-VISIBLE

class KeySecureInput {
private:
    static void setRawMode(bool enable) {
        static struct termios oldt;
        static bool initialized = false;
        struct termios tty;

        if (enable) {
            if (!initialized) {
                tcgetattr(STDIN_FILENO, &oldt);
                initialized = true;
            }
            tty = oldt;
            tty.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        } else {
            if (initialized) {
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            }
        }
    }

    static void clearLine(const string& prompt, size_t currentLength) {
        cout << "\r";
        cout << string(prompt.length() + currentLength + 1, ' ');
        cout << "\r" << prompt << flush;
    }

    static void redrawLine(const string& prompt, size_t asteriskCount) {
        cout << "\r" << prompt << string(asteriskCount, '*') << flush;
    }

public:
    static Botan::secure_vector<uint8_t> readAccessCode(const string& prompt = "Clave de acceso: ") {
        setRawMode(true);
        Botan::secure_vector<uint8_t> code;
        char c;
        const int SHOW_TIME_MS = 50;  

        cout << prompt << flush;

        while (true) {
            ssize_t result = read(STDIN_FILENO, &c, 1);
            if (result != 1) {
                break;
            }

            if (c == '\n' || c == '\r') {
                break;
            }

            if (c == 127 || c == '\b') {
                if (!code.empty()) {
                    code.pop_back();
                    clearLine(prompt, code.size() + 1);
                    redrawLine(prompt, code.size());
                }
                continue;
            }

            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(SHOW_TIME_MS));
            
            code.push_back(static_cast<uint8_t>(c));
            redrawLine(prompt, code.size());
        }

        setRawMode(false);
        cout << "\n";
        
        return code;
    }

    static Botan::secure_vector<uint8_t> readAccessCodeWithConfirm(
        const string& prompt = "Clave de acceso: ", 
        const string& confirmPrompt = "Confirmar clave de acceso: ") {
        
        Botan::secure_vector<uint8_t> code1, code2;
        int attempts = 0;
        const int MAX_ATTEMPTS = 3;

        while (attempts < MAX_ATTEMPTS) {
            code1 = readAccessCode(prompt);
            
            if (code1.empty()) {
                cout << RED << "✗ La clave no puede estar vacía" << RESET << endl;
                attempts++;
                continue;
            }

            if (code1.size() < 4) {
                cout << RED << "✗ La clave debe tener al menos 4 caracteres" << RESET << endl;
                code1.clear();
                attempts++;
                continue;
            }

            code2 = readAccessCode(confirmPrompt);

            bool match = (code1.size() == code2.size() && 
                         secure_memcmp(code1.data(), code2.data(), code1.size()));
            
            if (match) {
                code2.clear();
                return code1;
            } else {
                cout << RED << "✗ Las claves no coinciden. Intento " 
                     << (attempts + 1) << " de " << MAX_ATTEMPTS << RESET << endl;
                code1.clear();
                code2.clear();
                attempts++;
            }
        }

        cout << RED << "✗ Demasiados intentos fallidos" << RESET << endl;
        return Botan::secure_vector<uint8_t>();
    }

    static string readStringNormal(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }
};

// *************************************************
// CRYPTO UTILITIES CON ARGON2ID

class KeyCryptoUtils {
public:
    static constexpr int ARGON2_MEMORY_KB = 65536;
    static constexpr int ARGON2_ITERATIONS = 3;
    static constexpr int ARGON2_PARALLELISM = 1;
    static constexpr int SALT_SIZE = 32;
    static constexpr int KEY_SIZE = 32;
    static constexpr int IV_SIZE = 12;

    static Botan::secure_vector<uint8_t> generateSalt() {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> salt(SALT_SIZE);
            rng.randomize(salt.data(), salt.size());
            return salt;
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    // NUEVO METODO PARA GENERAR BYTES PUROS EN VEZ DE HEX
    static Botan::secure_vector<uint8_t> generateRandomBytes(int bytes = 32) {
        try {
            Botan::AutoSeeded_RNG rng;
            Botan::secure_vector<uint8_t> key(bytes);
            rng.randomize(key.data(), key.size());
            return key;
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    static string generateRandomHex(int bytes = 32) {
        try {
            Botan::AutoSeeded_RNG rng;
            vector<uint8_t> key(bytes);
            rng.randomize(key.data(), key.size());
            return Botan::hex_encode(key);
        } catch(...) {
            return "";
        }
    }

    static Botan::secure_vector<uint8_t> deriveKey(
        const Botan::secure_vector<uint8_t>& password,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_len = KEY_SIZE) {
        
        try {
            auto argon2_family = Botan::PasswordHashFamily::create("Argon2id");
            if (!argon2_family) {
                return Botan::secure_vector<uint8_t>();
            }
            
            auto argon2 = argon2_family->from_params(
                ARGON2_MEMORY_KB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM
            );
            
            if (!argon2) {
                return Botan::secure_vector<uint8_t>();
            }
            
            Botan::secure_vector<uint8_t> key(key_len);
            argon2->derive_key(key.data(), key.size(),
                              reinterpret_cast<const char*>(password.data()), password.size(),
                              salt.data(), salt.size());
            
            return key;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }

    static Botan::secure_vector<uint8_t> encryptData(
        const Botan::secure_vector<uint8_t>& plaintext,
        const Botan::secure_vector<uint8_t>& password) {
        
        try {
            Botan::AutoSeeded_RNG rng;
            
            Botan::secure_vector<uint8_t> salt = generateSalt();
            if (salt.empty()) return Botan::secure_vector<uint8_t>();
            
            Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
            if (key.empty()) return Botan::secure_vector<uint8_t>();
            
            Botan::secure_vector<uint8_t> iv(IV_SIZE);
            rng.randomize(iv.data(), iv.size());
            
            unique_ptr<Botan::Cipher_Mode> cipher = 
                Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
            
            if (!cipher) return Botan::secure_vector<uint8_t>();
            
            cipher->set_key(key);
            cipher->start(iv.data(), iv.size());
            
            Botan::secure_vector<uint8_t> ct = plaintext;
            cipher->finish(ct);
            
            Botan::secure_vector<uint8_t> result;
            result.reserve(salt.size() + iv.size() + ct.size());
            result.insert(result.end(), salt.begin(), salt.end());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), ct.begin(), ct.end());
            
            return result;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static Botan::secure_vector<uint8_t> decryptData(
        const Botan::secure_vector<uint8_t>& encrypted,
        const Botan::secure_vector<uint8_t>& password) {
        
        try {
            if (encrypted.size() < SALT_SIZE + IV_SIZE) {
                return Botan::secure_vector<uint8_t>();
            }
            
            Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
            Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, 
                                             encrypted.begin() + SALT_SIZE + IV_SIZE);
            Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());
            
            Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
            if (key.empty()) return Botan::secure_vector<uint8_t>();
            
            unique_ptr<Botan::Cipher_Mode> cipher = 
                Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
            
            if (!cipher) return Botan::secure_vector<uint8_t>();
            
            cipher->set_key(key);
            cipher->start(iv.data(), iv.size());
            
            Botan::secure_vector<uint8_t> pt = ct;
            cipher->finish(pt);
            
            return pt;
            
        } catch(...) {
            return Botan::secure_vector<uint8_t>();
        }
    }
    
    static bool isArgon2Available() {
        try {
            auto family = Botan::PasswordHashFamily::create("Argon2id");
            return family != nullptr;
        } catch(...) {
            return false;
        }
    }
    
    static void showSecurityInfo() {
        cout << BRIGHT_CYAN << "  Configuración de seguridad (Argon2id):" << RESET << endl;
        cout << "    • Memoria: " << ARGON2_MEMORY_KB / 1024 << " MB" << endl;
        cout << "    • Iteraciones: " << ARGON2_ITERATIONS << endl;
        cout << "    • Paralelismo: " << ARGON2_PARALLELISM << endl;
        cout << "    • Salt: " << SALT_SIZE << " bytes" << endl;
    }
};

// *****************************************************
// Estructura para almacenar información de claves

struct KeyInfo {
    string key_name;
    Botan::secure_vector<uint8_t> key_value;  // 🚨 CRITICO FIX: Ahora es un secure_vector
    string key_type;
    string key_usage;
    time_t created_at;
    time_t last_used;
    bool is_active;
    int strength;
    Botan::secure_vector<uint8_t> access_code;
    bool requires_access;
    
    mutable unique_ptr<MemoryLC> memory_locker;
    
    KeyInfo() : created_at(0), last_used(0), is_active(false), strength(256), requires_access(true) {
        key_type = "AES-256";
    }
    
    KeyInfo(const KeyInfo& other) 
        : key_name(other.key_name), 
          key_value(other.key_value), 
          key_type(other.key_type), 
          key_usage(other.key_usage),
          created_at(other.created_at), 
          last_used(other.last_used), 
          is_active(other.is_active), 
          strength(other.strength),
          access_code(other.access_code), 
          requires_access(other.requires_access),
          memory_locker(nullptr) {}
    
    KeyInfo(KeyInfo&& other) noexcept
        : key_name(std::move(other.key_name)),
          key_value(std::move(other.key_value)),
          key_type(std::move(other.key_type)),
          key_usage(std::move(other.key_usage)),
          created_at(other.created_at),
          last_used(other.last_used),
          is_active(other.is_active),
          strength(other.strength),
          access_code(std::move(other.access_code)),
          requires_access(other.requires_access),
          memory_locker(std::move(other.memory_locker)) {
        other.created_at = 0;
        other.last_used = 0;
        other.is_active = false;
        other.strength = 256;
        other.requires_access = true;
    }
    
    KeyInfo& operator=(const KeyInfo& other) {
        if (this != &other) {
            key_name = other.key_name;
            key_value = other.key_value;
            key_type = other.key_type;
            key_usage = other.key_usage;
            created_at = other.created_at;
            last_used = other.last_used;
            is_active = other.is_active;
            strength = other.strength;
            access_code = other.access_code;
            requires_access = other.requires_access;
            memory_locker.reset();
        }
        return *this;
    }
    
    KeyInfo& operator=(KeyInfo&& other) noexcept {
        if (this != &other) {
            key_name = std::move(other.key_name);
            key_value = std::move(other.key_value);
            key_type = std::move(other.key_type);
            key_usage = std::move(other.key_usage);
            created_at = other.created_at;
            last_used = other.last_used;
            is_active = other.is_active;
            strength = other.strength;
            access_code = std::move(other.access_code);
            requires_access = other.requires_access;
            memory_locker = std::move(other.memory_locker);
            
            other.created_at = 0;
            other.last_used = 0;
            other.is_active = false;
            other.strength = 256;
            other.requires_access = true;
        }
        return *this;
    }
    
    void lockMemory() const {
        if (!access_code.empty() && !memory_locker) {
            void* ptr = const_cast<uint8_t*>(access_code.data());
            memory_locker = make_unique<MemoryLC>(ptr, access_code.size());
        }
        // Botan::secure_vector ya implementa mlock() de manera nativa para key_value.
    }
    
    void unlockMemory() const {
        memory_locker.reset();
    }
    
    ~KeyInfo() {
        access_code.clear();
        key_value.clear();
    }
    
    string serialize() const {
        stringstream ss;
        ss << key_name << "\n";
        // Convertimos a hexadecimal SOLO para la persistencia antes de cifrar
        ss << Botan::hex_encode(key_value) << "\n"; 
        ss << key_type << "\n";
        ss << key_usage << "\n";
        ss << created_at << "\n";
        ss << last_used << "\n";
        ss << (is_active ? "1" : "0") << "\n";
        ss << strength << "\n";
        
        string accessB64 = Botan::base64_encode(access_code);
        ss << accessB64 << "\n";
        
        ss << (requires_access ? "1" : "0");
        return ss.str();
    }
    
    bool deserialize(const string& data) {
        try {
            stringstream ss(data);
            string line;
            
            if (!getline(ss, key_name)) return false;
            
            if (!getline(ss, line)) return false;
            // Recuperamos desde Hex directo al secure_vector
            auto decoded_key = Botan::hex_decode(line);
            key_value.assign(decoded_key.begin(), decoded_key.end());
            
            if (!getline(ss, key_type)) return false;
            if (!getline(ss, key_usage)) return false;
            
            if (!getline(ss, line)) return false;
            created_at = stol(line);
            
            if (!getline(ss, line)) return false;
            last_used = stol(line);
            
            if (!getline(ss, line)) return false;
            is_active = (line == "1");
            
            if (!getline(ss, line)) return false;
            strength = stoi(line);
            
            if (!getline(ss, line)) return false;
            access_code = Botan::base64_decode(line);
            
            if (!getline(ss, line)) return false;
            requires_access = (line == "1");
            
            return true;
        } catch(...) {
            return false;
        }
    }
    
    void display(int index = -1) const {
        if (index != -1) {
            cout << BRIGHT_BLUE << "[" << index + 1 << "] " << RESET;
        }
        
        cout << BRIGHT_GREEN << key_name << RESET;
        
        if (!is_active) {
            cout << RED << " (INACTIVA)" << RESET;
        }
        
        cout << "\n";
        cout << "   Tipo: " << BRIGHT_CYAN << key_type << RESET << " (" << strength << " bits)\n";
        cout << "   Uso: " << BRIGHT_MAGENTA << key_usage << RESET << "\n";
        
        char timeStr[100];
        if (created_at > 0) {
            struct tm* timeinfo = localtime(&created_at);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   Creada: " << BRIGHT_WHITE << timeStr << RESET << "\n";
        }
        
        if (last_used > 0) {
            struct tm* timeinfo = localtime(&last_used);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   Último uso: " << BRIGHT_YELLOW << timeStr << RESET << "\n";
        }
        
        cout << "   Estado: " << (is_active ? BRIGHT_GREEN "ACTIVA" : RED "INACTIVA") << RESET << "\n";
        cout << "\n";
    }
};

// *************************************************************
// CLASE PRINCIPAL DEL GESTOR DE CLAVES
class KeyManager {
private:
    string username;
    Botan::secure_vector<uint8_t> userPasswordSecure;
    map<string, KeyInfo> keys;
    bool passwordVerified;
    
    unique_ptr<MemoryLC> password_locker;
    
    string getKeysFilePath() const {
        extern string get_rubic_data_dir_users();
        
        string data_dir_users;
        const char* xdg_data = getenv("XDG_DATA_HOME");
        if (xdg_data && xdg_data[0] != '\0') {
            data_dir_users = string(xdg_data) + "/RUBIC-A/users";
        } else {
            const char* home = getenv("HOME");
            if (home) {
                data_dir_users = string(home) + "/.local/share/RUBIC-A/users";
            } else {
                data_dir_users = "/tmp/RUBIC-A/users";
            }
        }
        
        struct stat st;
        if (stat(data_dir_users.c_str(), &st) != 0) {
            string current_path;
            stringstream ss(data_dir_users);
            string segment;
            while (getline(ss, segment, '/')) {
                if (segment.empty()) {
                    current_path = "/";
                    continue;
                }
                if (current_path == "/") {
                    current_path += segment;
                } else {
                    current_path += "/" + segment;
                }
                if (stat(current_path.c_str(), &st) != 0) {
                    mkdir(current_path.c_str(), 0700);
                }
            }
        }
        
        return data_dir_users + "/" + username + "_keys.dat";
    }
    
    bool ensureUsersDirectory() const {
        string usersDir;
        const char* xdg_data = getenv("XDG_DATA_HOME");
        if (xdg_data && xdg_data[0] != '\0') {
            usersDir = string(xdg_data) + "/RUBIC-A/users";
        } else {
            const char* home = getenv("HOME");
            if (home) {
                usersDir = string(home) + "/.local/share/RUBIC-A/users";
            } else {
                usersDir = "/tmp/RUBIC-A/users";
            }
        }
        
        struct stat buffer;
        if (stat(usersDir.c_str(), &buffer) == 0) {
            if ((buffer.st_mode & 0777) != 0700) {
                chmod(usersDir.c_str(), 0700);
            }
            return true;
        }
        return mkdir(usersDir.c_str(), 0700) == 0;
    }
    
    bool setSecureFilePermissions(const string& filepath) const {
        return chmod(filepath.c_str(), 0600) == 0;
    }
    
    Botan::secure_vector<uint8_t> encryptDataWithUserPass(const Botan::secure_vector<uint8_t>& plaintext) {
        return KeyCryptoUtils::encryptData(plaintext, userPasswordSecure);
    }
    
    Botan::secure_vector<uint8_t> decryptDataWithUserPass(const Botan::secure_vector<uint8_t>& encrypted) {
        return KeyCryptoUtils::decryptData(encrypted, userPasswordSecure);
    }
    
    bool saveKeysToFile() {
        try {
            if (!ensureUsersDirectory()) {
                cout << RED << "✗ No se puede crear directorio de usuarios" << RESET << endl;
                return false;
            }
            
            if (userPasswordSecure.empty()) {
                cout << RED << "✗ Contraseña de usuario no establecida" << RESET << endl;
                return false;
            }
            
            stringstream allKeysData;
            for (const auto& pair : keys) {
                const KeyInfo& key = pair.second;
                allKeysData << "=== KEY START ===\n";
                allKeysData << key.serialize();
                allKeysData << "\n=== KEY END ===\n\n";
            }
            
            string keysData = allKeysData.str();
            
            Botan::secure_vector<uint8_t> pt_secure(keysData.begin(), keysData.end());
            
            Botan::secure_vector<uint8_t> encrypted = encryptDataWithUserPass(pt_secure);
            if (encrypted.empty()) {
                cout << RED << "✗ Error cifrando claves" << RESET << endl;
                return false;
            }
            
            string encryptedB64 = Botan::base64_encode(encrypted);
            
            string keysFile = getKeysFilePath();
            ofstream file(keysFile, ios::binary);
            if (!file) {
                cout << RED << "✗ No se puede crear archivo de claves" << RESET << endl;
                return false;
            }
            
            file << encryptedB64;
            file.close();
            
            setSecureFilePermissions(keysFile);
            
            return true;
            
        } catch(...) {
            return false;
        }
    }
    
    bool loadKeysFromFile() {
        try {
            string keysFile = getKeysFilePath();
            
            struct stat buffer;
            if (stat(keysFile.c_str(), &buffer) != 0) {
                return true;
            }
            
            if ((buffer.st_mode & 0777) != 0600) {
                chmod(keysFile.c_str(), 0600);
            }
            
            ifstream file(keysFile, ios::binary);
            if (!file) {
                cout << RED << "✗ No se puede abrir archivo de claves" << RESET << endl;
                return false;
            }
            
            stringstream bufferStream;
            bufferStream << file.rdbuf();
            file.close();
            
            string encryptedB64 = bufferStream.str();
            if (encryptedB64.empty()) {
                return true;
            }
            
            Botan::secure_vector<uint8_t> encrypted = Botan::base64_decode(encryptedB64);
            
            Botan::secure_vector<uint8_t> decrypted = decryptDataWithUserPass(encrypted);
            if (decrypted.empty()) {
                cout << RED << "✗ Error descifrando claves. Contraseña incorrecta o archivo corrupto." << RESET << endl;
                return false;
            }
            
            string decryptedStr(decrypted.begin(), decrypted.end());
            
            keys.clear();
            stringstream ss(decryptedStr);
            string line;
            string currentKeyData;
            bool readingKey = false;
            
            while (getline(ss, line)) {
                if (line == "=== KEY START ===") {
                    readingKey = true;
                    currentKeyData.clear();
                } else if (line == "=== KEY END ===") {
                    readingKey = false;
                    
                    KeyInfo key;
                    if (key.deserialize(currentKeyData)) {
                        keys[key.key_name] = std::move(key);
                    }
                    
                    currentKeyData.clear();
                } else if (readingKey) {
                    if (!currentKeyData.empty()) {
                        currentKeyData += "\n";
                    }
                    currentKeyData += line;
                }
            }
            
            return true;
            
        } catch(...) {
            return false;
        }
    }
    
    bool verifyUserPasswordOnce() {
        if (passwordVerified) {
            return true;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "VERIFICACIÓN DE SEGURIDAD" << BRIGHT_BLUE << "]─────────────────────────────┐\n";
        cout << "│" << RESET;
        
        Botan::secure_vector<uint8_t> inputPass = 
            KeySecureInput::readAccessCode("Ingrese su contraseña:");
        
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (!inputPass.empty()) {
            password_locker = make_unique<MemoryLC>(inputPass.data(), inputPass.size());
        }
        
        bool match = (inputPass.size() == userPasswordSecure.size() && 
                     secure_memcmp(inputPass.data(), userPasswordSecure.data(), inputPass.size()));
        
        if (!match) {
            cout << RED << "✗ Contraseña incorrecta. Acceso denegado." << RESET << endl;
            inputPass.clear();
            password_locker.reset();
            return false;
        }
        
        inputPass.clear();
        password_locker.reset();
        passwordVerified = true;
        
        cout << GREEN << "✓ Acceso concedido." << RESET << endl;
        return true;
    }
    
    void printKeyManagerHeader() const {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    GESTOR DE CLAVES AES-256                      " << BRIGHT_BLUE << "│\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        cout << "│" << RESET << "  Usuario: " << BRIGHT_MAGENTA << username << RESET << "                                           │\n";
        cout << "│" << RESET << "  Claves almacenadas: " << BRIGHT_CYAN << keys.size() << RESET << "                                │\n";
        
        if (KeyCryptoUtils::isArgon2Available()) {
            cout << "│" << BRIGHT_GREEN << "  Protección: Argon2id + AES-256-GCM                          " << BRIGHT_BLUE << "│\n";
        }
        
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    void createKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                   CREAR NUEVA CLAVE AES-256                     " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string keyName;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "NOMBRE DE LA CLAVE" << BRIGHT_BLUE << "]──────────────────────────────────┐\n";
        cout << "│ " << RESET;
        cout << "Nombre para identificar la clave: ";
        keyName = KeySecureInput::readStringNormal("");
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (keyName.empty()) {
            cout << RED << "\n✗ El nombre de la clave no puede estar vacío" << RESET << endl;
            return;
        }
        
        if (keys.find(keyName) != keys.end()) {
            cout << RED << "\n✗ Ya existe una clave con ese nombre" << RESET << endl;
            return;
        }
        
        string keyUsage;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "USO DE LA CLAVE" << BRIGHT_BLUE << "]─────────────────────────────────────┐\n";
        cout << "│ " << RESET;
        cout << "Para qué usará esta clave: ";
        keyUsage = KeySecureInput::readStringNormal("");
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        if (keyUsage.empty()) {
            keyUsage = "Cifrado de unidades";
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "CLAVE DE ACCESO" << BRIGHT_BLUE << "]───────────────────────────────────┐\n";
        cout << "│" << RESET << "  Configure una clave de acceso para esta clave.                     " << RESET << "│\n";
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        Botan::secure_vector<uint8_t> accessCode = 
            KeySecureInput::readAccessCodeWithConfirm("Clave de acceso: ", "Confirmar clave de acceso: ");
        
        if (accessCode.empty()) {
            cout << RED << "\n✗ La clave de acceso no puede estar vacía" << RESET << endl;
            return;
        }
        
        cout << MAGENTA << "\nGenerando clave AES-256..." << RESET << endl;
        
        // Generamos desde 
        Botan::secure_vector<uint8_t> keyValue = KeyCryptoUtils::generateRandomBytes(32);
        if (keyValue.empty()) {
            cout << RED << "\n✗ Error generando la clave criptográfica" << RESET << endl;
            accessCode.clear();
            return;
        }
        
        cout << GREEN << "✓ Clave generada exitosamente" << RESET << endl;
        
        KeyInfo newKey;
        newKey.key_name = keyName;
        newKey.key_value = std::move(keyValue);
        newKey.key_type = "AES-256";
        newKey.key_usage = keyUsage;
        newKey.created_at = time(nullptr);
        newKey.last_used = 0;
        newKey.is_active = false;
        newKey.strength = 256;
        newKey.access_code = accessCode;
        newKey.requires_access = true;
        
        newKey.lockMemory();
        
        keys[keyName] = std::move(newKey);
        accessCode.clear();
        
        if (saveKeysToFile()) {
            cout << GREEN;
            cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│" << BRIGHT_GREEN << "                   CLAVE CREADA EXITOSAMENTE                     " << GREEN << "│\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            cout << "│" << RESET << "  Nombre: " << BRIGHT_MAGENTA << keyName << RESET << "                                           │\n";
            cout << "│" << RESET << "  Tipo: " << BRIGHT_CYAN << "AES-256 (256 bits)" << RESET << "                               │\n";
            cout << "│" << RESET << "  Uso: " << BRIGHT_GREEN << keyUsage << RESET << "                                          │\n";
            cout << "│" << RESET << "  Estado: " << RED << "INACTIVA" << RESET << "                                             │\n";
            cout << GREEN << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        } else {
            cout << RED << "\n✗ Error guardando la clave" << RESET << endl;
            keys.erase(keyName);
        }
    }
    
    void toggleKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                  ACTIVAR/DESACTIVAR CLAVE                       " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (keys.empty()) {
            cout << YELLOW << "\nNo hay claves almacenadas." << RESET << endl;
            return;
        }
        
        cout << "\nClaves disponibles:\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (auto& pair : keys) {
            if (!pair.second.access_code.empty() && !pair.second.memory_locker) {
                pair.second.lockMemory();
            }
            pair.second.display(index);
            keyNames.push_back(pair.first);
            index++;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "SELECCIONAR CLAVE" << BRIGHT_BLUE << "]─────────────────────────────────────┐\n";
        cout << "│ " << RESET;
        cout << "Seleccione el número de la clave: ";
        string choiceStr = KeySecureInput::readStringNormal("");
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n✗ Selección inválida" << RESET << endl;
                return;
            }
            
            string selectedKey = keyNames[choice];
            KeyInfo& key = keys[selectedKey];
            
            if (key.is_active) {
                cout << "¿Desactivar la clave \"" << key.key_name << "\"? (s/N): ";
                string confirm = KeySecureInput::readStringNormal("");
                
                if (confirm != "s" && confirm != "S") {
                    cout << "Operación cancelada." << endl;
                    return;
                }
                
                key.is_active = false;
                key.last_used = time(nullptr);
                
                if (saveKeysToFile()) {
                    cout << GREEN << "\n✓ Clave desactivada" << RESET << endl;
                } else {
                    cout << RED << "\n✗ Error guardando cambios" << RESET << endl;
                    key.is_active = true;
                }
                return;
            }
            
            if (!key.is_active && key.requires_access) {
                Botan::secure_vector<uint8_t> inputCode = 
                    KeySecureInput::readAccessCode("Clave de acceso para \"" + key.key_name + "\": ");
                
                unique_ptr<MemoryLC> input_locker;
                if (!inputCode.empty()) {
                    input_locker = make_unique<MemoryLC>(inputCode.data(), inputCode.size());
                }
                
                bool match = (inputCode.size() == key.access_code.size() && 
                             secure_memcmp(inputCode.data(), key.access_code.data(), inputCode.size()));
                
                if (!match) {
                    cout << RED << "\n✗ Clave de acceso incorrecta" << RESET << endl;
                    inputCode.clear();
                    input_locker.reset();
                    return;
                }
                
                inputCode.clear();
                input_locker.reset();
                
                cout << "¿Activar la clave \"" << key.key_name << "\"? (s/N): ";
                string confirm = KeySecureInput::readStringNormal("");
                
                if (confirm != "s" && confirm != "S") {
                    cout << "Operación cancelada." << endl;
                    return;
                }
                
                key.is_active = true;
                key.last_used = time(nullptr);
                
                if (saveKeysToFile()) {
                    cout << GREEN << "\n✓ Clave activada" << RESET << endl;
                    cout << "Nombre: " << BRIGHT_MAGENTA << key.key_name << RESET << endl;
                    cout << "Estado: " << BRIGHT_GREEN << "ACTIVA" << RESET << endl;
                } else {
                    cout << RED << "\n✗ Error guardando cambios" << RESET << endl;
                    key.is_active = false;
                }
            }
            
        } catch(...) {
            cout << RED << "\n✗ Selección inválida" << RESET << endl;
        }
    }
    
    void listKeysMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    LISTA DE CLAVES AES-256                      " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (keys.empty()) {
            cout << YELLOW << "\nNo hay claves almacenadas." << RESET << endl;
            cout << "\nPresione Enter para continuar...";
            cin.get();
            return;
        }
        
        cout << "\nClaves almacenadas (" << keys.size() << "):\n" << endl;
        
        int index = 0;
        int activeCount = 0;
        
        for (auto& pair : keys) {
            const KeyInfo& key = pair.second;
            key.display(index);
            if (key.is_active) activeCount++;
            index++;
        }
        
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << RESET << "  Total: " << BRIGHT_CYAN << keys.size() << RESET << " claves | Activas: " << BRIGHT_GREEN << activeCount << RESET << " | Inactivas: " << BRIGHT_RED << (keys.size() - activeCount) << RESET << "          │\n";
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        cout << "\nPresione Enter para continuar...";
        cin.get();
    }
    
    void deleteKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    ELIMINAR CLAVE                              " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (keys.empty()) {
            cout << YELLOW << "\nNo hay claves para eliminar." << RESET << endl;
            return;
        }
        
        cout << "\nClaves disponibles:\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (auto& pair : keys) {
            pair.second.display(index);
            keyNames.push_back(pair.first);
            index++;
        }
        
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "SELECCIONAR CLAVE A ELIMINAR" << BRIGHT_BLUE << "]──────────────────────────┐\n";
        cout << "│ " << RESET;
        cout << "Seleccione el número de la clave a eliminar: ";
        string choiceStr = KeySecureInput::readStringNormal("");
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << endl;
        
        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n✗ Selección inválida" << RESET << endl;
                return;
            }
            
            string selectedKey = keyNames[choice];
            KeyInfo& key = keys[selectedKey];
            
            cout << RED << "\n⚠ ADVERTENCIA: Esta acción no se puede deshacer." << RESET << endl;
            cout << "¿Está seguro que desea eliminar la clave \"" << key.key_name << "\"? (s/N): ";
            string confirm = KeySecureInput::readStringNormal("");
            
            if (confirm != "s" && confirm != "S") {
                cout << "Operación cancelada." << endl;
                return;
            }
            
            if (key.requires_access && !key.access_code.empty()) {
                Botan::secure_vector<uint8_t> inputCode = 
                    KeySecureInput::readAccessCode("Clave de acceso para confirmar: ");
                
                unique_ptr<MemoryLC> input_locker;
                if (!inputCode.empty()) {
                    input_locker = make_unique<MemoryLC>(inputCode.data(), inputCode.size());
                }
                
                bool match = (inputCode.size() == key.access_code.size() && 
                             secure_memcmp(inputCode.data(), key.access_code.data(), inputCode.size()));
                
                if (!match) {
                    cout << RED << "\n✗ Clave de acceso incorrecta. Eliminación cancelada." << RESET << endl;
                    inputCode.clear();
                    input_locker.reset();
                    return;
                }
                
                inputCode.clear();
                input_locker.reset();
            }
            
            keys.erase(selectedKey);
            
            if (saveKeysToFile()) {
                cout << GREEN << "\n✓ Clave eliminada" << RESET << endl;
            } else {
                cout << RED << "\n✗ Error guardando cambios" << RESET << endl;
            }
            
        } catch(...) {
            cout << RED << "\n✗ Selección inválida" << RESET << endl;
        }
    }

public:
    KeyManager() : passwordVerified(false) {}
    
    ~KeyManager() {
        userPasswordSecure.clear();
        password_locker.reset();
    }
    
    void setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password) {
        userPasswordSecure = password;
        
        if (!userPasswordSecure.empty()) {
            password_locker = make_unique<MemoryLC>(
                const_cast<uint8_t*>(userPasswordSecure.data()), 
                userPasswordSecure.size()
            );
        }
    }
    
    void setUsername(const string& name) {
        username = name;
        if (!userPasswordSecure.empty()) {
            loadKeysFromFile();
            
            for (auto& pair : keys) {
                if (!pair.second.access_code.empty() && !pair.second.memory_locker) {
                    pair.second.lockMemory();
                }
            }
        }
    }
    
    void saveKeys() {
        if (!username.empty() && !userPasswordSecure.empty() && !keys.empty()) {
            saveKeysToFile();
        }
    }
    
    void showMenu() {
        if (!verifyUserPasswordOnce()) {
            return;
        }
        
        while (true) {
            printKeyManagerHeader();
            
            cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "OPCIONES" << BRIGHT_BLUE << "]───────────────────────────────────────────────┐\n";
            cout << "│" << BRIGHT_GREEN << " [1] " << BRIGHT_MAGENTA << " Crear nueva clave AES-256                                 " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [2] " << BRIGHT_MAGENTA << " Activar/Desactivar clave                                 " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [3] " << BRIGHT_MAGENTA << " Lista de claves                                          " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [4] " << BRIGHT_MAGENTA << " Eliminar clave                                           " << BRIGHT_BLUE << "│\n";
            cout << "│" << BRIGHT_GREEN << " [5] " << BRIGHT_MAGENTA << " Volver                                                   " << BRIGHT_BLUE << "│\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            cout << BRIGHT_GREEN << "\nSeleccione opción [" << BRIGHT_MAGENTA << "1-5" << BRIGHT_GREEN << "]: " << RESET;
            
            string choice;
            getline(cin, choice);
            
            if (choice == "1") {
                createKeyMenu();
            } else if (choice == "2") {
                toggleKeyMenu();
            } else if (choice == "3") {
                listKeysMenu();
            } else if (choice == "4") {
                deleteKeyMenu();
            } else if (choice == "5") {
                saveKeys();
                break;
            } else {
                cout << RED << "\n✗ Opción no válida" << RESET << endl;
            }
        }
    }
    
    const map<string, KeyInfo>& getKeys() const {
        return keys;
    }
    
    bool hasKey(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end();
    }
    
    bool isKeyActive(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end() && it->second.is_active;
    }
    // 
    Botan::secure_vector<uint8_t> getKeyValue(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it != keys.end() && it->second.is_active) {
            return it->second.key_value;
        }
        return Botan::secure_vector<uint8_t>();
    }
    
    bool activateKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode) {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            return false;
        }
        
        KeyInfo& key = it->second;
        
        if (key.is_active) {
            return true;
        }
        
        if (!key.requires_access) {
            key.is_active = true;
            key.last_used = time(nullptr);
            saveKeysToFile();
            return true;
        }
        
        bool match = (accessCode.size() == key.access_code.size() && 
                     secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
        
        if (!match) {
            return false;
        }
        
        key.is_active = true;
        key.last_used = time(nullptr);
        
        if (saveKeysToFile()) {
            return true;
        } else {
            key.is_active = false;
            return false;
        }
    }
    
    bool activateKey(const string& keyName, const string& accessCode) {
        Botan::secure_vector<uint8_t> codeSecure(accessCode.begin(), accessCode.end());
        return activateKey(keyName, codeSecure);
    }
    
    bool keyRequiresActivation(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            return false;
        }
        return it->second.requires_access;
    }
    
    bool hasKeys() const {
        return !keys.empty();
    }
    
    vector<string> getActiveKeys() const {
        vector<string> activeKeys;
        for (const auto& pair : keys) {
            if (pair.second.is_active) {
                activeKeys.push_back(pair.first);
            }
        }
        return activeKeys;
    }
    
    void resetVerification() {
        passwordVerified = false;
    }
    
    static bool isArgon2Available() {
        return KeyCryptoUtils::isArgon2Available();
    }
};

#endif 
// KEY_MANAGER_H