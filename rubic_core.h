#ifndef RUBIC_CORE_H
#define RUBIC_CORE_H

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <memory>
#include <map>
#include <cstring>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <termios.h>
#include <unistd.h>
#include <queue>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <immintrin.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <signal.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pwd.h>

// Botan 3
#include <botan/pwdhash.h> 
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/dilithium.h>
#include <botan/kyber.h>
#include <botan/data_src.h>

using namespace std;

// ******************************************
// INCLUDES DE LOS MÓDULOS //
#include "key_manager.h"
#include "share_manager.h"
#include "universal_cipher.h"
#include "unit_encryptor.h"

// colores-para-la-ui
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define BRIGHT_RED     "\033[91m"
#define BRIGHT_GREEN   "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#define BRIGHT_BLUE    "\033[94m"
#define BRIGHT_MAGENTA "\033[95m"
#define BRIGHT_CYAN    "\033[96m"
#define BRIGHT_WHITE   "\033[97m"

// constantes-de-configuracion
constexpr int SALT_SIZE = 32;
constexpr int KEY_SIZE = 32;
constexpr int IV_SIZE = 12;
constexpr int HASH_SIZE = 32;
constexpr size_t ARGON2_MEMORY = 128 * 1024;
constexpr size_t ARGON2_ITERATIONS = 4;
constexpr size_t ARGON2_PARALLELISM = 4;
constexpr int MASTER_KEY_SIZE = 32;

// **************************************
// BLOQUEO-DE-MEMORIA-mlock //

class Memguardin {
private:
    static bool mlock_active;
    
public:
    static bool lockProcess() {
        #ifdef __linux__
        struct rlimit core_limits = {0, 0};
        setrlimit(RLIMIT_CORE, &core_limits);
        prctl(PR_SET_DUMPABLE, 0);
        mlock_active = (mlockall(MCL_CURRENT | MCL_FUTURE) == 0);
        return mlock_active;
        #else
        return true;
        #endif
    }
    
    static void unlockProcess() {
        #ifdef __linux__
        if (mlock_active) {
            munlockall();
            mlock_active = false;
        }
        #endif
    }
};

bool Memguardin::mlock_active = false;

// ****************************************
// MANEJADOR-DE-CRASH //

class CrashHnd {
public:
    static void setup() {
        struct sigaction sa;
        sa.sa_handler = [](int sig) {
            const char* msg = "\n\x1b[91m✗ CRASH: Limpiando memoria segura...\x1b[0m\n";
            if (write(STDERR_FILENO, msg, strlen(msg)) < 0) {}
            Memguardin::unlockProcess();
            signal(sig, SIG_DFL);
            raise(sig);
        };
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGABRT, &sa, nullptr);
        sigaction(SIGFPE, &sa, nullptr);
        sigaction(SIGILL, &sa, nullptr);
        sigaction(SIGBUS, &sa, nullptr);
    }
};

// *****************************************
// LIMPIEZA-DE-MEMORIA //

inline void secure_z(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}

template<typename T>
inline void secure_c_container(T& container) {
    if (!container.empty()) {
        secure_z(container.data(), container.size() * sizeof(typename T::value_type));
        container.clear();
    }
}

inline bool ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

template<typename T>
inline bool secure_compare(const T& a, const T& b) {
    if (a.size() != b.size()) return false;
    return ct_compare(
        reinterpret_cast<const uint8_t*>(a.data()),
        reinterpret_cast<const uint8_t*>(b.data()),
        a.size() * sizeof(typename T::value_type)
    );
}

// **************************************
// LECTOR-DE-CONTRASEÑAS

class PwdReader {
private:
    static struct termios old_termios;
    static bool termios_saved;
    
    static void raw_mode(bool enable) {
        if (enable) {
            if (!termios_saved) {
                tcgetattr(STDIN_FILENO, &old_termios);
                termios_saved = true;
            }
            struct termios raw = old_termios;
            raw.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        } else if (termios_saved) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        }
    }
    
public:
    static Botan::secure_vector<uint8_t> readPassword(const string& prompt = "Contraseña: ") {
        raw_mode(true);
        Botan::secure_vector<uint8_t> pass;
        
        cout << prompt << flush;
        char c;
        while (::read(STDIN_FILENO, &c, 1) == 1) {
            if (c == '\n' || c == '\r') break;
            if (c == 127 || c == '\b') {
                if (!pass.empty()) {
                    pass.pop_back();
                    cout << "\b \b" << flush;
                }
                continue;
            }
            pass.push_back(static_cast<uint8_t>(c));
            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(50));
            cout << "\b*" << flush;
        }
        
        raw_mode(false);
        cout << endl;
        return pass;
    }
    
    static Botan::secure_vector<uint8_t> readWithConfirm() {
        for (int i = 0; i < 3; i++) {
            auto p1 = readPassword("Contraseña: ");
            if (p1.size() < 8) {
                cout << RED << "X Mínimo 8 caracteres" << RESET << endl;
                secure_c_container(p1);
                continue;
            }
            
            auto p2 = readPassword("Confirmar: ");
            if (secure_compare(p1, p2)) {
                secure_c_container(p2);
                return p1;
            }
            
            cout << RED << "✗ No coinciden (" << (i+1) << "/3)" << RESET << endl;
            secure_c_container(p1);
            secure_c_container(p2);
        }
        return {};
    }
};

bool PwdReader::termios_saved = false;
struct termios PwdReader::old_termios;

// ********************************************
// UTILIDADES-DE-ARCHIVOS Y XDG DE RUTAS //


namespace XDG {
    inline string get_xdg_data_home() {
        const char* xdg_data = getenv("XDG_DATA_HOME");
        if (xdg_data && xdg_data[0] != '\0') {
            return string(xdg_data);
        }
        const char* home = getenv("HOME");
        if (home) {
            return string(home) + "/.local/share";
        }
        return "/tmp";
    }
    
    inline string get_xdg_config_home() {
        const char* xdg_config = getenv("XDG_CONFIG_HOME");
        if (xdg_config && xdg_config[0] != '\0') {
            return string(xdg_config);
        }
        const char* home = getenv("HOME");
        if (home) {
            return string(home) + "/.config";
        }
        return "/tmp";
    }
    
    inline bool create_dir_recursive(const string& path) {
        struct stat st;
        if (stat(path.c_str(), &st) == 0) return true;
        
        string current_path;
        stringstream ss(path);
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
                if (mkdir(current_path.c_str(), 0700) != 0) return false;
            }
        }
        return true;
    }
    
    inline string get_rubic_data_dir() {
        string data_dir = get_xdg_data_home() + "/RUBIC-A";
        create_dir_recursive(data_dir);
        return data_dir;
    }
    
    inline string get_rubic_config_dir() {
        string config_dir = get_xdg_config_home() + "/RUBIC-A";
        create_dir_recursive(config_dir);
        return config_dir;
    }
}

namespace FileUtil {
    inline bool exists(const string& path) {
        struct stat st;
        return stat(path.c_str(), &st) == 0;
    }
    
    inline bool is_dir(const string& path) {
        struct stat st;
        return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    }
    
    inline bool create_dir(const string& path) {
        #ifdef __linux__
        return mkdir(path.c_str(), 0700) == 0;
        #else
        return mkdir(path.c_str()) == 0;
        #endif
    }
    
    inline bool create_dir_recursive(const string& path) {
        return XDG::create_dir_recursive(path);
    }
    
    string get_downloads() {
        const char* home = getenv("HOME");
        if (!home) return "";
        
        vector<string> dirs = {
            string(home) + "/Descargas",
            string(home) + "/Downloads"
        };
        
        for (const auto& d : dirs) {
            if (is_dir(d)) return d;
        }
        return string(home);
    }
    
    Botan::secure_vector<uint8_t> read_all(const string& path) {
        Botan::secure_vector<uint8_t> data;
        ifstream f(path, ios::binary | ios::ate);
        if (!f) return data;
        
        size_t sz = f.tellg();
        f.seekg(0);
        data.resize(sz);
        f.read(reinterpret_cast<char*>(data.data()), sz);
        return data;
    }
    
    bool write_all(const string& path, const void* data, size_t len) {
        ofstream f(path, ios::binary);
        if (!f) return false;
        f.write(static_cast<const char*>(data), len);
        #ifdef __linux__
        chmod(path.c_str(), 0600);
        #endif
        return f.good();
    }
    
    bool secure_remove(const string& path) {
        if (!exists(path)) return true;
        
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && st.st_size > 0) {
            vector<uint8_t> zeros(st.st_size, 0);
            write_all(path, zeros.data(), zeros.size());
        }
        
        return remove(path.c_str()) == 0;
    }
};

// *******************************************
// OPERACIONES-CRIPTOGRAFICAS //

namespace Crypto {
    inline Botan::secure_vector<uint8_t> rand_bytes(size_t n) {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> out(n);
        rng.randomize(out.data(), n);
        return out;
    }
    
    inline string b64enc(const uint8_t* data, size_t len) {
        return Botan::base64_encode(data, len);
    }
    
    inline Botan::secure_vector<uint8_t> b64dec(const string& s) {
        return Botan::base64_decode(s);
    }
    
    inline string hex(const uint8_t* data, size_t len) {
        return Botan::hex_encode(data, len);
    }
    
    Botan::secure_vector<uint8_t> argon2(
        const Botan::secure_vector<uint8_t>& pass,
        const Botan::secure_vector<uint8_t>& salt,
        size_t out_len = KEY_SIZE
    ) {
        Botan::secure_vector<uint8_t> key(out_len);
        auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
        if (!pwdhash_fam) return key;
        
        auto pwdhash = pwdhash_fam->from_params(ARGON2_MEMORY, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
        pwdhash->derive_key(
            key.data(), key.size(),
            reinterpret_cast<const char*>(pass.data()), pass.size(),
            salt.data(), salt.size()
        );
        return key;
    }

    Botan::secure_vector<uint8_t> combine_keys_hmac(
        const Botan::secure_vector<uint8_t>& master_key, 
        const Botan::secure_vector<uint8_t>& system_key  
    ) {
        auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac) return master_key; 
        
        hmac->set_key(system_key);
        hmac->update(master_key.data(), master_key.size());
        return hmac->final();
    }

    Botan::secure_vector<uint8_t> get_system_key(const string& context = "") {
        string sys_id = "";
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            sys_id += string(hostname);
        }
        
        ifstream machine_id("/etc/machine-id");
        if (machine_id.good()) {
            string mid;
            machine_id >> mid;
            sys_id += "-" + mid;
        }
        
        sys_id += "-RUBIC-BIND-" + context;
        
        auto hash = Botan::HashFunction::create("SHA-256");
        if (!hash) return rand_bytes(32); 
        vector<uint8_t> out(32);
        hash->update(reinterpret_cast<const uint8_t*>(sys_id.data()), sys_id.size());
        hash->final(out.data());
        return Botan::secure_vector<uint8_t>(out.begin(), out.end());
    }
    
    Botan::secure_vector<uint8_t> aes_gcm_enc(
        const Botan::secure_vector<uint8_t>& plain,
        const Botan::secure_vector<uint8_t>& key,
        const Botan::secure_vector<uint8_t>& system_key = {}
    ) {
        auto salt = rand_bytes(SALT_SIZE);
        auto master_key = argon2(key, salt);
        
        Botan::secure_vector<uint8_t> final_key = master_key;
        if (!system_key.empty()) {
            final_key = combine_keys_hmac(master_key, system_key);  
        }
        
        auto iv = rand_bytes(IV_SIZE);
        
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        if (!cipher) return {};
        
        cipher->set_key(final_key);
        cipher->start(iv.data(), iv.size());
        
        Botan::secure_vector<uint8_t> ct = plain;
        cipher->finish(ct);
        
        Botan::secure_vector<uint8_t> out;
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), ct.begin(), ct.end());
        return out;
    }
    
    Botan::secure_vector<uint8_t> aes_gcm_dec(
        const Botan::secure_vector<uint8_t>& encrypted,
        const Botan::secure_vector<uint8_t>& key,
        const Botan::secure_vector<uint8_t>& system_key = {}
    ) {
        if (encrypted.size() < SALT_SIZE + IV_SIZE) return {};
        
        Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
        Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, encrypted.begin() + SALT_SIZE + IV_SIZE);
        Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());
        
        auto master_key = argon2(key, salt); 
        
        Botan::secure_vector<uint8_t> final_key = master_key;
        if (!system_key.empty()) {
            final_key = combine_keys_hmac(master_key, system_key); 
        }
        
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        if (!cipher) return {};
        
        cipher->set_key(final_key);
        cipher->start(iv.data(), iv.size());
        
        Botan::secure_vector<uint8_t> pt = ct;
        try {
            cipher->finish(pt);
            return pt;
        } catch (const Botan::Integrity_Failure& e) {
            std::cerr << "\n" << BRIGHT_RED << "[!] ALERTA CRÍTICA: Fallo de integridad AES-GCM o Hardware BIND inválido." << RESET << "\n";
            return {};
        } catch (const std::exception& e) {
            std::cerr << "\n" << BRIGHT_RED << "[!] Error criptográfico general: " << e.what() << RESET << "\n";
            return {};
        }
    }
    
    Botan::secure_vector<uint8_t> gen_master_key() {
        return rand_bytes(MASTER_KEY_SIZE);
    }
};

// ***************************************************
// GESTOR-DE--DILITHIUM-PQC //

class DiliID {
private:
    unique_ptr<Botan::Private_Key> priv_key;
    unique_ptr<Botan::Public_Key> pub_key;
    vector<uint8_t> pub_key_enc;
    string fprint;
    bool init = false;
    Botan::AutoSeeded_RNG rng;
    
public:
    DiliID() = default;
    
    bool generate() {
        try {
            Botan::DilithiumMode mode("Dilithium-6x5-AES-r3");
            Botan::Dilithium_PrivateKey priv(rng, mode);
            
            priv_key = make_unique<Botan::Dilithium_PrivateKey>(priv);
            pub_key = make_unique<Botan::Dilithium_PublicKey>(priv);
            
            pub_key_enc = Botan::X509::BER_encode(*pub_key);
            
            auto hash = Botan::HashFunction::create("SHA-256");
            vector<uint8_t> h(32);
            hash->update(pub_key_enc);
            hash->final(h.data());
            fprint = Botan::hex_encode(h.data(), 16);
            
            init = true;
            return true;
        } catch (...) {
            return false;
        }
    }
    
    bool loadFromPubKey(const vector<uint8_t>& pub_data) {
        try {
            Botan::DataSource_Memory src(pub_data);
            pub_key = Botan::X509::load_key(src);
            pub_key_enc = pub_data;
            
            auto hash = Botan::HashFunction::create("SHA-256");
            vector<uint8_t> h(32);
            hash->update(pub_data);
            hash->final(h.data());
            fprint = Botan::hex_encode(h.data(), 16);
            
            init = true;
            return true;
        } catch (...) {
            return false;
        }
    }
    
    bool verify(const vector<uint8_t>& data, const vector<uint8_t>& sig) {
        if (!init || !pub_key) return false;
        
        try {
            Botan::PK_Verifier verifier(*pub_key, "SHA-512");
            return verifier.verify_message(data, sig);
        } catch (...) {
            return false;
        }
    }
    
    const vector<uint8_t>& getPubKey() const { return pub_key_enc; }
    string getFprint() const { return fprint; }
    bool isInit() const { return init; }
};

// *****************************************
// REGISTRO-DE-USUARIO // 

struct UserRec {
    string name_hash;
    Botan::secure_vector<uint8_t> pwd_hash;
    Botan::secure_vector<uint8_t> salt;
    Botan::secure_vector<uint8_t> enc_name;
    time_t created = 0;
    time_t last_login = 0;
    string algo = "ARGON2";
    int version = 5;
    
    bool has_id = false;
    vector<uint8_t> id_pub_key;
    string id_fprint;
    
    ~UserRec() {
        secure_c_container(pwd_hash);
        secure_c_container(salt);
        secure_c_container(enc_name);
        secure_c_container(id_pub_key);
    }
    
    string serialize() const {
        stringstream ss;
        ss << name_hash << "\n"
           << Crypto::b64enc(pwd_hash.data(), pwd_hash.size()) << "\n"
           << Crypto::b64enc(salt.data(), salt.size()) << "\n"
           << Crypto::b64enc(enc_name.data(), enc_name.size()) << "\n"
           << created << "\n"
           << last_login << "\n"
           << algo << "\n"
           << version << "\n"
           << (has_id ? "1" : "0") << "\n";
        
        if (has_id) {
            ss << Crypto::b64enc(id_pub_key.data(), id_pub_key.size()) << "\n"
               << id_fprint << "\n";
        }
        
        return ss.str();
    }
    
    bool deserialize(const string& data) {
        stringstream ss(data);
        string line;
        
        if (!getline(ss, line)) return false; name_hash = line;
        if (!getline(ss, line)) return false; pwd_hash = Crypto::b64dec(line);
        if (!getline(ss, line)) return false; salt = Crypto::b64dec(line);
        if (!getline(ss, line)) return false; enc_name = Crypto::b64dec(line);
        if (!getline(ss, line)) return false; created = stoll(line);
        if (!getline(ss, line)) return false; last_login = stoll(line);
        if (!getline(ss, line)) return false; algo = line;
        if (!getline(ss, line)) return false; version = stoi(line);
        if (!getline(ss, line)) return false; has_id = (line == "1");
        
        if (has_id) {
            if (!getline(ss, line)) return false;
            auto decoded = Crypto::b64dec(line);
            id_pub_key.assign(decoded.begin(), decoded.end());
            if (!getline(ss, line)) return false;
            id_fprint = line;
        }
        
        return true;
    }
    
    string decryptName(const Botan::secure_vector<uint8_t>& key) const {
        auto dec = Crypto::aes_gcm_dec(enc_name, key);
        if (dec.empty()) return "";
        return string(dec.begin(), dec.end());
    }
};


// ******************************************
// GESTOR-PRINCIPAL-DE-USUARIOS-SISTEMA //

class UserMgr {
private:
    string users_dir;
    string cur_user;
    string cur_user_hash;
    Botan::secure_vector<uint8_t> mast_pwd;
    Botan::secure_vector<uint8_t> mast_key;
    string mast_key_path;
    bool auth = false;
    bool modules_init = false;
    
    unique_ptr<KeyManager> key_mgr;
    unique_ptr<ShareManager> share_mgr;
    unique_ptr<UniversalCipher> univ_ciph;
    unique_ptr<UnitEncryptor> unit_enc;
    unique_ptr<DiliID> id_mgr;
    
    struct LoginThrottle {
        map<string, pair<int, time_t>> attempts;
        const int MAX_FAIL = 5;
        const int LOCK_SEC = 300;
        
        bool can_try(const string& u) {
            auto it = attempts.find(u);
            if (it == attempts.end()) return true;
            if (it->second.second > time(nullptr)) return false;
            return true;
        }
        
        int wait_time(const string& u) {
            auto it = attempts.find(u);
            if (it == attempts.end()) return 0;
            return max(0L, it->second.second - time(nullptr));
        }
        
        void rec_fail(const string& u) {
            auto& a = attempts[u];
            a.first++;
            if (a.first >= MAX_FAIL) {
                a.second = time(nullptr) + LOCK_SEC;
            }
        }
        
        void rec_success(const string& u) {
            attempts.erase(u);
        }
    } throttle;
    
    void ensure_dirs() {
        users_dir = XDG::get_rubic_data_dir() + "/users";
        if (!FileUtil::is_dir(users_dir)) {
            XDG::create_dir_recursive(users_dir);
        }
        mast_key_path = users_dir + "/.system";
    }
    
    void init_master_key() {
        bool key_loaded = false;
        
        if (FileUtil::exists(mast_key_path)) {
            auto enc_key = FileUtil::read_all(mast_key_path);
            if (enc_key.size() >= SALT_SIZE + IV_SIZE) {
                auto sys_key = Crypto::get_system_key("SYSTEM_ROOT");
                auto decrypted = Crypto::aes_gcm_dec(enc_key, sys_key);
                
                if (!decrypted.empty() && decrypted.size() == MASTER_KEY_SIZE) {
                    mast_key = decrypted;
                    key_loaded = true;
                } else {
                    throw std::runtime_error("Fallo crítico de integridad o acceso en hardware clonado. Master Key inaccesible.");
                }
            }
        }
        
        if (!key_loaded) {
            if (FileUtil::exists(idx_path())) {
                throw std::runtime_error("Índice de usuarios detectado pero falta la clave maestra del sistema. Abortando para evitar corrupción.");
            } else {
                mast_key = Crypto::gen_master_key();
                
                auto sys_key = Crypto::get_system_key("SYSTEM_ROOT");
                auto enc_key = Crypto::aes_gcm_enc(mast_key, sys_key);
                
                if (!enc_key.empty()) {
                    FileUtil::write_all(mast_key_path, enc_key.data(), enc_key.size());
                } else {
                    throw std::runtime_error("Fallo crítico al intentar cifrar la nueva clave maestra.");
                }
            }
        }
    }
    
    string hash_user(const string& u) {
        auto h = Botan::HashFunction::create("SHA-256");
        if (!h) return "";
        vector<uint8_t> out(HASH_SIZE);
        h->update(reinterpret_cast<const uint8_t*>(u.data()), u.size());
        h->final(out.data());
        return Crypto::hex(out.data(), out.size());
    }
    
    string user_path(const string& u_hash) {
        return users_dir + "/" + u_hash + ".enc";
    }
    
    string idx_path() {
        return users_dir + "/.idx";
    }
    
    vector<string> load_idx() {
        vector<string> users;
        if (!FileUtil::exists(idx_path())) return users;
        
        auto enc = FileUtil::read_all(idx_path());
        if (enc.empty()) return users;
        
        auto dec = Crypto::aes_gcm_dec(enc, mast_key);
        if (dec.empty()) return users;
        
        string data(dec.begin(), dec.end());
        stringstream ss(data);
        string u;
        while (getline(ss, u)) {
            if (!u.empty()) users.push_back(u);
        }
        return users;
    }
    
    void save_idx(const vector<string>& users) {
        stringstream ss;
        for (const auto& u : users) ss << u << "\n";
        string data = ss.str();
        Botan::secure_vector<uint8_t> pt(data.begin(), data.end());
        auto enc = Crypto::aes_gcm_enc(pt, mast_key);
        if (!enc.empty()) {
            FileUtil::write_all(idx_path(), enc.data(), enc.size());
        }
    }
    
    bool user_exists(const string& u_hash) {
        auto users = load_idx();
        return find(users.begin(), users.end(), u_hash) != users.end();
    }
    
    void cleanup_modules() {
        if (key_mgr) {
            key_mgr->saveKeys();
        }
        
        unit_enc.reset();
        univ_ciph.reset();
        share_mgr.reset();
        id_mgr.reset();
        key_mgr.reset();
        
        modules_init = false;
    }
    
    void init_modules() {
        if (modules_init) {
            cleanup_modules();
        }
        
        key_mgr = make_unique<KeyManager>();
        share_mgr = make_unique<ShareManager>();
        univ_ciph = make_unique<UniversalCipher>();
        unit_enc = make_unique<UnitEncryptor>();
        id_mgr = make_unique<DiliID>();
        
        key_mgr->setUserPasswordSecure(mast_pwd);
        key_mgr->setUsername(cur_user);
        univ_ciph->setKeyManager(key_mgr.get());
        unit_enc->setKeyManager(key_mgr.get());
        
        if (share_mgr) {
            share_mgr->setUsername(cur_user);
        }
        
        UserRec rec = load_user(cur_user_hash, cur_user, mast_pwd);
        if (rec.has_id && !rec.id_pub_key.empty()) {
            id_mgr->loadFromPubKey(rec.id_pub_key);
            share_mgr->setIdentity(rec.id_pub_key, std::vector<uint8_t>(), rec.id_fprint);
        }
        
        modules_init = true;
    }
    
    UserRec load_user(const string& u_hash, const string& username, const Botan::secure_vector<uint8_t>& pass) {
        UserRec rec;
        string path = user_path(u_hash);
        if (!FileUtil::exists(path)) return rec;
        
        auto sys_key = Crypto::get_system_key(username);
        auto enc = FileUtil::read_all(path);
        
        auto dec = Crypto::aes_gcm_dec(enc, pass, sys_key);
        if (dec.empty()) return rec;
        
        string data(dec.begin(), dec.end());
        rec.deserialize(data);
        return rec;
    }
    
    bool save_user(const string& username, const UserRec& rec) {
        string data = rec.serialize();
        Botan::secure_vector<uint8_t> pt(data.begin(), data.end());
        
        auto sys_key = Crypto::get_system_key(username);
        
        auto enc = Crypto::aes_gcm_enc(pt, mast_pwd, sys_key);
        if (enc.empty()) return false;
        
        string path = user_path(rec.name_hash);
        return FileUtil::write_all(path, enc.data(), enc.size());
    }
    //logo xd 
    void print_banner() {
    cout << BRIGHT_BLUE;
    cout << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
    cout << "│" << BRIGHT_GREEN << "  ██████╗ ██╗   ██╗██████╗ ██╗      ██████╗   " << BRIGHT_BLUE << "                       │\n";
    cout << "│" << BRIGHT_GREEN << "  ██╔══██╗██║   ██║██╔══██╗██║      ██╔════╝   " << BRIGHT_BLUE << "                      │\n";
    cout << "│" << BRIGHT_GREEN << "  ██████╔╝██║   ██║██████╔╝██║████╗ ██║        " << BRIGHT_BLUE << "                      │\n";
    cout << "│" << BRIGHT_GREEN << "  ██╔══██╗██║   ██║██╔══██╗██║╚═══╝ ██║        " << BRIGHT_BLUE << "                      │\n";
    cout << "│" << BRIGHT_GREEN << "  ██║  ██║╚██████╔╝██████╔╝██║      ╚██████╗   " << BRIGHT_BLUE << "                      │\n";
    cout << "│" << BRIGHT_GREEN << "  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝       ╚═════╝   " << BRIGHT_BLUE << "                      │\n";
    cout << "│                                                                     │\n";
    cout << "│" << BRIGHT_MAGENTA << "        SISTEMA DE CIFRADO- v1.0             " << BRIGHT_BLUE << "                        │\n";
    cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
}
    
    string getInput(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }
    
    void show_user_info() {
        auto rec = load_user(cur_user_hash, cur_user, mast_pwd);
        if (rec.name_hash.empty()) {
            cout << RED << "✗ Error: No se pudo cargar la información del usuario" << RESET << endl;
            return;
        }
        
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "INFORMACIÓN DE USUARIO" << BRIGHT_BLUE << "                                        │\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        cout << "│ Usuario: " << BRIGHT_MAGENTA << cur_user << RESET << string(48 - cur_user.length(), ' ') << BRIGHT_BLUE << "│\n";
        cout << "│ Algoritmo: " << BRIGHT_CYAN << rec.algo << RESET << string(46 - rec.algo.length(), ' ') << BRIGHT_BLUE << "│\n";
        
        char buf[30];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", localtime(&rec.created));
        cout << "│ Creado: " << buf << string(48 - strlen(buf), ' ') << BRIGHT_BLUE << "│\n";
        
        cout << "│ Identidad: " << (rec.has_id ? BRIGHT_GREEN "✓ ACTIVA" : BRIGHT_RED "✗ PENDIENTE") << RESET << string(36, ' ') << BRIGHT_BLUE << "│\n";
        
        if (rec.has_id && !rec.id_fprint.empty()) {
            cout << "│ Huella: " << BRIGHT_GREEN << rec.id_fprint << RESET << string(48 - rec.id_fprint.length(), ' ') << BRIGHT_BLUE << "│\n";
        }
        
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }
    
    void chg_pwd() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "CAMBIAR CONTRASEÑA" << BRIGHT_BLUE << "                                           │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        auto current = PwdReader::readPassword("Contraseña actual: ");
        auto rec = load_user(cur_user_hash, cur_user, current);
        
        if (rec.name_hash.empty()) {
            cout << RED << "✗ Contraseña incorrecta o Hardware de sistema inválido" << RESET << endl;
            secure_c_container(current);
            return;
        }
        
        auto new_pass = PwdReader::readWithConfirm();
        if (new_pass.empty()) {
            secure_c_container(current);
            return;
        }
        
        rec.salt = Crypto::rand_bytes(SALT_SIZE);
        rec.pwd_hash = Crypto::argon2(new_pass, rec.salt);
        
        auto old_pass = move(mast_pwd);
        mast_pwd = move(new_pass);
        
        if (save_user(cur_user, rec)) {
            cout << GREEN << "\n✓ Contraseña cambiada" << RESET << endl;
            if (key_mgr) {
                key_mgr->setUserPasswordSecure(mast_pwd);
            }
        } else {
            cout << RED << "\n✗ Error" << RESET << endl;
            mast_pwd = move(old_pass);
        }
        
        secure_c_container(old_pass);
        secure_c_container(current);
    }
    
    void gen_id() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "GENERAR IDENTIDAD DIGITAL" << BRIGHT_BLUE << "                                   │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        cout << MAGENTA << "\nGenerando clave Dilithium-6x5-AES-r3 (PQC)..." << RESET << endl;
        
        DiliID temp_id;
        if (!temp_id.generate()) {
            cout << RED << "✗ Error generando identidad" << RESET << endl;
            return;
        }
        
        auto rec = load_user(cur_user_hash, cur_user, mast_pwd);
        if (rec.name_hash.empty()) {
            cout << RED << "✗ Error cargando usuario" << RESET << endl;
            return;
        }
        
        rec.id_pub_key = temp_id.getPubKey();
        rec.id_fprint = temp_id.getFprint();
        rec.has_id = true;
        
        if (save_user(cur_user, rec)) {
            id_mgr->loadFromPubKey(rec.id_pub_key);
            if (share_mgr) {
                share_mgr->setIdentity(rec.id_pub_key, std::vector<uint8_t>(), rec.id_fprint);
            }
            cout << GREEN << "\n✓ Identidad generada exitosamente" << RESET << endl;
            cout << GREEN << "  Huella: " << BRIGHT_CYAN << rec.id_fprint << RESET << endl;
        } else {
            cout << RED << "\n✗ Error guardando identidad" << RESET << endl;
        }
    }
    
    void cfg_menu() {
        while (true) {
            cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│ " << BRIGHT_GREEN << "CONFIGURACIÓN" << BRIGHT_BLUE << "                                                       │\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            cout << "│ " << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Cambiar contraseña" << BRIGHT_BLUE << "                                              │\n";
            cout << "│ " << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Información de usuario" << BRIGHT_BLUE << "                                          │\n";
            cout << "│ " << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Generar identidad digital" << BRIGHT_BLUE << "                                       │\n";
            cout << "│ " << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " Volver" << BRIGHT_BLUE << "                                                          │\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            string opt = getInput(BRIGHT_GREEN + string("Opción [1-4]: ") + RESET);
            
            if (opt == "1") chg_pwd();
            else if (opt == "2") show_user_info();
            else if (opt == "3") gen_id();
            else if (opt == "4") break;
        }
    }
    
public:
    UserMgr() { 
        ensure_dirs(); 
        try {
            init_master_key();
        } catch (const std::exception& e) {
            std::cerr << "\n" << BRIGHT_RED << "[CRÍTICO] Error al iniciar: " << e.what() << RESET << "\n";
            exit(1);
        }
    }
    
    ~UserMgr() {
        cleanup_modules();
        secure_c_container(mast_pwd);
        secure_c_container(mast_key);
        Memguardin::unlockProcess();
    }
    
    bool authenticate() {
        print_banner();
        
        while (true) {
            cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│ " << BRIGHT_GREEN << "ACCESO AL SISTEMA" << BRIGHT_BLUE <<"                                                   │\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n"; 
            cout << "│" << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Iniciar sesión" << BRIGHT_BLUE << "                                                   │\n";
            cout << "│" << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Crear cuenta" << BRIGHT_BLUE << "                                                     │\n";
            cout << "│" << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Salir" << BRIGHT_BLUE << "                                                            │\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "                                                    \n";
            
            string opt = getInput(BRIGHT_GREEN + string("Opción [1-3]: ") + RESET);
            
            if (opt == "1") {
                if (login()) return true;
            } else if (opt == "2") {
                if (reg_user()) return true;
            } else if (opt == "3") {
                cout << MAGENTA << "\nSaliendo...\n" << RESET;
                cleanup_modules();
                secure_c_container(mast_pwd);
                secure_c_container(mast_key);
                Memguardin::unlockProcess();
                exit(0);
            }
        }
    }
    
    bool login() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "INICIAR SESIÓN" << BRIGHT_BLUE << "                                              │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string user = getInput("Usuario: ");
        string user_hash = hash_user(user);
        
        if (!throttle.can_try(user_hash)) {
            int w = throttle.wait_time(user_hash);
            cout << RED << "✗ Bloqueado. Espere " << w << " segundos." << RESET << endl;
            return false;
        }
        
        if (!user_exists(user_hash)) {
            cout << RED << "✗ Usuario no encontrado" << RESET << endl;
            throttle.rec_fail(user_hash);
            return false;
        }
        
        auto pass = PwdReader::readPassword();
        auto rec = load_user(user_hash, user, pass);
        
        if (rec.name_hash.empty()) {
            cout << RED << "✗ Credenciales o hardware inválidos" << RESET << endl;
            throttle.rec_fail(user_hash);
            secure_c_container(pass);
            return false;
        }
        
        auto computed = Crypto::argon2(pass, rec.salt);
        bool pwd_ok = secure_compare(computed, rec.pwd_hash);
        secure_c_container(computed);
        
        if (!pwd_ok) {
            cout << RED << "✗ Contraseña incorrecta" << RESET << endl;
            throttle.rec_fail(user_hash);
            secure_c_container(pass);
            return false;
        }
        
        throttle.rec_success(user_hash);
        
        rec.last_login = time(nullptr);
        mast_pwd = move(pass);
        save_user(user, rec);
        
        cur_user = user;
        cur_user_hash = user_hash;
        auth = true;
        init_modules();
        
        cout << GREEN << "\n✓ Bienvenido, " << user << RESET << endl;
        return true;
    }
    
    bool reg_user() {
        cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│ " << BRIGHT_GREEN << "CREAR CUENTA" << BRIGHT_BLUE << "                                                │\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        string user = getInput("Usuario: ");
        
        if (user.empty()) {
            cout << RED << "✗ Usuario no puede estar vacío" << RESET << endl;
            return false;
        }
        
        string user_hash = hash_user(user);
        if (user_exists(user_hash)) {
            cout << RED << "✗ Usuario ya existe" << RESET << endl;
            return false;
        }
        
        auto pass = PwdReader::readWithConfirm();
        if (pass.empty()) return false;
        
        cout << MAGENTA << "\nGenerando credenciales con ARGON2 y vinculando al Hardware..." << RESET << endl;
        
        UserRec rec;
        rec.name_hash = user_hash;
        rec.salt = Crypto::rand_bytes(SALT_SIZE);
        rec.pwd_hash = Crypto::argon2(pass, rec.salt);
        
        Botan::secure_vector<uint8_t> name_vec(user.begin(), user.end());
        rec.enc_name = Crypto::aes_gcm_enc(name_vec, pass); 
        
        rec.created = time(nullptr);
        rec.last_login = time(nullptr);
        
        // GENERAR IDENTIDAD 
        cout << MAGENTA << "\nGenerando identidad digital Dilithium-6x5-AES-r3 automáticamente..." << RESET << endl;
        
        DiliID temp_id;
        if (temp_id.generate()) {
            rec.id_pub_key = temp_id.getPubKey();
            rec.id_fprint = temp_id.getFprint();
            rec.has_id = true;
            cout << GREEN << "✓ Identidad digital generada automáticamente" << RESET << endl;
            cout << CYAN << "  Huella: " << BRIGHT_GREEN << rec.id_fprint << RESET << endl;
        } else {
            cout << YELLOW << "⚠ Advertencia: No se pudo generar la identidad digital automáticamente" << RESET << endl;
            cout << YELLOW << "  Puede generarla después desde el menú de configuración" << RESET << endl;
        }
        
        mast_pwd = move(pass);
        
        if (!save_user(user, rec)) {
            cout << RED << "✗ Error guardando usuario" << RESET << endl;
            secure_c_container(mast_pwd);
            return false;
        }
        
        auto users = load_idx();
        users.push_back(user_hash);
        save_idx(users);
        
        cur_user = user;
        cur_user_hash = user_hash;
        auth = true;
        init_modules();
        
        if (rec.has_id) {
            id_mgr->loadFromPubKey(rec.id_pub_key);
            if (share_mgr) {
                share_mgr->setIdentity(rec.id_pub_key, std::vector<uint8_t>(), rec.id_fprint);
            }
        }
        
        cout << GREEN << "\n✓ Cuenta creada exitosamente" << RESET << endl;
        cout << GREEN << "✓ Identidad digital vinculada al sistema" << RESET << endl;
        return true;
    }
    //menu principal
    void main_menu() {
        while (auth) {
            print_banner();
            
            cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            cout << "│ " << BRIGHT_MAGENTA << "MENÚ PRINCIPAL - " << cur_user << string(48 - cur_user.length(), ' ') << BRIGHT_BLUE << " │\n";
            cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            cout << "│" << BRIGHT_CYAN  << "---HERRAMIENTAS DE CIFRADO//                  " << BRIGHT_BLUE << "                       │\n";
            cout << "│" << BRIGHT_GREEN << "[1]" << BRIGHT_MAGENTA << " Cifrar Unidad"      << BRIGHT_BLUE << "                                                    │\n";
            cout << "│" << BRIGHT_GREEN << "[2]" << BRIGHT_MAGENTA << " Cifrador Universal" << BRIGHT_BLUE << "                                               │\n";
            cout << "│" << BRIGHT_CYAN  << "---GESTIÓN DE SEGURIDAD// "                     << BRIGHT_BLUE << "                                           │\n";
            cout << "│" << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " Gestor de Claves"   << BRIGHT_BLUE << "                                                 │\n";
            cout << "│" << BRIGHT_CYAN  << "---COMPARTIR ARCHIVOS//   "                     << BRIGHT_BLUE << "                                           │\n";
            cout << "│" << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " Compartir Archivos" << BRIGHT_BLUE << "                                               │\n";
            cout << "│" << BRIGHT_CYAN  << "---ADMINISTRACIÓN Y SESIÓN//"                   << BRIGHT_BLUE << "                                         │\n";
            cout << "│" << BRIGHT_GREEN << "[5]" << BRIGHT_MAGENTA << " Configuración"      << BRIGHT_BLUE << "                                                    │\n";
            cout << "│" << BRIGHT_GREEN << "[6]" << BRIGHT_MAGENTA << " Cerrar Sesión"      << BRIGHT_BLUE << "                                                    │\n";
            cout << "│" << BRIGHT_GREEN << "[0]" << BRIGHT_MAGENTA << " Salir del Sistema"  << BRIGHT_BLUE << "                                                │\n";
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "    \n";
            
            string opt = getInput(BRIGHT_GREEN + string("Opción [0-6]: ") + RESET);
            
            if (opt == "1") {
                if (unit_enc) unit_enc->showMenu();
            } else if (opt == "2") {
                if (univ_ciph) univ_ciph->showMenu();
            } else if (opt == "3") {
                if (key_mgr) key_mgr->showMenu();
            } else if (opt == "4") {
                if (share_mgr) share_mgr->showMenu();
            } else if (opt == "5") {
                cfg_menu();
            } else if (opt == "6") {
                cout << MAGENTA << "\nCerrando sesión..." << RESET << endl;
                cleanup_modules();
                secure_c_container(mast_pwd);
                auth = false;
                cur_user.clear();
                cur_user_hash.clear();
                break;
            } else if (opt == "0") {
                cout << MAGENTA << "\nSaliendo...\n" << RESET;
                cleanup_modules();
                secure_c_container(mast_pwd);
                secure_c_container(mast_key);
                Memguardin::unlockProcess();
                exit(0);
            }
        }
    }
    
    void run() {
        while (true) {
            if (authenticate()) {
                main_menu();
            }
        }
    }
};

#endif
