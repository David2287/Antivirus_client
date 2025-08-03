//
// Created by WhySkyDie on 21.07.2025.
//

#include "scanner.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <xxhash64.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <future>
#include <zlib.h>

#ifdef _WIN32
    #include <windows.h>
    #include <shlwapi.h>
    #pragma comment(lib, "shlwapi.lib")
#else
    #include <magic.h>
#endif

struct ScanResult {
    std::string file_path;
    bool is_infected;
};



namespace FileScanner {

    // Реализация DirectoryScanner::Impl
    class DirectoryScanner::Impl {
    public:
        ScanConfig config;
        std::vector<FileSignature> signatures;
        std::unordered_set<std::string> hash_filters;

        // Threading
        std::vector<std::thread> worker_threads;
        std::queue<std::filesystem::path> scan_queue;
        std::mutex queue_mutex;
        std::condition_variable queue_cv;
        std::atomic<bool> should_stop{false};
        std::atomic<bool> is_scanning{false};

        // Callbacks
        ScanProgressCallback progress_callback;
        FileFoundCallback file_found_callback;
        ErrorCallback error_callback;

        // Statistics
        ScanStatistics statistics;
        mutable std::mutex stats_mutex;

        Impl() = default;
        ~Impl() {
            StopScanning();
        }

        void StopScanning() {
            should_stop = true;
            queue_cv.notify_all();

            for (auto& thread : worker_threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            worker_threads.clear();
            is_scanning = false;
        }

        void WorkerThread() {
            while (!should_stop) {
                std::filesystem::path file_path;

                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    queue_cv.wait(lock, [this] {
                        return should_stop || !scan_queue.empty();
                    });

                    if (should_stop) break;

                    if (!scan_queue.empty()) {
                        file_path = scan_queue.front();
                        scan_queue.pop();
                    } else {
                        continue;
                    }
                }

                ProcessFile(file_path);
            }
        }

        void ProcessFile(const std::filesystem::path& file_path) {
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                ScanResult result;
                result.file_path = file_path;
                result.hash_type = config.hash_algorithm;

                // Получение информации о файле
                if (!std::filesystem::exists(file_path)) {
                    statistics.error_files++;
                    if (error_callback) {
                        error_callback(file_path.string(), "File does not exist");
                    }
                    return;
                }

                std::error_code ec;
                result.file_size = std::filesystem::file_size(file_path, ec);
                if (ec) {
                    statistics.error_files++;
                    if (error_callback) {
                        error_callback(file_path.string(), "Cannot get file size: " + ec.message());
                    }
                    return;
                }

                result.last_modified = std::filesystem::last_write_time(file_path, ec);

                // Проверка размера файла
                if (result.file_size > config.max_file_size ||
                    result.file_size < config.min_file_size) {
                    statistics.skipped_files++;
                    return;
                }

                // Вычисление хэша
                if (config.calculate_hash) {
                    result.hash_value = CalculateFileHashImpl(file_path, config.hash_algorithm);

                    // Проверка хэш-фильтров
                    if (hash_filters.find(result.hash_value) != hash_filters.end()) {
                        result.is_suspicious = true;
                    }
                }

                // Определение MIME типа
                result.mime_type = GetMimeTypeImpl(file_path);

                // Проверка сигнатур
                if (config.signature_check) {
                    CheckSignatures(file_path, result);
                }

                auto end_time = std::chrono::high_resolution_clock::now();
                result.scan_time_ms = std::chrono::duration<double, std::milli>(
                    end_time - start_time).count();

                // Обновление статистики
                statistics.scanned_files++;
                statistics.total_bytes += result.file_size;
                statistics.total_scan_time += result.scan_time_ms;

                if (result.is_suspicious) {
                    statistics.suspicious_files++;
                }

                // Callback
                if (file_found_callback) {
                    file_found_callback(result);
                }

                // Progress callback
                if (progress_callback) {
                    progress_callback(file_path.string(), statistics);
                }

            } catch (const std::exception& e) {
                statistics.error_files++;
                if (error_callback) {
                    error_callback(file_path.string(), e.what());
                }
            }
        }

        void CheckSignatures(const std::filesystem::path& file_path, ScanResult& result) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                return;
            }

            // Читаем первые несколько KB для проверки сигнатур
            const std::size_t buffer_size = 8192;
            std::vector<uint8_t> buffer(buffer_size);
            file.read(reinterpret_cast<char*>(buffer.data()), buffer_size);
            std::size_t bytes_read = file.gcount();

            for (const auto& signature : signatures) {
                if (signature.offset + signature.signature.size() <= bytes_read) {
                    bool matches = std::equal(
                        signature.signature.begin(),
                        signature.signature.end(),
                        buffer.begin() + signature.offset
                    );

                    if (matches) {
                        result.matched_signatures.push_back(signature.name);
                        if (signature.severity_level >= 7) {
                            result.is_suspicious = true;
                        }
                    }
                }
            }
        }

        std::string CalculateFileHashImpl(const std::filesystem::path& file_path,
                                        HashType hash_type) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file for hashing");
            }

            switch (hash_type) {
                case HashType::MD5:
                    return CalculateMD5(file);
                case HashType::SHA1:
                    return CalculateSHA1(file);
                case HashType::SHA256:
                    return CalculateSHA256(file);
                case HashType::CRC32:
                    return CalculateCRC32(file);
                case HashType::XXHASH64:
                    return CalculateXXHash64(file);
                default:
                    throw std::runtime_error("Unsupported hash type");
            }
        }

        std::string CalculateMD5(std::ifstream& file) {
            MD5_CTX ctx;
            MD5_Init(&ctx);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer))) {
                MD5_Update(&ctx, buffer, file.gcount());
            }
            MD5_Update(&ctx, buffer, file.gcount());

            unsigned char hash[MD5_DIGEST_LENGTH];
            MD5_Final(hash, &ctx);

            std::stringstream ss;
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string CalculateSHA1(std::ifstream& file) {
            SHA_CTX ctx;
            SHA1_Init(&ctx);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer))) {
                SHA1_Update(&ctx, buffer, file.gcount());
            }
            SHA1_Update(&ctx, buffer, file.gcount());

            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA1_Final(hash, &ctx);

            std::stringstream ss;
            for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string CalculateSHA256(std::ifstream& file) {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer))) {
                SHA256_Update(&ctx, buffer, file.gcount());
            }
            SHA256_Update(&ctx, buffer, file.gcount());

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_Final(hash, &ctx);

            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string CalculateCRC32(std::ifstream& file) {
            uLong crc = crc32(0L, Z_NULL, 0);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer))) {
                crc = crc32(crc, reinterpret_cast<const Bytef*>(buffer), file.gcount());
            }
            crc = crc32(crc, reinterpret_cast<const Bytef*>(buffer), file.gcount());

            std::stringstream ss;
            ss << std::hex << crc;
            return ss.str();
        }

        std::string CalculateXXHash64(std::ifstream& file) {
            XXH64_state_t* state = XXH64_createState();
            XXH64_reset(state, 0);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer))) {
                XXH64_update(state, buffer, file.gcount());
            }
            XXH64_update(state, buffer, file.gcount());

            XXH64_hash_t hash = XXH64_digest(state);
            XXH64_freeState(state);

            std::stringstream ss;
            ss << std::hex << hash;
            return ss.str();
        }

        std::string GetMimeTypeImpl(const std::filesystem::path& file_path) {
#ifdef _WIN32
            // Windows implementation using registry
            std::string ext = file_path.extension().string();
            if (ext.empty()) return "application/octet-stream";

            HKEY hKey;
            std::string reg_path = ext;
            if (RegOpenKeyExA(HKEY_CLASSES_ROOT, reg_path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char mime_type[256];
                DWORD size = sizeof(mime_type);
                if (RegQueryValueExA(hKey, "Content Type", NULL, NULL,
                                   reinterpret_cast<LPBYTE>(mime_type), &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return std::string(mime_type);
                }
                RegCloseKey(hKey);
            }
            return "application/octet-stream";
#else
            // Linux implementation using libmagic
            magic_t magic = magic_open(MAGIC_MIME_TYPE);
            if (magic == NULL) {
                return "application/octet-stream";
            }

            if (magic_load(magic, NULL) != 0) {
                magic_close(magic);
                return "application/octet-stream";
            }

            const char* mime_type = magic_file(magic, file_path.c_str());
            std::string result = mime_type ? mime_type : "application/octet-stream";
            magic_close(magic);
            return result;
#endif
        }
    };

    // Реализация DirectoryScanner
    DirectoryScanner::DirectoryScanner() : pImpl(std::make_unique<Impl>()) {
        LoadDefaultSignatures();
    }

    DirectoryScanner::DirectoryScanner(const ScanConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
        LoadDefaultSignatures();
    }

    DirectoryScanner::~DirectoryScanner() = default;

    void DirectoryScanner::SetConfig(const ScanConfig& config) {
        pImpl->config = config;
    }

    const ScanConfig& DirectoryScanner::GetConfig() const {
        return pImpl->config;
    }

    void DirectoryScanner::SetProgressCallback(ScanProgressCallback callback) {
        pImpl->progress_callback = std::move(callback);
    }

    void DirectoryScanner::SetFileFoundCallback(FileFoundCallback callback) {
        pImpl->file_found_callback = std::move(callback);
    }

    void DirectoryScanner::SetErrorCallback(ErrorCallback callback) {
        pImpl->error_callback = std::move(callback);
    }

    void DirectoryScanner::AddSignature(const FileSignature& signature) {
        pImpl->signatures.push_back(signature);
    }

    void DirectoryScanner::LoadSignaturesFromFile(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open signatures file: " + file_path);
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            // Формат: name|hex_signature|offset|description|severity
            std::istringstream ss(line);
            std::string name, hex_sig, offset_str, description, severity_str;

            if (std::getline(ss, name, '|') &&
                std::getline(ss, hex_sig, '|') &&
                std::getline(ss, offset_str, '|') &&
                std::getline(ss, description, '|') &&
                std::getline(ss, severity_str)) {

                auto signature_bytes = Utils::HexStringToBytes(hex_sig);
                std::size_t offset = std::stoull(offset_str);
                int severity = std::stoi(severity_str);

                AddSignature(FileSignature(name, signature_bytes, offset, description, severity));
            }
        }
    }

    void DirectoryScanner::LoadDefaultSignatures() {
        // PE executable
        AddSignature(FileSignature("PE32", {0x4D, 0x5A}, 0, "PE32 Executable", 3));

        // ELF executable
        AddSignature(FileSignature("ELF", {0x7F, 0x45, 0x4C, 0x46}, 0, "ELF Executable", 3));

        // PDF
        AddSignature(FileSignature("PDF", {0x25, 0x50, 0x44, 0x46}, 0, "PDF Document", 1));

        // ZIP
        AddSignature(FileSignature("ZIP", {0x50, 0x4B, 0x03, 0x04}, 0, "ZIP Archive", 2));

        // RAR
        AddSignature(FileSignature("RAR", {0x52, 0x61, 0x72, 0x21}, 0, "RAR Archive", 2));

        // JPEG
        AddSignature(FileSignature("JPEG", {0xFF, 0xD8, 0xFF}, 0, "JPEG Image", 1));

        // PNG
        AddSignature(FileSignature("PNG", {0x89, 0x50, 0x4E, 0x47}, 0, "PNG Image", 1));

        // Suspicious signatures (примеры)
        AddSignature(FileSignature("SUSPICIOUS_SCRIPT", {0x3C, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74}, 0, "Script tag", 8));
    }

    void DirectoryScanner::ClearSignatures() {
        pImpl->signatures.clear();
    }

    std::size_t DirectoryScanner::GetSignatureCount() const {
        return pImpl->signatures.size();
    }

    void DirectoryScanner::AddHashFilter(const std::string& hash_value, HashType type) {
        pImpl->hash_filters.insert(hash_value);
    }

    void DirectoryScanner::LoadHashFiltersFromFile(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open hash filters file: " + file_path);
        }

        std::string hash;
        while (std::getline(file, hash)) {
            if (!hash.empty() && hash[0] != '#') {
                pImpl->hash_filters.insert(hash);
            }
        }
    }

    void DirectoryScanner::ClearHashFilters() {
        pImpl->hash_filters.clear();
    }

    std::size_t DirectoryScanner::GetHashFilterCount() const {
        return pImpl->hash_filters.size();
    }

    bool DirectoryScanner::StartScan() {
        if (pImpl->is_scanning) {
            return false;
        }

        pImpl->should_stop = false;
        pImpl->is_scanning = true;
        pImpl->statistics.Reset();
        pImpl->statistics.start_time = std::chrono::steady_clock::now();

        // Запуск рабочих потоков
        for (int i = 0; i < pImpl->config.max_threads; ++i) {
            pImpl->worker_threads.emplace_back(&DirectoryScanner::Impl::WorkerThread, pImpl.get());
        }

        // Запуск сканирования в отдельном потоке
        std::thread scan_thread([this]() {
            try {
                for (const auto& target_path : pImpl->config.target_paths) {
                    std::filesystem::path path(target_path);
                    if (!std::filesystem::exists(path)) {
                        continue;
                    }

                    if (std::filesystem::is_regular_file(path)) {
                        // Сканирование одного файла
                        {
                            std::lock_guard<std::mutex> lock(pImpl->queue_mutex);
                            if (pImpl->scan_queue.size() < pImpl->config.max_queue_size) {
                                pImpl->scan_queue.push(path);
                                pImpl->statistics.total_files++;
                            }
                        }
                        pImpl->queue_cv.notify_one();
                    } else if (std::filesystem::is_directory(path)) {
                        // Рекурсивное сканирование каталога
                        ScanDirectory(path);
                    }
                }

                // Ожидание завершения обработки всех файлов
                while (true) {
                    {
                        std::lock_guard<std::mutex> lock(pImpl->queue_mutex);
                        if (pImpl->scan_queue.empty()) {
                            break;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                pImpl->statistics.end_time = std::chrono::steady_clock::now();
                pImpl->StopScanning();

            } catch (const std::exception& e) {
                if (pImpl->error_callback) {
                    pImpl->error_callback("", "Scan error: " + std::string(e.what()));
                }
                pImpl->StopScanning();
            }
        });

        scan_thread.detach();
        return true;
    }

    std::string hash_file(const std::string& path, const std::string& algorithm) {
        // MD5 или SHA256
        if (algorithm == "MD5") {
            unsigned char digest[MD5_DIGEST_LENGTH];
            char buf[4096];
            MD5_CTX ctx;
            MD5_Init(&ctx);

            std::ifstream file(path, std::ifstream::binary);
            if (!file) throw std::runtime_error("Cannot open file");

            while (file.read(buf, sizeof(buf)))
                MD5_Update(&ctx, buf, file.gcount());

            MD5_Final(digest, &ctx);
            char mdString[33];
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
                sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);

            return std::string(mdString);
        } else if (algorithm == "SHA256") {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);

            std::ifstream file(path, std::ifstream::binary);
            if (!file) throw std::runtime_error("Cannot open file");

            char buf[4096];
            while (file.read(buf, sizeof(buf)))
                SHA256_Update(&sha256, buf, file.gcount());

            SHA256_Final(hash, &sha256);
            char out[65];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                sprintf(&out[i * 2], "%02x", hash[i]);
            return std::string(out);
        } else {
            throw std::invalid_argument("Unsupported hash algorithm");
        }
    }

    bool is_file_infected(const std::string& file_path) {
        std::string file_hash = hash_file(file_path, "MD5");

        //TODO: Подключить signatures.cpp для проверки
        static const std::vector<std::string> known_hashes = {
            "known_infected_hash"
        };

        return std::find(known_hashes.begin(), known_hashes.end(), file_hash) != known_hashes.end();
    }

    std::vector<ScanResult> scan_directory(const std::string& path) {
        std::vector<ScanResult> results;

        for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                const std::string file_path = entry.path().string();
                try {
                    results.push_back({
                        file_path,
                        is_file_infected(file_path)
                    });
                } catch (...) {
                    continue; // ошибки пропускаем
                }
            }
        }
        return results;
    }

    void DirectoryScanner::StopScan() {
        pImpl->StopScanning();
    }

    bool DirectoryScanner::IsScanning() const {
        return pImpl->is_scanning;
    }

    ScanResult DirectoryScanner::ScanFile(const std::filesystem::path& file_path) {
        ScanResult result;
        pImpl->ProcessFile(file_path);
        return result;
    }

    const ScanStatistics& DirectoryScanner::GetStatistics() const {
        return pImpl->statistics;
    }

    void DirectoryScanner::ResetStatistics() {
        pImpl->statistics.Reset();
    }

    std::string DirectoryScanner::CalculateFileHash(const std::filesystem::path& file_path,
                                                   HashType hash_type) {
        DirectoryScanner::Impl impl;
        return impl.CalculateFileHashImpl(file_path, hash_type);
    }

    std::string DirectoryScanner::GetMimeType(const std::filesystem::path& file_path) {
        DirectoryScanner::Impl impl;
        return impl.GetMimeTypeImpl(file_path);
    }

    bool DirectoryScanner::MatchesSignature(const std::filesystem::path& file_path,
                                           const FileSignature& signature) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        file.seekg(signature.offset);
        std::vector<uint8_t> buffer(signature.signature.size());
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        return file.gcount() == static_cast<std::streamsize>(signature.signature.size()) &&
               std::equal(signature.signature.begin(), signature.signature.end(), buffer.begin());
    }

    void DirectoryScanner::ScanDirectory(const std::filesystem::path& dir_path) {
        std::error_code ec;

        if (pImpl->config.recursive) {
            auto iterator = pImpl->config.follow_symlinks ?
                std::filesystem::recursive_directory_iterator(dir_path, ec) :
                std::filesystem::recursive_directory_iterator(
                    dir_path, std::filesystem::directory_options::skip_symlinks, ec);

            for (const auto& entry : iterator) {
                if (pImpl->should_stop) break;

                if (entry.is_regular_file(ec) && !ec) {
                    if (!Utils::ShouldSkipFile(entry.path(), pImpl->config)) {
                        {
                            std::lock_guard<std::mutex> lock(pImpl->queue_mutex);
                            if (pImpl->scan_queue.size() < pImpl->config.max_queue_size) {
                                pImpl->scan_queue.push(entry.path());
                                pImpl->statistics.total_files++;
                            }
                        }
                        pImpl->queue_cv.notify_one();
                    }
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
                if (pImpl->should_stop) break;

                if (entry.is_regular_file(ec) && !ec) {
                    if (!Utils::ShouldSkipFile(entry.path(), pImpl->config)) {
                        {
                            std::lock_guard<std::mutex> lock(pImpl->queue_mutex);
                            if (pImpl->scan_queue.size() < pImpl->config.max_queue_size) {
                                pImpl->scan_queue.push(entry.path());
                                pImpl->statistics.total_files++;
                            }
                        }
                        pImpl->queue_cv.notify_one();
                    }
                }
            }
        }
    }

    // Реализация утилитарных функций
    namespace Utils {

        std::string HashTypeToString(HashType type) {
            switch (type) {
                case HashType::MD5: return "MD5";
                case HashType::SHA1: return "SHA1";
                case HashType::SHA256: return "SHA256";
                case HashType::CRC32: return "CRC32";
                case HashType::XXHASH64: return "XXHASH64";
                default: return "UNKNOWN";
            }
        }

        HashType StringToHashType(const std::string& type_str) {
            if (type_str == "MD5") return HashType::MD5;
            if (type_str == "SHA1") return HashType::SHA1;
            if (type_str == "SHA256") return HashType::SHA256;
            if (type_str == "CRC32") return HashType::CRC32;
            if (type_str == "XXHASH64") return HashType::XXHASH64;
            return HashType::SHA256; // default
        }

        std::vector<uint8_t> HexStringToBytes(const std::string& hex_str) {
            std::vector<uint8_t> bytes;
            for (std::size_t i = 0; i < hex_str.length(); i += 2) {
                std::string byte_str = hex_str.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        }

        std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
            std::stringstream ss;
            for (auto byte : bytes) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            return ss.str();
        }

        bool IsValidPath(const std::filesystem::path& path) {
            std::error_code ec;
            return std::filesystem::exists(path, ec) && !ec;
        }

        bool ShouldSkipFile(const std::filesystem::path& file_path, const ScanConfig& config) {
            std::string file_str = file_path.string();
            std::string ext = file_path.extension().string();

            // Проверка скрытых файлов
            if (!config.scan_hidden && file_path.filename().string()[0] == '.') {
                return true;
            }

            // Проверка исключенных путей
            for (const auto& exclude_path : config.exclude_paths) {
                if (file_str.find(exclude_path) != std::string::npos) {
                    return true;
                }
            }

            // Проверка расширений файлов
            if (!config.file_extensions.empty()) {
                auto it = std::find(config.file_extensions.begin(),
                                  config.file_extensions.end(), ext);
                if (it == config.file_extensions.end()) {
                    return true;
                }
            }

            // Проверка исключенных расширений
            if (!config.exclude_extensions.empty()) {
                auto it = std::find(config.exclude_extensions.begin(),
                                  config.exclude_extensions.end(), ext);
                if (it != config.exclude_extensions.end()) {
                    return true;
                }
            }

            return false;
        }

        std::string FormatFileSize(std::uintmax_t size) {
            const char* units[] = {"B", "KB", "MB", "GB", "TB"};
            int unit_index = 0;
            double size_d = static_cast<double>(size);

            while (size_d >= 1024.0 && unit_index < 4) {
                size_d /= 1024.0;
                unit_index++;
            }

            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << size_d << " " << units[unit_index];
            return ss.str();
        }

        std::string FormatDuration(double seconds) {
            if (seconds < 60) {
                return std::to_string(static_cast<int>(seconds)) + "s";
            } else if (seconds < 3600) {
                int minutes = static_cast<int>(seconds / 60);
                int secs = static_cast<int>(seconds) % 60;
                return std::to_string(minutes) + "m " + std::to_string(secs) + "s";
            } else {
                int hours = static_cast<int>(seconds / 3600);
                int minutes = static_cast<int>((seconds - hours * 3600) / 60);
                return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
            }
        }
    }
}