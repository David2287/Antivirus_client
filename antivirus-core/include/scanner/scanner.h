//
// Created by WhySkyDie on 21.07.2025.
//

#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <filesystem>

namespace FileScanner {

    // Типы хэш-алгоритмов
    enum class HashType {
        MD5,
        SHA1,
        SHA256,
        CRC32,
        XXHASH64
    };

    // Результат сканирования файла
    struct ScanResult {
        std::filesystem::path file_path;
        std::uintmax_t file_size;
        std::filesystem::file_time_type last_modified;
        std::string hash_value;
        HashType hash_type;
        bool is_suspicious;
        std::vector<std::string> matched_signatures;
        std::string mime_type;
        double scan_time_ms;

        ScanResult() : file_size(0), is_suspicious(false), scan_time_ms(0.0) {}
    };

    // Конфигурация сканера
    struct ScanConfig {
        std::vector<std::string> target_paths;
        std::vector<std::string> exclude_paths;
        std::vector<std::string> file_extensions;
        std::vector<std::string> exclude_extensions;

        HashType hash_algorithm = HashType::SHA256;
        bool recursive = true;
        bool follow_symlinks = false;
        bool scan_hidden = false;
        bool calculate_hash = true;
        bool signature_check = true;

        std::uintmax_t max_file_size = 100 * 1024 * 1024; // 100MB
        std::uintmax_t min_file_size = 0;

        int max_threads = std::thread::hardware_concurrency();
        int max_queue_size = 1000;

        std::chrono::milliseconds scan_timeout{30000}; // 30 seconds

        ScanConfig() {
            if (max_threads == 0) max_threads = 4;
        }
    };

    // Статистика сканирования
    struct ScanStatistics {
        std::atomic<std::uintmax_t> total_files{0};
        std::atomic<std::uintmax_t> scanned_files{0};
        std::atomic<std::uintmax_t> skipped_files{0};
        std::atomic<std::uintmax_t> error_files{0};
        std::atomic<std::uintmax_t> suspicious_files{0};
        std::atomic<std::uintmax_t> total_bytes{0};
        std::atomic<double> total_scan_time{0.0};

        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;

        void Reset() {
            total_files = 0;
            scanned_files = 0;
            skipped_files = 0;
            error_files = 0;
            suspicious_files = 0;
            total_bytes = 0;
            total_scan_time = 0.0;
        }

        double GetElapsedSeconds() const {
            auto end = (end_time == std::chrono::steady_clock::time_point{}) ?
                      std::chrono::steady_clock::now() : end_time;
            return std::chrono::duration<double>(end - start_time).count();
        }
    };

    // Callback типы
    using ScanProgressCallback = std::function<void(const std::string& current_path,
                                                   const ScanStatistics& stats)>;
    using FileFoundCallback = std::function<void(const ScanResult& result)>;
    using ErrorCallback = std::function<void(const std::string& path,
                                           const std::string& error_message)>;

    // Сигнатура для поиска
    struct FileSignature {
        std::string name;
        std::vector<uint8_t> signature;
        std::size_t offset;
        std::string description;
        int severity_level; // 1-10, где 10 - критично

        FileSignature(const std::string& n, const std::vector<uint8_t>& sig,
                     std::size_t off = 0, const std::string& desc = "", int severity = 5)
            : name(n), signature(sig), offset(off), description(desc), severity_level(severity) {}
    };

    // Основной класс сканера
    class DirectoryScanner {
    public:
        DirectoryScanner();
        explicit DirectoryScanner(const ScanConfig& config);
        ~DirectoryScanner();

        // Конфигурация
        void SetConfig(const ScanConfig& config);
        const ScanConfig& GetConfig() const;

        // Callbacks
        void SetProgressCallback(ScanProgressCallback callback);
        void SetFileFoundCallback(FileFoundCallback callback);
        void SetErrorCallback(ErrorCallback callback);

        // Управление сигнатурами
        void AddSignature(const FileSignature& signature);
        void LoadSignaturesFromFile(const std::string& file_path);
        void LoadDefaultSignatures();
        void ClearSignatures();
        std::size_t GetSignatureCount() const;

        // Хэш-фильтры
        void AddHashFilter(const std::string& hash_value, HashType type = HashType::SHA256);
        void LoadHashFiltersFromFile(const std::string& file_path);
        void ClearHashFilters();
        std::size_t GetHashFilterCount() const;

        // Сканирование
        bool StartScan();
        void StopScan();
        bool IsScanning() const;

        // Синхронное сканирование одного файла
        ScanResult ScanFile(const std::filesystem::path& file_path);

        // Статистика
        const ScanStatistics& GetStatistics() const;
        void ResetStatistics();

        // Утилиты
        static std::string CalculateFileHash(const std::filesystem::path& file_path,
                                           HashType hash_type);
        static std::string GetMimeType(const std::filesystem::path& file_path);
        static bool MatchesSignature(const std::filesystem::path& file_path,
                                   const FileSignature& signature);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        std::string HashTypeToString(HashType type);
        HashType StringToHashType(const std::string& type_str);

        std::vector<uint8_t> HexStringToBytes(const std::string& hex_str);
        std::string BytesToHexString(const std::vector<uint8_t>& bytes);

        bool IsValidPath(const std::filesystem::path& path);
        bool ShouldSkipFile(const std::filesystem::path& file_path, const ScanConfig& config);

        std::string FormatFileSize(std::uintmax_t size);
        std::string FormatDuration(double seconds);
    }
}