//
// Created by WhySkyDie on 21.07.2025.
//

#ifndef QUARANTINE_H
#define QUARANTINE_H

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <optional>

namespace QuarantineEngine {

    // Типы операций карантина
    enum class QuarantineAction {
        MOVE,
        COPY,
        ENCRYPT,
        COMPRESS,
        ENCRYPT_AND_COMPRESS
    };

    // Статус файла в карантине
    enum class QuarantineStatus {
        PENDING,
        QUARANTINED,
        RESTORED,
        PERMANENTLY_DELETED,
        FAILED
    };

    // Причины помещения в карантин
    enum class QuarantineReason {
        MALWARE_DETECTED,
        SUSPICIOUS_BEHAVIOR,
        SIGNATURE_MATCH,
        HASH_MATCH,
        USER_REQUEST,
        POLICY_VIOLATION,
        UNKNOWN_FILE_TYPE,
        HIGH_ENTROPY
    };

    // Алгоритмы шифрования
    enum class EncryptionAlgorithm {
        AES_256_CBC,
        AES_256_GCM,
        CHACHA20_POLY1305,
        XOR_SIMPLE
    };

    // Алгоритмы сжатия
    enum class CompressionAlgorithm {
        ZLIB,
        GZIP,
        BZIP2,
        LZMA,
        LZ4
    };

    // Информация о файле в карантине
    struct QuarantinedFile {
        std::string quarantine_id;
        std::filesystem::path original_path;
        std::filesystem::path quarantine_path;
        std::string original_hash;
        std::string quarantine_hash;
        std::uintmax_t original_size;
        std::uintmax_t quarantine_size;

        QuarantineStatus status;
        QuarantineAction action;
        QuarantineReason reason;

        std::chrono::system_clock::time_point quarantine_time;
        std::chrono::system_clock::time_point expiry_time;

        EncryptionAlgorithm encryption_algorithm;
        CompressionAlgorithm compression_algorithm;

        std::string detection_engine;
        std::string signature_name;
        std::string user_name;
        std::string computer_name;

        std::unordered_map<std::string, std::string> metadata;
        std::vector<std::string> restore_notes;

        QuarantinedFile() : original_size(0), quarantine_size(0),
                           status(QuarantineStatus::PENDING),
                           action(QuarantineAction::MOVE),
                           reason(QuarantineReason::UNKNOWN_FILE_TYPE),
                           encryption_algorithm(EncryptionAlgorithm::AES_256_CBC),
                           compression_algorithm(CompressionAlgorithm::ZLIB) {}
    };

    // Конфигурация карантина
    struct QuarantineConfig {
        std::filesystem::path quarantine_directory;
        std::filesystem::path metadata_directory;
        std::filesystem::path temp_directory;

        std::size_t max_file_size = 1024 * 1024 * 1024; // 1GB
        std::size_t max_quarantine_size = 10ULL * 1024 * 1024 * 1024; // 10GB
        std::chrono::hours default_retention_period{24 * 30}; // 30 дней

        EncryptionAlgorithm default_encryption = EncryptionAlgorithm::AES_256_CBC;
        CompressionAlgorithm default_compression = CompressionAlgorithm::ZLIB;

        bool auto_encrypt = true;
        bool auto_compress = true;
        bool create_backup = true;
        bool secure_delete_original = true;

        std::string encryption_password;
        std::vector<std::string> authorized_users;

        int compression_level = 6; // 1-9
        int max_threads = 4;

        QuarantineConfig() {
            quarantine_directory = std::filesystem::temp_directory_path() / "quarantine";
            metadata_directory = quarantine_directory / "metadata";
            temp_directory = quarantine_directory / "temp";
        }
    };

    // Статистика карантина
    struct QuarantineStatistics {
        std::atomic<std::size_t> total_files{0};
        std::atomic<std::size_t> active_files{0};
        std::atomic<std::size_t> restored_files{0};
        std::atomic<std::size_t> deleted_files{0};
        std::atomic<std::size_t> failed_operations{0};

        std::atomic<std::uintmax_t> total_size{0};
        std::atomic<std::uintmax_t> compressed_size{0};
        std::atomic<double> compression_ratio{0.0};

        std::chrono::system_clock::time_point last_quarantine_time;
        std::chrono::system_clock::time_point last_restore_time;

        std::unordered_map<QuarantineReason, std::size_t> reason_counts;
        std::unordered_map<std::string, std::size_t> detection_engine_counts;
    };

    // Результат операции карантина
    struct QuarantineResult {
        bool success;
        std::string quarantine_id;
        std::string error_message;
        std::filesystem::path quarantine_path;
        std::chrono::milliseconds operation_time{0};
        std::uintmax_t bytes_processed{0};
        double compression_ratio{0.0};

        QuarantineResult() : success(false), compression_ratio(0.0) {}
    };

    struct QuarantineItem {
        std::string file_id;
        std::string original_path;
        std::string quarantine_path;
        std::chrono::system_clock::time_point quarantine_time;
        std::string file_hash;
        size_t file_size;
        std::string reason;

        QuarantineItem() = default;
        QuarantineItem(const std::string& id, const std::string& orig_path,
                       const std::string& quar_path, const std::string& hash,
                       size_t size, const std::string& quarantine_reason);
    };

    // Callback типы
    using ProgressCallback = std::function<void(const std::string& operation,
                                               std::size_t current, std::size_t total)>;
    using QuarantineCallback = std::function<void(const QuarantinedFile& file)>;
    using ErrorCallback = std::function<void(const std::string& error_message,
                                           const std::string& file_path)>;

    // Основной класс управления карантином
    class QuarantineManager {
    public:
        QuarantineManager();
        explicit QuarantineManager(const QuarantineConfig& config);
        ~QuarantineManager();

        // Инициализация и конфигурация
        bool Initialize();
        void Shutdown();
        bool IsInitialized() const;

        void SetConfig(const QuarantineConfig& config);
        const QuarantineConfig& GetConfig() const;

        // Callbacks
        void SetProgressCallback(ProgressCallback callback);
        void SetQuarantineCallback(QuarantineCallback callback);
        void SetErrorCallback(ErrorCallback callback);

        // Операции карантина
        QuarantineResult QuarantineFile(const std::filesystem::path& file_path,
                                       QuarantineReason reason,
                                       const std::string& detection_info = "",
                                       QuarantineAction action = QuarantineAction::ENCRYPT_AND_COMPRESS);

        QuarantineResult QuarantineFiles(const std::vector<std::filesystem::path>& file_paths,
                                        QuarantineReason reason,
                                        const std::string& detection_info = "");

        // Восстановление файлов
        bool RestoreFile(const std::string& quarantine_id,
                        const std::filesystem::path& restore_path = "");
        bool RestoreFiles(const std::vector<std::string>& quarantine_ids);

        // Удаление файлов из карантина
        bool DeleteQuarantinedFile(const std::string& quarantine_id, bool secure = true);
        bool DeleteExpiredFiles();
        bool DeleteAllFiles(bool secure = true);

        // Поиск и получение информации
        std::vector<QuarantinedFile> GetQuarantinedFiles() const;
        std::vector<QuarantinedFile> GetFilesByStatus(QuarantineStatus status) const;
        std::vector<QuarantinedFile> GetFilesByReason(QuarantineReason reason) const;
        std::optional<QuarantinedFile> GetFileInfo(const std::string& quarantine_id) const;

        // Поиск по критериям
        std::vector<QuarantinedFile> SearchFiles(const std::string& search_term) const;
        std::vector<QuarantinedFile> GetFilesInDateRange(
            const std::chrono::system_clock::time_point& start,
            const std::chrono::system_clock::time_point& end) const;

        // Экспорт и импорт
        bool ExportQuarantineData(const std::filesystem::path& export_path) const;
        bool ImportQuarantineData(const std::filesystem::path& import_path);

        // Проверка целостности
        bool VerifyQuarantineIntegrity();
        std::vector<std::string> GetCorruptedFiles() const;

        // Статистика
        QuarantineStatistics GetStatistics() const;
        void ResetStatistics();

        // Утилиты
        std::uintmax_t GetQuarantineSize() const;
        std::size_t GetFileCount() const;
        bool CleanupTempFiles();

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    class QuarantineManager {
    private:
        std::filesystem::path quarantine_dir;
        std::filesystem::path metadata_file;
        std::unordered_map<std::string, QuarantineItem> quarantine_items;

        // Вспомогательные методы
        std::string generate_file_id() const;
        bool load_metadata();
        bool save_metadata();
        std::string calculate_file_hash(const std::filesystem::path& path) const;

    public:
        explicit QuarantineManager(const std::filesystem::path& quarantine_directory = "./quarantine");
        ~QuarantineManager();

        // Основные методы с исправленными сигнатурами
        bool quarantine_file(const std::filesystem::path& path);
        bool restore_file(const std::string& file_id);
        bool delete_file(const std::string& file_id);
        std::vector<QuarantineItem> list_quarantine() const;

        // Дополнительные методы
        bool initialize();
        void set_quarantine_reason(const std::string& reason);
        size_t get_quarantine_count() const;
        bool cleanup_quarantine(std::chrono::hours older_than = std::chrono::hours(24 * 30)); // 30 дней по умолчанию

    private:
        std::string current_reason = "Подозрительный файл";
    };

    // Криптографический движок
    class CryptoEngine {
    public:
        CryptoEngine();
        ~CryptoEngine();

        // Шифрование
        std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data,
                                    const std::string& password,
                                    EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES_256_CBC);

        bool EncryptFile(const std::filesystem::path& input_path,
                        const std::filesystem::path& output_path,
                        const std::string& password,
                        EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES_256_CBC);

        // Расшифровка
        std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& encrypted_data,
                                    const std::string& password,
                                    EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES_256_CBC);

        bool DecryptFile(const std::filesystem::path& input_path,
                        const std::filesystem::path& output_path,
                        const std::string& password,
                        EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES_256_CBC);

        // Генерация ключей и паролей
        std::string GeneratePassword(std::size_t length = 32);
        std::vector<uint8_t> GenerateKey(std::size_t length = 32);
        std::vector<uint8_t> GenerateIV(std::size_t length = 16);

        // Хэширование
        std::string CalculateHash(const std::vector<uint8_t>& data, const std::string& algorithm = "SHA256");
        std::string CalculateFileHash(const std::filesystem::path& file_path, const std::string& algorithm = "SHA256");

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Движок сжатия
    class CompressionEngine {
    public:
        CompressionEngine();
        ~CompressionEngine();

        // Сжатие
        std::vector<uint8_t> Compress(const std::vector<uint8_t>& data,
                                     CompressionAlgorithm algorithm = CompressionAlgorithm::ZLIB,
                                     int level = 6);

        bool CompressFile(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         CompressionAlgorithm algorithm = CompressionAlgorithm::ZLIB,
                         int level = 6);

        // Распаковка
        std::vector<uint8_t> Decompress(const std::vector<uint8_t>& compressed_data,
                                       CompressionAlgorithm algorithm = CompressionAlgorithm::ZLIB);

        bool DecompressFile(const std::filesystem::path& input_path,
                           const std::filesystem::path& output_path,
                           CompressionAlgorithm algorithm = CompressionAlgorithm::ZLIB);

        // Информация о сжатии
        double CalculateCompressionRatio(std::uintmax_t original_size, std::uintmax_t compressed_size);
        std::vector<CompressionAlgorithm> GetSupportedAlgorithms() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        std::string QuarantineActionToString(QuarantineAction action);
        QuarantineAction StringToQuarantineAction(const std::string& action_str);

        std::string QuarantineStatusToString(QuarantineStatus status);
        QuarantineStatus StringToQuarantineStatus(const std::string& status_str);

        std::string QuarantineReasonToString(QuarantineReason reason);
        QuarantineReason StringToQuarantineReason(const std::string& reason_str);

        std::string EncryptionAlgorithmToString(EncryptionAlgorithm algorithm);
        EncryptionAlgorithm StringToEncryptionAlgorithm(const std::string& algorithm_str);

        std::string CompressionAlgorithmToString(CompressionAlgorithm algorithm);
        CompressionAlgorithm StringToCompressionAlgorithm(const std::string& algorithm_str);

        std::string GenerateQuarantineId();
        std::string FormatFileSize(std::uintmax_t size);
        std::string FormatDuration(const std::chrono::milliseconds& duration);

        bool SecureDeleteFile(const std::filesystem::path& file_path, int passes = 3);
        std::filesystem::path CreateTempFile(const std::filesystem::path& directory);

        std::string GetCurrentUser();
        std::string GetComputerName();

        bool IsValidQuarantineId(const std::string& quarantine_id);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp);
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& time_point);
    }
}

#endif // QUARANTINE_H