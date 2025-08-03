//
// Created by WhySkyDie on 21.07.2025.
//

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <unordered_map>

namespace FileUtils {

    // Типы файлов
    enum class FileType {
        UNKNOWN,
        TEXT,
        BINARY,
        EXECUTABLE,
        ARCHIVE,
        IMAGE,
        VIDEO,
        AUDIO,
        DOCUMENT,
        SCRIPT
    };

    // Алгоритмы хэширования
    enum class HashAlgorithm {
        MD5,
        SHA1,
        SHA256,
        SHA512,
        CRC32,
        XXHASH64
    };

    // Атрибуты файла
    enum class FileAttribute {
        READONLY = 0x01,
        HIDDEN = 0x02,
        SYSTEM = 0x04,
        ARCHIVE = 0x20,
        NORMAL = 0x80,
        TEMPORARY = 0x100,
        COMPRESSED = 0x800,
        ENCRYPTED = 0x4000
    };

    // Режим доступа к файлу
    enum class AccessMode {
        READ = 0x01,
        WRITE = 0x02,
        EXECUTE = 0x04,
        DELETE = 0x08
    };

    // Информация о файле
    struct FileInfo {
        std::filesystem::path file_path;
        std::uintmax_t size;
        std::filesystem::file_time_type last_write_time;
        std::filesystem::file_time_type last_access_time;
        std::filesystem::file_time_type creation_time;

        FileType file_type;
        std::string mime_type;
        std::string extension;

        bool is_directory;
        bool is_regular_file;
        bool is_symlink;
        bool is_hidden;
        bool is_readonly;
        bool is_executable;

        std::uintmax_t hard_link_count;
        std::filesystem::perms permissions;

        // Хэши файла (вычисляются при необходимости)
        mutable std::unordered_map<HashAlgorithm, std::string> hashes;
        mutable std::mutex hash_mutex;

        FileInfo() : size(0), file_type(FileType::UNKNOWN), is_directory(false),
                    is_regular_file(false), is_symlink(false), is_hidden(false),
                    is_readonly(false), is_executable(false), hard_link_count(0) {}
    };

    // Результат операции чтения файла
    struct ReadResult {
        bool success;
        std::vector<uint8_t> data;
        std::string error_message;
        std::size_t bytes_read;
        std::chrono::milliseconds read_time{0};

        ReadResult() : success(false), bytes_read(0) {}
    };

    // Результат операции записи файла
    struct WriteResult {
        bool success;
        std::string error_message;
        std::size_t bytes_written;
        std::chrono::milliseconds write_time{0};

        WriteResult() : success(false), bytes_written(0) {}
    };

    // Конфигурация для операций с файлами
    struct FileOperationConfig {
        std::size_t buffer_size = 64 * 1024; // 64KB
        std::size_t max_file_size = 1024ULL * 1024 * 1024; // 1GB
        std::chrono::milliseconds operation_timeout{30000}; // 30 секунд

        bool use_memory_mapping = false;
        bool verify_checksums = false;
        bool create_backup = false;
        bool atomic_operations = false;

        std::filesystem::path temp_directory;
        std::filesystem::path backup_directory;

        FileOperationConfig() {
            temp_directory = std::filesystem::temp_directory_path();
            backup_directory = temp_directory / "backups";
        }
    };

    // Callback типы
    using ProgressCallback = std::function<void(std::size_t current, std::size_t total)>;
    using ErrorCallback = std::function<void(const std::string& error_message)>;

    // Основной класс для работы с файлами
    class FileManager {
    public:
        FileManager();
        explicit FileManager(const FileOperationConfig& config);
        ~FileManager();

        // Конфигурация
        void SetConfig(const FileOperationConfig& config);
        const FileOperationConfig& GetConfig() const;

        // Callbacks
        void SetProgressCallback(ProgressCallback callback);
        void SetErrorCallback(ErrorCallback callback);

        // Чтение файлов
        ReadResult ReadFile(const std::filesystem::path& file_path);
        ReadResult ReadFileAsync(const std::filesystem::path& file_path);
        ReadResult ReadFileChunk(const std::filesystem::path& file_path,
                                std::size_t offset, std::size_t size);

        std::string ReadTextFile(const std::filesystem::path& file_path,
                                const std::string& encoding = "utf-8");
        std::vector<std::string> ReadLines(const std::filesystem::path& file_path);

        // Запись файлов
        WriteResult WriteFile(const std::filesystem::path& file_path,
                             const std::vector<uint8_t>& data,
                             bool append = false);
        WriteResult WriteTextFile(const std::filesystem::path& file_path,
                                 const std::string& content,
                                 bool append = false);
        WriteResult WriteLines(const std::filesystem::path& file_path,
                              const std::vector<std::string>& lines);

        // Атомарные операции
        WriteResult WriteFileAtomic(const std::filesystem::path& file_path,
                                   const std::vector<uint8_t>& data);
        bool ReplaceFileAtomic(const std::filesystem::path& source,
                              const std::filesystem::path& target);

        // Информация о файлах
        std::optional<FileInfo> GetFileInfo(const std::filesystem::path& file_path);
        bool FileExists(const std::filesystem::path& file_path);
        bool IsDirectory(const std::filesystem::path& path);
        bool IsRegularFile(const std::filesystem::path& path);
        std::uintmax_t GetFileSize(const std::filesystem::path& file_path);

        // Копирование и перемещение
        bool CopyFile(const std::filesystem::path& source,
                     const std::filesystem::path& destination,
                     bool overwrite = false);
        bool MoveFile(const std::filesystem::path& source,
                     const std::filesystem::path& destination);
        bool DeleteFile(const std::filesystem::path& file_path);
        bool DeleteFileSecure(const std::filesystem::path& file_path, int passes = 3);

        // Права доступа
        bool SetFilePermissions(const std::filesystem::path& file_path,
                               std::filesystem::perms permissions);
        std::filesystem::perms GetFilePermissions(const std::filesystem::path& file_path);
        bool HasAccess(const std::filesystem::path& file_path, AccessMode mode);

        // Атрибуты файла
        bool SetFileAttributes(const std::filesystem::path& file_path, int attributes);
        int GetFileAttributes(const std::filesystem::path& file_path);

        // Временные файлы
        std::filesystem::path CreateTempFile(const std::string& prefix = "tmp_",
                                           const std::string& suffix = ".tmp");
        std::filesystem::path CreateTempDirectory(const std::string& prefix = "tmpdir_");
        bool CleanupTempFiles();

        // Резервное копирование
        std::filesystem::path CreateBackup(const std::filesystem::path& file_path);
        bool RestoreFromBackup(const std::filesystem::path& backup_path,
                              const std::filesystem::path& target_path);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилиты для хэширования
    class HashUtils {
    public:
        HashUtils();
        ~HashUtils();

        // Вычисление хэшей
        std::string CalculateFileHash(const std::filesystem::path& file_path,
                                     HashAlgorithm algorithm = HashAlgorithm::SHA256);
        std::string CalculateDataHash(const std::vector<uint8_t>& data,
                                     HashAlgorithm algorithm = HashAlgorithm::SHA256);
        std::string CalculateStringHash(const std::string& str,
                                       HashAlgorithm algorithm = HashAlgorithm::SHA256);

        // Сравнение файлов по хэшу
        bool CompareFilesByHash(const std::filesystem::path& file1,
                               const std::filesystem::path& file2,
                               HashAlgorithm algorithm = HashAlgorithm::SHA256);

        // Верификация файла
        bool VerifyFileIntegrity(const std::filesystem::path& file_path,
                                const std::string& expected_hash,
                                HashAlgorithm algorithm = HashAlgorithm::SHA256);

        // Множественные хэши
        std::unordered_map<HashAlgorithm, std::string>
            CalculateMultipleHashes(const std::filesystem::path& file_path,
                                   const std::vector<HashAlgorithm>& algorithms);

        // Инкрементальное хэширование
        class IncrementalHasher {
        public:
            explicit IncrementalHasher(HashAlgorithm algorithm);
            ~IncrementalHasher();

            void Update(const std::vector<uint8_t>& data);
            void Update(const void* data, std::size_t size);
            std::string Finalize();
            void Reset();

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилиты для путей
    class PathUtils {
    public:
        // Нормализация путей
        static std::filesystem::path NormalizePath(const std::filesystem::path& path);
        static std::filesystem::path GetAbsolutePath(const std::filesystem::path& path);
        static std::filesystem::path GetRelativePath(const std::filesystem::path& base,
                                                    const std::filesystem::path& target);

        // Анализ путей
        static std::string GetExtension(const std::filesystem::path& path);
        static std::string GetFilename(const std::filesystem::path& path);
        static std::string GetStem(const std::filesystem::path& path);
        static std::filesystem::path GetParentPath(const std::filesystem::path& path);

        // Создание путей
        static std::filesystem::path JoinPaths(const std::vector<std::string>& components);
        static std::filesystem::path ChangeExtension(const std::filesystem::path& path,
                                                    const std::string& new_extension);

        // Проверка путей
        static bool IsValidPath(const std::filesystem::path& path);
        static bool IsAbsolutePath(const std::filesystem::path& path);
        static bool IsRelativePath(const std::filesystem::path& path);
        static bool PathContains(const std::filesystem::path& parent,
                                const std::filesystem::path& child);

        // Временные пути
        static std::filesystem::path GetTempDirectory();
        static std::filesystem::path GetSystemTempDirectory();
        static std::filesystem::path GetUserTempDirectory();
        static std::filesystem::path GenerateUniquePath(const std::filesystem::path& base_path,
                                                       const std::string& prefix = "");

        // Поиск файлов
        static std::vector<std::filesystem::path> FindFiles(const std::filesystem::path& directory,
                                                           const std::string& pattern,
                                                           bool recursive = false);
        static std::optional<std::filesystem::path> FindExecutable(const std::string& name);
    };

    // Утилиты для работы с директориями
    class DirectoryUtils {
    public:
        // Создание и удаление
        static bool CreateDirectory(const std::filesystem::path& path);
        static bool CreateDirectories(const std::filesystem::path& path);
        static bool RemoveDirectory(const std::filesystem::path& path, bool recursive = false);
        static bool IsDirectoryEmpty(const std::filesystem::path& path);

        // Копирование
        static bool CopyDirectory(const std::filesystem::path& source,
                                 const std::filesystem::path& destination,
                                 bool overwrite = false);

        // Обход директории
        static std::vector<std::filesystem::path> ListFiles(const std::filesystem::path& directory,
                                                           bool recursive = false);
        static std::vector<std::filesystem::path> ListDirectories(const std::filesystem::path& directory,
                                                                 bool recursive = false);

        // Размер директории
        static std::uintmax_t GetDirectorySize(const std::filesystem::path& path,
                                              bool recursive = true);
        static std::size_t CountFiles(const std::filesystem::path& path,
                                     bool recursive = true);

        // Очистка
        static bool CleanDirectory(const std::filesystem::path& path);
        static bool CleanOldFiles(const std::filesystem::path& path,
                                 const std::chrono::hours& max_age);
    };

    // Детектор типов файлов
    class FileTypeDetector {
    public:
        FileTypeDetector();
        ~FileTypeDetector();

        // Детекция по содержимому
        FileType DetectByContent(const std::filesystem::path& file_path);
        FileType DetectBySignature(const std::vector<uint8_t>& data);

        // Детекция по расширению
        FileType DetectByExtension(const std::string& extension);

        // MIME типы
        std::string GetMimeType(const std::filesystem::path& file_path);
        std::string GetMimeTypeByExtension(const std::string& extension);

        // Регистрация новых типов
        void RegisterFileType(const std::string& extension, FileType type, const std::string& mime_type);
        void RegisterSignature(const std::vector<uint8_t>& signature, FileType type, std::size_t offset = 0);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        // Конвертация типов
        std::string FileTypeToString(FileType type);
        FileType StringToFileType(const std::string& type_str);

        std::string HashAlgorithmToString(HashAlgorithm algorithm);
        HashAlgorithm StringToHashAlgorithm(const std::string& algorithm_str);

        // Размер файлов
        std::string FormatFileSize(std::uintmax_t size);
        std::uintmax_t ParseFileSize(const std::string& size_str);

        // Время
        std::string FormatFileTime(const std::filesystem::file_time_type& time);
        std::filesystem::file_time_type ParseFileTime(const std::string& time_str);

        // Кодировки
        std::string ConvertEncoding(const std::string& text,
                                   const std::string& from_encoding,
                                   const std::string& to_encoding);
        std::string DetectEncoding(const std::vector<uint8_t>& data);

        // Проверка доступности
        bool IsFileInUse(const std::filesystem::path& file_path);
        bool WaitForFileAccess(const std::filesystem::path& file_path,
                              std::chrono::milliseconds timeout = std::chrono::milliseconds{5000});

        // Сравнение файлов
        bool CompareFiles(const std::filesystem::path& file1,
                         const std::filesystem::path& file2);
        bool CompareFilesBySize(const std::filesystem::path& file1,
                               const std::filesystem::path& file2);

        // Блокировка файлов
        class FileLock {
        public:
            explicit FileLock(const std::filesystem::path& file_path);
            ~FileLock();

            bool TryLock();
            void Unlock();
            bool IsLocked() const;

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // Мониторинг файлов
        class FileWatcher {
        public:
            enum class EventType {
                FILE_CREATED,
                FILE_MODIFIED,
                FILE_DELETED,
                FILE_RENAMED
            };

            using WatchCallback = std::function<void(const std::filesystem::path& path, EventType event)>;

            FileWatcher();
            ~FileWatcher();

            bool AddWatch(const std::filesystem::path& path, bool recursive = false);
            bool RemoveWatch(const std::filesystem::path& path);
            void SetCallback(WatchCallback callback);

            void Start();
            void Stop();
            bool IsRunning() const;

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // Безопасное удаление
        bool SecureDelete(const std::filesystem::path& file_path, int passes = 3);

        // Проверка на вредоносность пути
        bool IsSafePath(const std::filesystem::path& path);
        bool IsPathTraversalAttempt(const std::filesystem::path& path);

        // Генерация уникальных имен
        std::string GenerateUniqueFileName(const std::string& prefix = "file_",
                                          const std::string& suffix = ".tmp");
        std::filesystem::path GetUniqueFilePath(const std::filesystem::path& desired_path);
    }
}