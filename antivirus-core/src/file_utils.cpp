//
// Created by WhySkyDie on 21.07.2025.
//


#include "file_utils.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <future>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <xxhash64.h>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
    #include <sys/stat.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <fcntl.h>
    #include <sys/mman.h>
#endif

namespace FileUtils {

    // Реализация FileManager::Impl
    class FileManager::Impl {
    public:
        FileOperationConfig config;
        ProgressCallback progress_callback;
        ErrorCallback error_callback;

        mutable std::mutex callback_mutex;
        std::vector<std::filesystem::path> temp_files;
        mutable std::mutex temp_files_mutex;

        Impl() = default;

        ~Impl() {
            CleanupTempFilesImpl();
        }

        ReadResult ReadFileImpl(const std::filesystem::path& file_path) {
            auto start_time = std::chrono::high_resolution_clock::now();
            ReadResult result;

            try {
                if (!std::filesystem::exists(file_path)) {
                    result.error_message = "File does not exist: " + file_path.string();
                    return result;
                }

                if (!std::filesystem::is_regular_file(file_path)) {
                    result.error_message = "Path is not a regular file: " + file_path.string();
                    return result;
                }

                std::uintmax_t file_size = std::filesystem::file_size(file_path);
                if (file_size > config.max_file_size) {
                    result.error_message = "File too large: " + std::to_string(file_size) + " bytes";
                    return result;
                }

                if (config.use_memory_mapping && file_size > config.buffer_size) {
                    result = ReadFileMemoryMapped(file_path, file_size);
                } else {
                    result = ReadFileBuffered(file_path, file_size);
                }

                auto end_time = std::chrono::high_resolution_clock::now();
                result.read_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Error reading file: " + std::string(e.what());
                return result;
            }
        }

        ReadResult ReadFileBuffered(const std::filesystem::path& file_path, std::uintmax_t file_size) {
            ReadResult result;

            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                result.error_message = "Cannot open file for reading: " + file_path.string();
                return result;
            }

            result.data.reserve(file_size);

            std::vector<char> buffer(config.buffer_size);
            std::size_t total_read = 0;

            while (file && total_read < file_size) {
                file.read(buffer.data(), buffer.size());
                std::streamsize bytes_read = file.gcount();

                if (bytes_read > 0) {
                    result.data.insert(result.data.end(), buffer.begin(), buffer.begin() + bytes_read);
                    total_read += bytes_read;
                    result.bytes_read = total_read;

                    // Callback прогресса
                    if (progress_callback) {
                        std::lock_guard<std::mutex> lock(callback_mutex);
                        progress_callback(total_read, file_size);
                    }
                }
            }

            result.success = (total_read == file_size);
            if (!result.success && result.error_message.empty()) {
                result.error_message = "Incomplete file read: " + std::to_string(total_read) +
                                     " of " + std::to_string(file_size) + " bytes";
            }

            return result;
        }

        ReadResult ReadFileMemoryMapped(const std::filesystem::path& file_path, std::uintmax_t file_size) {
            ReadResult result;

#ifdef _WIN32
            HANDLE file_handle = CreateFileA(file_path.string().c_str(), GENERIC_READ,
                                            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file_handle == INVALID_HANDLE_VALUE) {
                result.error_message = "Cannot open file for memory mapping";
                return result;
            }

            HANDLE mapping_handle = CreateFileMapping(file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!mapping_handle) {
                CloseHandle(file_handle);
                result.error_message = "Cannot create file mapping";
                return result;
            }

            void* mapped_data = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
            if (!mapped_data) {
                CloseHandle(mapping_handle);
                CloseHandle(file_handle);
                result.error_message = "Cannot map file to memory";
                return result;
            }

            result.data.resize(file_size);
            std::memcpy(result.data.data(), mapped_data, file_size);
            result.bytes_read = file_size;
            result.success = true;

            UnmapViewOfFile(mapped_data);
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
#else
            int fd = open(file_path.c_str(), O_RDONLY);
            if (fd == -1) {
                result.error_message = "Cannot open file for memory mapping";
                return result;
            }

            void* mapped_data = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (mapped_data == MAP_FAILED) {
                close(fd);
                result.error_message = "Cannot map file to memory";
                return result;
            }

            result.data.resize(file_size);
            std::memcpy(result.data.data(), mapped_data, file_size);
            result.bytes_read = file_size;
            result.success = true;

            munmap(mapped_data, file_size);
            close(fd);
#endif

            return result;
        }

        WriteResult WriteFileImpl(const std::filesystem::path& file_path,
                                 const std::vector<uint8_t>& data,
                                 bool append) {
            auto start_time = std::chrono::high_resolution_clock::now();
            WriteResult result;

            try {
                // Создание директории если необходимо
                std::filesystem::create_directories(file_path.parent_path());

                std::ios_base::openmode mode = std::ios::binary;
                if (append) {
                    mode |= std::ios::app;
                } else {
                    mode |= std::ios::trunc;
                }

                std::ofstream file(file_path, mode);
                if (!file.is_open()) {
                    result.error_message = "Cannot open file for writing: " + file_path.string();
                    return result;
                }

                // Запись данных блоками
                std::size_t total_written = 0;
                std::size_t data_size = data.size();

                while (total_written < data_size) {
                    std::size_t chunk_size = std::min(config.buffer_size, data_size - total_written);

                    file.write(reinterpret_cast<const char*>(data.data() + total_written), chunk_size);

                    if (!file.good()) {
                        result.error_message = "Error writing to file";
                        return result;
                    }

                    total_written += chunk_size;
                    result.bytes_written = total_written;

                    // Callback прогресса
                    if (progress_callback) {
                        std::lock_guard<std::mutex> lock(callback_mutex);
                        progress_callback(total_written, data_size);
                    }
                }

                file.flush();
                result.success = true;

                auto end_time = std::chrono::high_resolution_clock::now();
                result.write_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Error writing file: " + std::string(e.what());
                return result;
            }
        }

        WriteResult WriteFileAtomicImpl(const std::filesystem::path& file_path,
                                       const std::vector<uint8_t>& data) {
            try {
                // Создание временного файла
                std::filesystem::path temp_path = file_path;
                temp_path += ".tmp." + Utils::GenerateUniqueFileName();

                // Запись во временный файл
                WriteResult temp_result = WriteFileImpl(temp_path, data, false);
                if (!temp_result.success) {
                    std::filesystem::remove(temp_path);
                    return temp_result;
                }

                // Атомарная замена
                std::error_code ec;
                std::filesystem::rename(temp_path, file_path, ec);

                if (ec) {
                    std::filesystem::remove(temp_path);
                    WriteResult result;
                    result.error_message = "Failed to replace file atomically: " + ec.message();
                    return result;
                }

                return temp_result;

            } catch (const std::exception& e) {
                WriteResult result;
                result.error_message = "Atomic write error: " + std::string(e.what());
                return result;
            }
        }

        std::filesystem::path CreateTempFileImpl(const std::string& prefix, const std::string& suffix) {
            try {
                std::filesystem::create_directories(config.temp_directory);

                std::string filename = prefix + Utils::GenerateUniqueFileName() + suffix;
                std::filesystem::path temp_path = config.temp_directory / filename;

                // Создание пустого файла
                std::ofstream file(temp_path);
                file.close();

                // Добавление в список для последующей очистки
                {
                    std::lock_guard<std::mutex> lock(temp_files_mutex);
                    temp_files.push_back(temp_path);
                }

                return temp_path;

            } catch (const std::exception& e) {
                if (error_callback) {
                    std::lock_guard<std::mutex> lock(callback_mutex);
                    error_callback("Failed to create temp file: " + std::string(e.what()));
                }
                return {};
            }
        }

        bool CleanupTempFilesImpl() {
            bool all_cleaned = true;

            std::lock_guard<std::mutex> lock(temp_files_mutex);
            for (const auto& temp_file : temp_files) {
                try {
                    if (std::filesystem::exists(temp_file)) {
                        std::filesystem::remove(temp_file);
                    }
                } catch (const std::exception&) {
                    all_cleaned = false;
                }
            }

            temp_files.clear();
            return all_cleaned;
        }

        void NotifyError(const std::string& error_message) {
            if (error_callback) {
                std::lock_guard<std::mutex> lock(callback_mutex);
                error_callback(error_message);
            }
        }
    };

    // Реализация HashUtils::Impl
    class HashUtils::Impl {
    public:
        std::string CalculateFileHashImpl(const std::filesystem::path& file_path, HashAlgorithm algorithm) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file for hashing: " + file_path.string());
            }

            IncrementalHasher hasher(algorithm);

            const std::size_t buffer_size = 64 * 1024;
            std::vector<char> buffer(buffer_size);

            while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
                hasher.Update(buffer.data(), file.gcount());
            }

            return hasher.Finalize();
        }

        std::string CalculateDataHashImpl(const std::vector<uint8_t>& data, HashAlgorithm algorithm) {
            IncrementalHasher hasher(algorithm);
            hasher.Update(data);
            return hasher.Finalize();
        }
    };

    // Реализация IncrementalHasher::Impl
    class HashUtils::IncrementalHasher::Impl {
    public:
        HashAlgorithm algorithm;
        void* context;
        bool finalized;

        Impl(HashAlgorithm algo) : algorithm(algo), context(nullptr), finalized(false) {
            switch (algorithm) {
                case HashAlgorithm::MD5:
                    context = new MD5_CTX;
                    MD5_Init(static_cast<MD5_CTX*>(context));
                    break;
                case HashAlgorithm::SHA1:
                    context = new SHA_CTX;
                    SHA1_Init(static_cast<SHA_CTX*>(context));
                    break;
                case HashAlgorithm::SHA256:
                    context = new SHA256_CTX;
                    SHA256_Init(static_cast<SHA256_CTX*>(context));
                    break;
                case HashAlgorithm::SHA512:
                    context = new SHA512_CTX;
                    SHA512_Init(static_cast<SHA512_CTX*>(context));
                    break;
                default:
                    throw std::invalid_argument("Unsupported hash algorithm");
            }
        }

        ~Impl() {
            if (context) {
                switch (algorithm) {
                    case HashAlgorithm::MD5:
                        delete static_cast<MD5_CTX*>(context);
                        break;
                    case HashAlgorithm::SHA1:
                        delete static_cast<SHA_CTX*>(context);
                        break;
                    case HashAlgorithm::SHA256:
                        delete static_cast<SHA256_CTX*>(context);
                        break;
                    case HashAlgorithm::SHA512:
                        delete static_cast<SHA512_CTX*>(context);
                        break;
                }
            }
        }

        void Update(const void* data, std::size_t size) {
            if (finalized) {
                throw std::runtime_error("Cannot update finalized hasher");
            }

            switch (algorithm) {
                case HashAlgorithm::MD5:
                    MD5_Update(static_cast<MD5_CTX*>(context), data, size);
                    break;
                case HashAlgorithm::SHA1:
                    SHA1_Update(static_cast<SHA_CTX*>(context), data, size);
                    break;
                case HashAlgorithm::SHA256:
                    SHA256_Update(static_cast<SHA256_CTX*>(context), data, size);
                    break;
                case HashAlgorithm::SHA512:
                    SHA512_Update(static_cast<SHA512_CTX*>(context), data, size);
                    break;
            }
        }

        std::string Finalize() {
            if (finalized) {
                throw std::runtime_error("Hasher already finalized");
            }

            std::vector<unsigned char> hash;

            switch (algorithm) {
                case HashAlgorithm::MD5:
                    hash.resize(MD5_DIGEST_LENGTH);
                    MD5_Final(hash.data(), static_cast<MD5_CTX*>(context));
                    break;
                case HashAlgorithm::SHA1:
                    hash.resize(SHA_DIGEST_LENGTH);
                    SHA1_Final(hash.data(), static_cast<SHA_CTX*>(context));
                    break;
                case HashAlgorithm::SHA256:
                    hash.resize(SHA256_DIGEST_LENGTH);
                    SHA256_Final(hash.data(), static_cast<SHA256_CTX*>(context));
                    break;
                case HashAlgorithm::SHA512:
                    hash.resize(SHA512_DIGEST_LENGTH);
                    SHA512_Final(hash.data(), static_cast<SHA512_CTX*>(context));
                    break;
            }

            finalized = true;

            // Конвертация в hex строку
            std::stringstream ss;
            for (unsigned char byte : hash) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }

            return ss.str();
        }

        void Reset() {
            finalized = false;

            switch (algorithm) {
                case HashAlgorithm::MD5:
                    MD5_Init(static_cast<MD5_CTX*>(context));
                    break;
                case HashAlgorithm::SHA1:
                    SHA1_Init(static_cast<SHA_CTX*>(context));
                    break;
                case HashAlgorithm::SHA256:
                    SHA256_Init(static_cast<SHA256_CTX*>(context));
                    break;
                case HashAlgorithm::SHA512:
                    SHA512_Init(static_cast<SHA512_CTX*>(context));
                    break;
            }
        }
    };

    // Реализация FileTypeDetector::Impl
    class FileTypeDetector::Impl {
    public:
        // Сигнатуры файлов
        struct FileSignature {
            std::vector<uint8_t> signature;
            std::size_t offset;
            FileType type;
        };

        std::vector<FileSignature> signatures;
        std::unordered_map<std::string, FileType> extension_map;
        std::unordered_map<std::string, std::string> mime_map;

        Impl() {
            InitializeDefaultSignatures();
            InitializeDefaultExtensions();
        }

        void InitializeDefaultSignatures() {
            // PDF
            signatures.push_back({{0x25, 0x50, 0x44, 0x46}, 0, FileType::DOCUMENT});

            // JPEG
            signatures.push_back({{0xFF, 0xD8, 0xFF}, 0, FileType::IMAGE});

            // PNG
            signatures.push_back({{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, FileType::IMAGE});

            // ZIP/Office documents
            signatures.push_back({{0x50, 0x4B, 0x03, 0x04}, 0, FileType::ARCHIVE});

            // EXE
            signatures.push_back({{0x4D, 0x5A}, 0, FileType::EXECUTABLE});

            // ELF
            signatures.push_back({{0x7F, 0x45, 0x4C, 0x46}, 0, FileType::EXECUTABLE});

            // AVI
            signatures.push_back({{0x52, 0x49, 0x46, 0x46}, 0, FileType::VIDEO});

            // MP3
            signatures.push_back({{0xFF, 0xFB}, 0, FileType::AUDIO});
            signatures.push_back({{0x49, 0x44, 0x33}, 0, FileType::AUDIO});
        }

        void InitializeDefaultExtensions() {
            // Изображения
            extension_map[".jpg"] = extension_map[".jpeg"] = FileType::IMAGE;
            extension_map[".png"] = extension_map[".gif"] = FileType::IMAGE;
            extension_map[".bmp"] = extension_map[".tiff"] = FileType::IMAGE;

            // Документы
            extension_map[".pdf"] = extension_map[".doc"] = FileType::DOCUMENT;
            extension_map[".docx"] = extension_map[".txt"] = FileType::DOCUMENT;
            extension_map[".rtf"] = extension_map[".odt"] = FileType::DOCUMENT;

            // Архивы
            extension_map[".zip"] = extension_map[".rar"] = FileType::ARCHIVE;
            extension_map[".7z"] = extension_map[".tar"] = FileType::ARCHIVE;
            extension_map[".gz"] = extension_map[".bz2"] = FileType::ARCHIVE;

            // Исполняемые файлы
            extension_map[".exe"] = extension_map[".dll"] = FileType::EXECUTABLE;
            extension_map[".so"] = extension_map[".dylib"] = FileType::EXECUTABLE;

            // Видео
            extension_map[".mp4"] = extension_map[".avi"] = FileType::VIDEO;
            extension_map[".mkv"] = extension_map[".mov"] = FileType::VIDEO;
            extension_map[".wmv"] = extension_map[".flv"] = FileType::VIDEO;

            // Аудио
            extension_map[".mp3"] = extension_map[".wav"] = FileType::AUDIO;
            extension_map[".flac"] = extension_map[".ogg"] = FileType::AUDIO;
            extension_map[".aac"] = extension_map[".wma"] = FileType::AUDIO;

            // Скрипты
            extension_map[".js"] = extension_map[".py"] = FileType::SCRIPT;
            extension_map[".sh"] = extension_map[".bat"] = FileType::SCRIPT;
            extension_map[".ps1"] = extension_map[".vbs"] = FileType::SCRIPT;

            // MIME типы
            mime_map[".txt"] = "text/plain";
            mime_map[".html"] = "text/html";
            mime_map[".css"] = "text/css";
            mime_map[".js"] = "application/javascript";
            mime_map[".json"] = "application/json";
            mime_map[".xml"] = "application/xml";
            mime_map[".pdf"] = "application/pdf";
            mime_map[".zip"] = "application/zip";
            mime_map[".jpg"] = mime_map[".jpeg"] = "image/jpeg";
            mime_map[".png"] = "image/png";
            mime_map[".gif"] = "image/gif";
            mime_map[".mp4"] = "video/mp4";
            mime_map[".mp3"] = "audio/mpeg";
            mime_map[".wav"] = "audio/wav";
        }

        FileType DetectByContentImpl(const std::filesystem::path& file_path) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                return FileType::UNKNOWN;
            }

            // Читаем первые несколько KB для анализа сигнатур
            const std::size_t buffer_size = 8192;
            std::vector<uint8_t> buffer(buffer_size);

            file.read(reinterpret_cast<char*>(buffer.data()), buffer_size);
            std::size_t bytes_read = file.gcount();

            if (bytes_read > 0) {
                buffer.resize(bytes_read);
                return DetectBySignatureImpl(buffer);
            }

            return FileType::UNKNOWN;
        }

        FileType DetectBySignatureImpl(const std::vector<uint8_t>& data) {
            for (const auto& sig : signatures) {
                if (data.size() >= sig.offset + sig.signature.size()) {
                    bool match = std::equal(sig.signature.begin(), sig.signature.end(),
                                          data.begin() + sig.offset);
                    if (match) {
                        return sig.type;
                    }
                }
            }

            return FileType::UNKNOWN;
        }

        FileType DetectByExtensionImpl(const std::string& extension) {
            std::string lower_ext = extension;
            std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(), ::tolower);

            auto it = extension_map.find(lower_ext);
            return it != extension_map.end() ? it->second : FileType::UNKNOWN;
        }

        std::string GetMimeTypeImpl(const std::filesystem::path& file_path) {
            std::string extension = file_path.extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

            auto it = mime_map.find(extension);
            return it != mime_map.end() ? it->second : "application/octet-stream";
        }
    };

    // Реализация основных классов

    // FileManager
    FileManager::FileManager() : pImpl(std::make_unique<Impl>()) {}

    FileManager::FileManager(const FileOperationConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    FileManager::~FileManager() = default;

    void FileManager::SetConfig(const FileOperationConfig& config) {
        pImpl->config = config;
    }

    const FileOperationConfig& FileManager::GetConfig() const {
        return pImpl->config;
    }

    void FileManager::SetProgressCallback(ProgressCallback callback) {
        std::lock_guard<std::mutex> lock(pImpl->callback_mutex);
        pImpl->progress_callback = std::move(callback);
    }

    void FileManager::SetErrorCallback(ErrorCallback callback) {
        std::lock_guard<std::mutex> lock(pImpl->callback_mutex);
        pImpl->error_callback = std::move(callback);
    }

    ReadResult FileManager::ReadFile(const std::filesystem::path& file_path) {
        return pImpl->ReadFileImpl(file_path);
    }

    ReadResult FileManager::ReadFileAsync(const std::filesystem::path& file_path) {
        auto future_result = std::async(std::launch::async, [this, file_path]() {
            return pImpl->ReadFileImpl(file_path);
        });

        return future_result.get();
    }

    ReadResult FileManager::ReadFileChunk(const std::filesystem::path& file_path,
                                         std::size_t offset, std::size_t size) {
        ReadResult result;

        try {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                result.error_message = "Cannot open file";
                return result;
            }

            file.seekg(offset);
            if (!file.good()) {
                result.error_message = "Cannot seek to offset";
                return result;
            }

            result.data.resize(size);
            file.read(reinterpret_cast<char*>(result.data.data()), size);

            result.bytes_read = file.gcount();
            result.success = (result.bytes_read > 0);

            if (result.bytes_read < size) {
                result.data.resize(result.bytes_read);
            }

        } catch (const std::exception& e) {
            result.error_message = e.what();
        }

        return result;
    }

    std::string FileManager::ReadTextFile(const std::filesystem::path& file_path, const std::string& encoding) {
        auto read_result = ReadFile(file_path);
        if (!read_result.success) {
            return "";
        }

        return std::string(read_result.data.begin(), read_result.data.end());
    }

    std::vector<std::string> FileManager::ReadLines(const std::filesystem::path& file_path) {
        std::vector<std::string> lines;
        std::ifstream file(file_path);

        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                lines.push_back(line);
            }
        }

        return lines;
    }

    WriteResult FileManager::WriteFile(const std::filesystem::path& file_path,
                                      const std::vector<uint8_t>& data,
                                      bool append) {
        return pImpl->WriteFileImpl(file_path, data, append);
    }

    WriteResult FileManager::WriteTextFile(const std::filesystem::path& file_path,
                                          const std::string& content,
                                          bool append) {
        std::vector<uint8_t> data(content.begin(), content.end());
        return WriteFile(file_path, data, append);
    }

    WriteResult FileManager::WriteLines(const std::filesystem::path& file_path,
                                       const std::vector<std::string>& lines) {
        std::ostringstream oss;
        for (const auto& line : lines) {
            oss << line << '\n';
        }

        return WriteTextFile(file_path, oss.str());
    }

    WriteResult FileManager::WriteFileAtomic(const std::filesystem::path& file_path,
                                            const std::vector<uint8_t>& data) {
        return pImpl->WriteFileAtomicImpl(file_path, data);
    }

    std::optional<FileInfo> FileManager::GetFileInfo(const std::filesystem::path& file_path) {
        try {
            if (!std::filesystem::exists(file_path)) {
                return std::nullopt;
            }

            FileInfo info;
            info.file_path = file_path;

            std::error_code ec;
            auto status = std::filesystem::status(file_path, ec);
            if (ec) {
                return std::nullopt;
            }

            info.is_directory = std::filesystem::is_directory(status);
            info.is_regular_file = std::filesystem::is_regular_file(status);
            info.is_symlink = std::filesystem::is_symlink(status);

            if (info.is_regular_file) {
                info.size = std::filesystem::file_size(file_path, ec);
                if (ec) info.size = 0;
            }

            info.last_write_time = std::filesystem::last_write_time(file_path, ec);
            info.permissions = std::filesystem::status(file_path, ec).permissions();

            info.extension = file_path.extension().string();

            // Определение типа файла
            FileTypeDetector detector;
            if (info.is_regular_file) {
                info.file_type = detector.DetectByContent(file_path);
                if (info.file_type == FileType::UNKNOWN) {
                    info.file_type = detector.DetectByExtension(info.extension);
                }
                info.mime_type = detector.GetMimeType(file_path);
            }

            return info;

        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    bool FileManager::FileExists(const std::filesystem::path& file_path) {
        return std::filesystem::exists(file_path);
    }

    bool FileManager::IsDirectory(const std::filesystem::path& path) {
        return std::filesystem::is_directory(path);
    }

    bool FileManager::IsRegularFile(const std::filesystem::path& path) {
        return std::filesystem::is_regular_file(path);
    }

    std::uintmax_t FileManager::GetFileSize(const std::filesystem::path& file_path) {
        std::error_code ec;
        auto size = std::filesystem::file_size(file_path, ec);
        return ec ? 0 : size;
    }

    bool FileManager::CopyFile(const std::filesystem::path& source,
                              const std::filesystem::path& destination,
                              bool overwrite) {
        try {
            std::filesystem::copy_options options = std::filesystem::copy_options::none;
            if (overwrite) {
                options = std::filesystem::copy_options::overwrite_existing;
            }

            std::filesystem::create_directories(destination.parent_path());
            return std::filesystem::copy_file(source, destination, options);

        } catch (const std::exception&) {
            return false;
        }
    }

    bool FileManager::MoveFile(const std::filesystem::path& source,
                              const std::filesystem::path& destination) {
        try {
            std::filesystem::create_directories(destination.parent_path());
            std::filesystem::rename(source, destination);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    bool FileManager::DeleteFile(const std::filesystem::path& file_path) {
        try {
            return std::filesystem::remove(file_path);
        } catch (const std::exception&) {
            return false;
        }
    }

    std::filesystem::path FileManager::CreateTempFile(const std::string& prefix, const std::string& suffix) {
        return pImpl->CreateTempFileImpl(prefix, suffix);
    }

    std::filesystem::path FileManager::CreateTempDirectory(const std::string& prefix) {
        try {
            std::filesystem::create_directories(pImpl->config.temp_directory);

            std::string dirname = prefix + Utils::GenerateUniqueFileName();
            std::filesystem::path temp_path = pImpl->config.temp_directory / dirname;

            std::filesystem::create_directories(temp_path);

            return temp_path;

        } catch (const std::exception&) {
            return {};
        }
    }

    bool FileManager::CleanupTempFiles() {
        return pImpl->CleanupTempFilesImpl();
    }

    // HashUtils
    HashUtils::HashUtils() : pImpl(std::make_unique<Impl>()) {}
    HashUtils::~HashUtils() = default;

    std::string HashUtils::CalculateFileHash(const std::filesystem::path& file_path, HashAlgorithm algorithm) {
        return pImpl->CalculateFileHashImpl(file_path, algorithm);
    }

    std::string HashUtils::CalculateDataHash(const std::vector<uint8_t>& data, HashAlgorithm algorithm) {
        return pImpl->CalculateDataHashImpl(data, algorithm);
    }

    std::string HashUtils::CalculateStringHash(const std::string& str, HashAlgorithm algorithm) {
        std::vector<uint8_t> data(str.begin(), str.end());
        return CalculateDataHash(data, algorithm);
    }

    bool HashUtils::CompareFilesByHash(const std::filesystem::path& file1,
                                      const std::filesystem::path& file2,
                                      HashAlgorithm algorithm) {
        try {
            std::string hash1 = CalculateFileHash(file1, algorithm);
            std::string hash2 = CalculateFileHash(file2, algorithm);
            return hash1 == hash2;
        } catch (const std::exception&) {
            return false;
        }
    }

    bool HashUtils::VerifyFileIntegrity(const std::filesystem::path& file_path,
                                       const std::string& expected_hash,
                                       HashAlgorithm algorithm) {
        try {
            std::string calculated_hash = CalculateFileHash(file_path, algorithm);
            return calculated_hash == expected_hash;
        } catch (const std::exception&) {
            return false;
        }
    }

    // IncrementalHasher
    HashUtils::IncrementalHasher::IncrementalHasher(HashAlgorithm algorithm)
        : pImpl(std::make_unique<Impl>(algorithm)) {}

    HashUtils::IncrementalHasher::~IncrementalHasher() = default;

    void HashUtils::IncrementalHasher::Update(const std::vector<uint8_t>& data) {
        pImpl->Update(data.data(), data.size());
    }

    void HashUtils::IncrementalHasher::Update(const void* data, std::size_t size) {
        pImpl->Update(data, size);
    }

    std::string HashUtils::IncrementalHasher::Finalize() {
        return pImpl->Finalize();
    }

    void HashUtils::IncrementalHasher::Reset() {
        pImpl->Reset();
    }

    // FileTypeDetector
    FileTypeDetector::FileTypeDetector() : pImpl(std::make_unique<Impl>()) {}
    FileTypeDetector::~FileTypeDetector() = default;

    FileType FileTypeDetector::DetectByContent(const std::filesystem::path& file_path) {
        return pImpl->DetectByContentImpl(file_path);
    }

    FileType FileTypeDetector::DetectBySignature(const std::vector<uint8_t>& data) {
        return pImpl->DetectBySignatureImpl(data);
    }

    FileType FileTypeDetector::DetectByExtension(const std::string& extension) {
        return pImpl->DetectByExtensionImpl(extension);
    }

    std::string FileTypeDetector::GetMimeType(const std::filesystem::path& file_path) {
        return pImpl->GetMimeTypeImpl(file_path);
    }

    std::string FileTypeDetector::GetMimeTypeByExtension(const std::string& extension) {
        auto it = pImpl->mime_map.find(extension);
        return it != pImpl->mime_map.end() ? it->second : "application/octet-stream";
    }

    // Утилитарные функции PathUtils
    std::filesystem::path PathUtils::NormalizePath(const std::filesystem::path& path) {
        try {
            return std::filesystem::weakly_canonical(path);
        } catch (const std::exception&) {
            return path;
        }
    }

    std::filesystem::path PathUtils::GetAbsolutePath(const std::filesystem::path& path) {
        try {
            return std::filesystem::absolute(path);
        } catch (const std::exception&) {
            return path;
        }
    }

    std::string PathUtils::GetExtension(const std::filesystem::path& path) {
        return path.extension().string();
    }

    std::string PathUtils::GetFilename(const std::filesystem::path& path) {
        return path.filename().string();
    }

    std::string PathUtils::GetStem(const std::filesystem::path& path) {
        return path.stem().string();
    }

    std::filesystem::path PathUtils::GetParentPath(const std::filesystem::path& path) {
        return path.parent_path();
    }

    std::filesystem::path PathUtils::GetTempDirectory() {
        return std::filesystem::temp_directory_path();
    }

    std::filesystem::path PathUtils::GenerateUniquePath(const std::filesystem::path& base_path, const std::string& prefix) {
        std::filesystem::path unique_path;
        do {
            std::string unique_name = prefix + Utils::GenerateUniqueFileName();
            unique_path = base_path / unique_name;
        } while (std::filesystem::exists(unique_path));

        return unique_path;
    }

    bool PathUtils::IsValidPath(const std::filesystem::path& path) {
        try {
            std::filesystem::path test_path = path;
            // Простая проверка валидности пути
            return !path.empty() && !path.string().empty();
        } catch (const std::exception&) {
            return false;
        }
    }

    // Утилитарные функции Utils
    namespace Utils {

        std::string FileTypeToString(FileType type) {
            switch (type) {
                case FileType::UNKNOWN: return "unknown";
                case FileType::TEXT: return "text";
                case FileType::BINARY: return "binary";
                case FileType::EXECUTABLE: return "executable";
                case FileType::ARCHIVE: return "archive";
                case FileType::IMAGE: return "image";
                case FileType::VIDEO: return "video";
                case FileType::AUDIO: return "audio";
                case FileType::DOCUMENT: return "document";
                case FileType::SCRIPT: return "script";
                default: return "unknown";
            }
        }

        FileType StringToFileType(const std::string& type_str) {
            if (type_str == "text") return FileType::TEXT;
            if (type_str == "binary") return FileType::BINARY;
            if (type_str == "executable") return FileType::EXECUTABLE;
            if (type_str == "archive") return FileType::ARCHIVE;
            if (type_str == "image") return FileType::IMAGE;
            if (type_str == "video") return FileType::VIDEO;
            if (type_str == "audio") return FileType::AUDIO;
            if (type_str == "document") return FileType::DOCUMENT;
            if (type_str == "script") return FileType::SCRIPT;
            return FileType::UNKNOWN;
        }

        std::string HashAlgorithmToString(HashAlgorithm algorithm) {
            switch (algorithm) {
                case HashAlgorithm::MD5: return "md5";
                case HashAlgorithm::SHA1: return "sha1";
                case HashAlgorithm::SHA256: return "sha256";
                case HashAlgorithm::SHA512: return "sha512";
                case HashAlgorithm::CRC32: return "crc32";
                case HashAlgorithm::XXHASH64: return "xxhash64";
                default: return "unknown";
            }
        }

        HashAlgorithm StringToHashAlgorithm(const std::string& algorithm_str) {
            if (algorithm_str == "md5") return HashAlgorithm::MD5;
            if (algorithm_str == "sha1") return HashAlgorithm::SHA1;
            if (algorithm_str == "sha256") return HashAlgorithm::SHA256;
            if (algorithm_str == "sha512") return HashAlgorithm::SHA512;
            if (algorithm_str == "crc32") return HashAlgorithm::CRC32;
            if (algorithm_str == "xxhash64") return HashAlgorithm::XXHASH64;
            return HashAlgorithm::SHA256; // default
        }

        std::string FormatFileSize(std::uintmax_t size) {
            const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
            int unit_index = 0;
            double size_d = static_cast<double>(size);

            while (size_d >= 1024.0 && unit_index < 5) {
                size_d /= 1024.0;
                unit_index++;
            }

            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << size_d << " " << units[unit_index];
            return oss.str();
        }

        std::string GenerateUniqueFileName(const std::string& prefix, const std::string& suffix) {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::ostringstream oss;
            oss << prefix;

            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            oss << std::hex << time_t << "_";

            for (int i = 0; i < 8; ++i) {
                oss << std::hex << dis(gen);
            }

            oss << suffix;
            return oss.str();
        }

        bool CompareFiles(const std::filesystem::path& file1, const std::filesystem::path& file2) {
            try {
                // Сначала сравниваем размеры
                if (!CompareFilesBySize(file1, file2)) {
                    return false;
                }

                // Затем сравниваем содержимое
                std::ifstream f1(file1, std::ios::binary);
                std::ifstream f2(file2, std::ios::binary);

                if (!f1.is_open() || !f2.is_open()) {
                    return false;
                }

                const std::size_t buffer_size = 8192;
                std::vector<char> buffer1(buffer_size);
                std::vector<char> buffer2(buffer_size);

                while (f1 && f2) {
                    f1.read(buffer1.data(), buffer_size);
                    f2.read(buffer2.data(), buffer_size);

                    if (f1.gcount() != f2.gcount()) {
                        return false;
                    }

                    if (std::memcmp(buffer1.data(), buffer2.data(), f1.gcount()) != 0) {
                        return false;
                    }
                }

                return f1.eof() && f2.eof();

            } catch (const std::exception&) {
                return false;
            }
        }

        bool CompareFilesBySize(const std::filesystem::path& file1, const std::filesystem::path& file2) {
            try {
                return std::filesystem::file_size(file1) == std::filesystem::file_size(file2);
            } catch (const std::exception&) {
                return false;
            }
        }

        bool SecureDelete(const std::filesystem::path& file_path, int passes) {
            try {
                if (!std::filesystem::exists(file_path)) {
                    return true;
                }

                std::uintmax_t file_size = std::filesystem::file_size(file_path);

                // Открываем файл для записи
                std::fstream file(file_path, std::ios::binary | std::ios::in | std::ios::out);
                if (!file.is_open()) {
                    return false;
                }

                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dis(0, 255);

                const std::size_t buffer_size = 64 * 1024;
                std::vector<uint8_t> random_data(buffer_size);

                // Многократная перезапись случайными данными
                for (int pass = 0; pass < passes; ++pass) {
                    file.seekp(0, std::ios::beg);

                    for (std::uintmax_t written = 0; written < file_size; written += buffer_size) {
                        std::size_t write_size = std::min(buffer_size, static_cast<std::size_t>(file_size - written));

                        // Генерация случайных данных
                        for (std::size_t i = 0; i < write_size; ++i) {
                            random_data[i] = dis(gen);
                        }

                        file.write(reinterpret_cast<const char*>(random_data.data()), write_size);
                    }

                    file.flush();
                }

                file.close();

                // Удаление файла
                return std::filesystem::remove(file_path);

            } catch (const std::exception&) {
                return false;
            }
        }

        std::filesystem::path GetUniqueFilePath(const std::filesystem::path& desired_path) {
            if (!std::filesystem::exists(desired_path)) {
                return desired_path;
            }

            std::filesystem::path parent = desired_path.parent_path();
            std::string stem = desired_path.stem().string();
            std::string extension = desired_path.extension().string();

            int counter = 1;
            std::filesystem::path unique_path;

            do {
                std::string new_filename = stem + "_" + std::to_string(counter) + extension;
                unique_path = parent / new_filename;
                counter++;
            } while (std::filesystem::exists(unique_path));

            return unique_path;
        }

        bool IsSafePath(const std::filesystem::path& path) {
            std::string path_str = path.string();

            // Проверка на path traversal
            if (path_str.find("..") != std::string::npos) {
                return false;
            }

            // Проверка на абсолютные пути в небезопасных местах
            if (path.is_absolute()) {
                std::string abs_path = path.string();
                #ifdef _WIN32
                if (abs_path.find("C:\\Windows") == 0 || abs_path.find("C:\\Program Files") == 0) {
                    return false;
                }
                #else
                if (abs_path.find("/etc") == 0 || abs_path.find("/usr/bin") == 0 || abs_path.find("/bin") == 0) {
                    return false;
                }
                #endif
            }

            return true;
        }

        bool IsPathTraversalAttempt(const std::filesystem::path& path) {
            std::string path_str = path.string();

            // Поиск различных вариантов path traversal
            std::vector<std::string> traversal_patterns = {
                "..", "..\\", "../", "%2e%2e", "%2e%2e%2f", "%2e%2e\\",
                "%c0%ae%c0%ae", "..%c1%9c", "..%c0%af"
            };

            std::transform(path_str.begin(), path_str.end(), path_str.begin(), ::tolower);

            for (const auto& pattern : traversal_patterns) {
                if (path_str.find(pattern) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }
    }
}