//
// Created by WhySkyDie on 21.07.2025.
//


#include "quarantine.h"
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <iomanip>
#include <thread>
#include <future>
#include <json/json.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

#ifdef _WIN32
    #include <windows.h>
    #include <lmcons.h>
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <sys/utsname.h>
#endif

namespace QuarantineEngine {

    // Реализация QuarantineManager::Impl
    class QuarantineManager::Impl {
    public:
        QuarantineConfig config;
        std::vector<QuarantinedFile> quarantined_files;
        std::unordered_map<std::string, std::size_t> file_index;

        mutable std::mutex files_mutex;
        mutable std::mutex stats_mutex;
        std::atomic<bool> initialized{false};

        QuarantineStatistics statistics;

        // Callbacks
        ProgressCallback progress_callback;
        QuarantineCallback quarantine_callback;
        ErrorCallback error_callback;

        // Engines
        CryptoEngine crypto_engine;
        CompressionEngine compression_engine;

        Impl() = default;

        bool InitializeDirectories() {
            try {
                std::filesystem::create_directories(config.quarantine_directory);
                std::filesystem::create_directories(config.metadata_directory);
                std::filesystem::create_directories(config.temp_directory);
                return true;
            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Failed to create quarantine directories: " + std::string(e.what()), "");
                }
                return false;
            }
        }

        bool LoadMetadata() {
            try {
                std::lock_guard<std::mutex> lock(files_mutex);
                quarantined_files.clear();
                file_index.clear();

                if (!std::filesystem::exists(config.metadata_directory)) {
                    return true; // Нет метаданных - это нормально для первого запуска
                }

                for (const auto& entry : std::filesystem::directory_iterator(config.metadata_directory)) {
                    if (entry.path().extension() == ".json") {
                        try {
                            auto file_info = LoadFileMetadata(entry.path());
                            if (file_info) {
                                quarantined_files.push_back(*file_info);
                                file_index[file_info->quarantine_id] = quarantined_files.size() - 1;
                            }
                        } catch (const std::exception& e) {
                            if (error_callback) {
                                error_callback("Failed to load metadata: " + std::string(e.what()),
                                             entry.path().string());
                            }
                        }
                    }
                }

                UpdateStatistics();
                return true;

            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Failed to load quarantine metadata: " + std::string(e.what()), "");
                }
                return false;
            }
        }

        std::optional<QuarantinedFile> LoadFileMetadata(const std::filesystem::path& metadata_path) {
            std::ifstream file(metadata_path);
            if (!file.is_open()) {
                return std::nullopt;
            }

            Json::Value root;
            Json::Reader reader;
            if (!reader.parse(file, root)) {
                return std::nullopt;
            }

            QuarantinedFile quarantined_file;

            quarantined_file.quarantine_id = root.get("quarantine_id", "").asString();
            quarantined_file.original_path = root.get("original_path", "").asString();
            quarantined_file.quarantine_path = root.get("quarantine_path", "").asString();
            quarantined_file.original_hash = root.get("original_hash", "").asString();
            quarantined_file.quarantine_hash = root.get("quarantine_hash", "").asString();
            quarantined_file.original_size = root.get("original_size", 0).asUInt64();
            quarantined_file.quarantine_size = root.get("quarantine_size", 0).asUInt64();

            quarantined_file.status = Utils::StringToQuarantineStatus(root.get("status", "pending").asString());
            quarantined_file.action = Utils::StringToQuarantineAction(root.get("action", "move").asString());
            quarantined_file.reason = Utils::StringToQuarantineReason(root.get("reason", "unknown_file_type").asString());

            quarantined_file.quarantine_time = Utils::ParseTimestamp(root.get("quarantine_time", "").asString());
            quarantined_file.expiry_time = Utils::ParseTimestamp(root.get("expiry_time", "").asString());

            quarantined_file.encryption_algorithm = Utils::StringToEncryptionAlgorithm(
                root.get("encryption_algorithm", "aes_256_cbc").asString());
            quarantined_file.compression_algorithm = Utils::StringToCompressionAlgorithm(
                root.get("compression_algorithm", "zlib").asString());

            quarantined_file.detection_engine = root.get("detection_engine", "").asString();
            quarantined_file.signature_name = root.get("signature_name", "").asString();
            quarantined_file.user_name = root.get("user_name", "").asString();
            quarantined_file.computer_name = root.get("computer_name", "").asString();

            // Metadata
            if (root.isMember("metadata") && root["metadata"].isObject()) {
                for (const auto& key : root["metadata"].getMemberNames()) {
                    quarantined_file.metadata[key] = root["metadata"][key].asString();
                }
            }

            // Restore notes
            if (root.isMember("restore_notes") && root["restore_notes"].isArray()) {
                for (const auto& note : root["restore_notes"]) {
                    quarantined_file.restore_notes.push_back(note.asString());
                }
            }

            return quarantined_file;
        }

        bool SaveFileMetadata(const QuarantinedFile& file_info) {
            try {
                std::filesystem::path metadata_path = config.metadata_directory / (file_info.quarantine_id + ".json");

                Json::Value root;
                root["quarantine_id"] = file_info.quarantine_id;
                root["original_path"] = file_info.original_path.string();
                root["quarantine_path"] = file_info.quarantine_path.string();
                root["original_hash"] = file_info.original_hash;
                root["quarantine_hash"] = file_info.quarantine_hash;
                root["original_size"] = static_cast<Json::UInt64>(file_info.original_size);
                root["quarantine_size"] = static_cast<Json::UInt64>(file_info.quarantine_size);

                root["status"] = Utils::QuarantineStatusToString(file_info.status);
                root["action"] = Utils::QuarantineActionToString(file_info.action);
                root["reason"] = Utils::QuarantineReasonToString(file_info.reason);

                root["quarantine_time"] = Utils::FormatTimestamp(file_info.quarantine_time);
                root["expiry_time"] = Utils::FormatTimestamp(file_info.expiry_time);

                root["encryption_algorithm"] = Utils::EncryptionAlgorithmToString(file_info.encryption_algorithm);
                root["compression_algorithm"] = Utils::CompressionAlgorithmToString(file_info.compression_algorithm);

                root["detection_engine"] = file_info.detection_engine;
                root["signature_name"] = file_info.signature_name;
                root["user_name"] = file_info.user_name;
                root["computer_name"] = file_info.computer_name;

                // Metadata
                if (!file_info.metadata.empty()) {
                    Json::Value metadata;
                    for (const auto& pair : file_info.metadata) {
                        metadata[pair.first] = pair.second;
                    }
                    root["metadata"] = metadata;
                }

                // Restore notes
                if (!file_info.restore_notes.empty()) {
                    Json::Value notes(Json::arrayValue);
                    for (const auto& note : file_info.restore_notes) {
                        notes.append(note);
                    }
                    root["restore_notes"] = notes;
                }

                std::ofstream file(metadata_path);
                Json::StreamWriterBuilder builder;
                std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
                writer->write(root, &file);

                return true;

            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Failed to save metadata: " + std::string(e.what()),
                                 file_info.quarantine_id);
                }
                return false;
            }
        }

        QuarantineResult PerformQuarantine(const std::filesystem::path& file_path,
                                          QuarantineReason reason,
                                          const std::string& detection_info,
                                          QuarantineAction action) {
            QuarantineResult result;
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                // Проверка существования файла
                if (!std::filesystem::exists(file_path)) {
                    result.error_message = "File does not exist: " + file_path.string();
                    return result;
                }

                // Проверка размера файла
                std::uintmax_t file_size = std::filesystem::file_size(file_path);
                if (file_size > config.max_file_size) {
                    result.error_message = "File too large: " + Utils::FormatFileSize(file_size);
                    return result;
                }

                // Создание записи о файле
                QuarantinedFile quarantined_file;
                quarantined_file.quarantine_id = Utils::GenerateQuarantineId();
                quarantined_file.original_path = file_path;
                quarantined_file.original_size = file_size;
                quarantined_file.status = QuarantineStatus::PENDING;
                quarantined_file.action = action;
                quarantined_file.reason = reason;
                quarantined_file.quarantine_time = std::chrono::system_clock::now();
                quarantined_file.expiry_time = quarantined_file.quarantine_time + config.default_retention_period;
                quarantined_file.encryption_algorithm = config.default_encryption;
                quarantined_file.compression_algorithm = config.default_compression;
                quarantined_file.detection_engine = detection_info;
                quarantined_file.user_name = Utils::GetCurrentUser();
                quarantined_file.computer_name = Utils::GetComputerName();

                // Вычисление хэша оригинального файла
                quarantined_file.original_hash = crypto_engine.CalculateFileHash(file_path);

                // Определение пути в карантине
                std::string quarantine_filename = quarantined_file.quarantine_id + ".qdat";
                quarantined_file.quarantine_path = config.quarantine_directory / quarantine_filename;

                // Выполнение операции карантина
                bool operation_success = false;
                switch (action) {
                    case QuarantineAction::MOVE:
                        operation_success = MoveFileToQuarantine(file_path, quarantined_file.quarantine_path);
                        break;
                    case QuarantineAction::COPY:
                        operation_success = CopyFileToQuarantine(file_path, quarantined_file.quarantine_path);
                        break;
                    case QuarantineAction::ENCRYPT:
                        operation_success = EncryptFileToQuarantine(file_path, quarantined_file);
                        break;
                    case QuarantineAction::COMPRESS:
                        operation_success = CompressFileToQuarantine(file_path, quarantined_file);
                        break;
                    case QuarantineAction::ENCRYPT_AND_COMPRESS:
                        operation_success = EncryptAndCompressFileToQuarantine(file_path, quarantined_file);
                        break;
                }

                if (!operation_success) {
                    result.error_message = "Failed to quarantine file";
                    return result;
                }

                // Обновление информации о размере после обработки
                if (std::filesystem::exists(quarantined_file.quarantine_path)) {
                    quarantined_file.quarantine_size = std::filesystem::file_size(quarantined_file.quarantine_path);
                    quarantined_file.quarantine_hash = crypto_engine.CalculateFileHash(quarantined_file.quarantine_path);
                }

                quarantined_file.status = QuarantineStatus::QUARANTINED;

                // Сохранение метаданных
                if (!SaveFileMetadata(quarantined_file)) {
                    result.error_message = "Failed to save metadata";
                    return result;
                }

                // Добавление в список
                {
                    std::lock_guard<std::mutex> lock(files_mutex);
                    quarantined_files.push_back(quarantined_file);
                    file_index[quarantined_file.quarantine_id] = quarantined_files.size() - 1;
                }

                // Обновление статистики
                UpdateStatisticsAfterQuarantine(quarantined_file);

                // Результат
                result.success = true;
                result.quarantine_id = quarantined_file.quarantine_id;
                result.quarantine_path = quarantined_file.quarantine_path;
                result.bytes_processed = file_size;

                if (quarantined_file.quarantine_size > 0) {
                    result.compression_ratio = compression_engine.CalculateCompressionRatio(
                        quarantined_file.original_size, quarantined_file.quarantine_size);
                }

                auto end_time = std::chrono::high_resolution_clock::now();
                result.operation_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                // Callback
                if (quarantine_callback) {
                    quarantine_callback(quarantined_file);
                }

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Exception during quarantine: " + std::string(e.what());
                return result;
            }
        }

        bool MoveFileToQuarantine(const std::filesystem::path& source, const std::filesystem::path& destination) {
            try {
                std::filesystem::rename(source, destination);
                return true;
            } catch (const std::exception&) {
                // Если rename не удался, пробуем copy + delete
                try {
                    std::filesystem::copy_file(source, destination);
                    if (config.secure_delete_original) {
                        Utils::SecureDeleteFile(source);
                    } else {
                        std::filesystem::remove(source);
                    }
                    return true;
                } catch (const std::exception&) {
                    return false;
                }
            }
        }

        bool CopyFileToQuarantine(const std::filesystem::path& source, const std::filesystem::path& destination) {
            try {
                std::filesystem::copy_file(source, destination);
                return true;
            } catch (const std::exception&) {
                return false;
            }
        }

        bool EncryptFileToQuarantine(const std::filesystem::path& source, QuarantinedFile& file_info) {
            try {
                bool success = crypto_engine.EncryptFile(source, file_info.quarantine_path,
                                                        config.encryption_password,
                                                        file_info.encryption_algorithm);

                if (success && file_info.action == QuarantineAction::ENCRYPT) {
                    if (config.secure_delete_original) {
                        Utils::SecureDeleteFile(source);
                    } else {
                        std::filesystem::remove(source);
                    }
                }

                return success;
            } catch (const std::exception&) {
                return false;
            }
        }

        bool CompressFileToQuarantine(const std::filesystem::path& source, QuarantinedFile& file_info) {
            try {
                bool success = compression_engine.CompressFile(source, file_info.quarantine_path,
                                                             file_info.compression_algorithm,
                                                             config.compression_level);

                if (success && file_info.action == QuarantineAction::COMPRESS) {
                    if (config.secure_delete_original) {
                        Utils::SecureDeleteFile(source);
                    } else {
                        std::filesystem::remove(source);
                    }
                }

                return success;
            } catch (const std::exception&) {
                return false;
            }
        }

        bool EncryptAndCompressFileToQuarantine(const std::filesystem::path& source, QuarantinedFile& file_info) {
            try {
                // Сначала сжимаем во временный файл
                std::filesystem::path temp_compressed = Utils::CreateTempFile(config.temp_directory);

                bool compress_success = compression_engine.CompressFile(source, temp_compressed,
                                                                       file_info.compression_algorithm,
                                                                       config.compression_level);
                if (!compress_success) {
                    std::filesystem::remove(temp_compressed);
                    return false;
                }

                // Затем шифруем сжатый файл
                bool encrypt_success = crypto_engine.EncryptFile(temp_compressed, file_info.quarantine_path,
                                                               config.encryption_password,
                                                               file_info.encryption_algorithm);

                // Удаляем временный файл
                std::filesystem::remove(temp_compressed);

                if (encrypt_success) {
                    if (config.secure_delete_original) {
                        Utils::SecureDeleteFile(source);
                    } else {
                        std::filesystem::remove(source);
                    }
                }

                return encrypt_success;
            } catch (const std::exception&) {
                return false;
            }
        }

        void UpdateStatistics() {
            std::lock_guard<std::mutex> lock(stats_mutex);
            statistics = QuarantineStatistics{};

            for (const auto& file : quarantined_files) {
                statistics.total_files++;
                statistics.total_size += file.original_size;
                statistics.compressed_size += file.quarantine_size;

                switch (file.status) {
                    case QuarantineStatus::QUARANTINED:
                        statistics.active_files++;
                        break;
                    case QuarantineStatus::RESTORED:
                        statistics.restored_files++;
                        break;
                    case QuarantineStatus::PERMANENTLY_DELETED:
                        statistics.deleted_files++;
                        break;
                    case QuarantineStatus::FAILED:
                        statistics.failed_operations++;
                        break;
                    default:
                        break;
                }

                statistics.reason_counts[file.reason]++;
                if (!file.detection_engine.empty()) {
                    statistics.detection_engine_counts[file.detection_engine]++;
                }
            }

            if (statistics.total_size > 0) {
                statistics.compression_ratio = compression_engine.CalculateCompressionRatio(
                    statistics.total_size, statistics.compressed_size);
            }
        }

        void UpdateStatisticsAfterQuarantine(const QuarantinedFile& file) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            statistics.total_files++;
            statistics.active_files++;
            statistics.total_size += file.original_size;
            statistics.compressed_size += file.quarantine_size;
            statistics.last_quarantine_time = file.quarantine_time;
            statistics.reason_counts[file.reason]++;

            if (!file.detection_engine.empty()) {
                statistics.detection_engine_counts[file.detection_engine]++;
            }

            if (statistics.total_size > 0) {
                statistics.compression_ratio = compression_engine.CalculateCompressionRatio(
                    statistics.total_size, statistics.compressed_size);
            }
        }
    };

    // Реализация CryptoEngine::Impl
    class CryptoEngine::Impl {
    public:
        std::random_device rd;
        std::mt19937 gen{rd()};

        std::vector<uint8_t> EncryptAES256CBC(const std::vector<uint8_t>& data,
                                             const std::string& password) {
            // Генерация соли и IV
            std::vector<uint8_t> salt(16);
            std::vector<uint8_t> iv(16);
            RAND_bytes(salt.data(), salt.size());
            RAND_bytes(iv.data(), iv.size());

            // Вывод ключа из пароля
            std::vector<uint8_t> key(32);
            PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                             salt.data(), salt.size(),
                             10000, EVP_sha256(),
                             key.size(), key.data());

            // Шифрование
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("Failed to create cipher context");

            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize encryption");
            }

            std::vector<uint8_t> ciphertext;
            ciphertext.reserve(data.size() + 32); // Запас для padding

            int len;
            int ciphertext_len = 0;

            // Добавляем соль и IV в начало
            ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());
            ciphertext.insert(ciphertext.end(), iv.begin(), iv.end());

            // Шифруем данные блоками
            const int block_size = 4096;
            std::vector<uint8_t> output_buffer(block_size + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

            for (std::size_t i = 0; i < data.size(); i += block_size) {
                std::size_t chunk_size = std::min(block_size, data.size() - i);

                if (EVP_EncryptUpdate(ctx, output_buffer.data(), &len,
                                     data.data() + i, chunk_size) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to encrypt data");
                }

                ciphertext.insert(ciphertext.end(), output_buffer.begin(), output_buffer.begin() + len);
                ciphertext_len += len;
            }

            // Финализация
            if (EVP_EncryptFinal_ex(ctx, output_buffer.data(), &len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize encryption");
            }

            ciphertext.insert(ciphertext.end(), output_buffer.begin(), output_buffer.begin() + len);
            ciphertext_len += len;

            EVP_CIPHER_CTX_free(ctx);
            return ciphertext;
        }

        std::vector<uint8_t> DecryptAES256CBC(const std::vector<uint8_t>& encrypted_data,
                                             const std::string& password) {
            if (encrypted_data.size() < 32) {
                throw std::runtime_error("Invalid encrypted data size");
            }

            // Извлечение соли и IV
            std::vector<uint8_t> salt(encrypted_data.begin(), encrypted_data.begin() + 16);
            std::vector<uint8_t> iv(encrypted_data.begin() + 16, encrypted_data.begin() + 32);

            // Вывод ключа из пароля
            std::vector<uint8_t> key(32);
            PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                             salt.data(), salt.size(),
                             10000, EVP_sha256(),
                             key.size(), key.data());

            // Расшифровка
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("Failed to create cipher context");

            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize decryption");
            }

            std::vector<uint8_t> plaintext;
            std::vector<uint8_t> ciphertext(encrypted_data.begin() + 32, encrypted_data.end());
            plaintext.reserve(ciphertext.size());

            int len;
            int plaintext_len = 0;

            // Расшифровываем данные блоками
            const int block_size = 4096;
            std::vector<uint8_t> output_buffer(block_size + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

            for (std::size_t i = 0; i < ciphertext.size(); i += block_size) {
                std::size_t chunk_size = std::min(block_size, ciphertext.size() - i);

                if (EVP_DecryptUpdate(ctx, output_buffer.data(), &len,
                                     ciphertext.data() + i, chunk_size) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to decrypt data");
                }

                plaintext.insert(plaintext.end(), output_buffer.begin(), output_buffer.begin() + len);
                plaintext_len += len;
            }

            // Финализация
            if (EVP_DecryptFinal_ex(ctx, output_buffer.data(), &len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize decryption");
            }

            plaintext.insert(plaintext.end(), output_buffer.begin(), output_buffer.begin() + len);
            plaintext_len += len;

            EVP_CIPHER_CTX_free(ctx);
            return plaintext;
        }
    };

    // Реализация CompressionEngine::Impl
    class CompressionEngine::Impl {
    public:
        std::vector<uint8_t> CompressZlib(const std::vector<uint8_t>& data, int level) {
            z_stream stream{};

            if (deflateInit(&stream, level) != Z_OK) {
                throw std::runtime_error("Failed to initialize zlib compression");
            }

            stream.next_in = const_cast<Bytef*>(data.data());
            stream.avail_in = data.size();

            std::vector<uint8_t> compressed;
            compressed.reserve(data.size() / 2); // Предварительная оценка

            const int chunk_size = 4096;
            std::vector<uint8_t> output_buffer(chunk_size);

            int flush = Z_FINISH;
            do {
                stream.next_out = output_buffer.data();
                stream.avail_out = chunk_size;

                int ret = deflate(&stream, flush);
                if (ret == Z_STREAM_ERROR) {
                    deflateEnd(&stream);
                    throw std::runtime_error("Zlib compression error");
                }

                int compressed_size = chunk_size - stream.avail_out;
                compressed.insert(compressed.end(), output_buffer.begin(),
                                output_buffer.begin() + compressed_size);

            } while (stream.avail_out == 0);

            deflateEnd(&stream);
            return compressed;
        }

        std::vector<uint8_t> DecompressZlib(const std::vector<uint8_t>& compressed_data) {
            z_stream stream{};

            if (inflateInit(&stream) != Z_OK) {
                throw std::runtime_error("Failed to initialize zlib decompression");
            }

            stream.next_in = const_cast<Bytef*>(compressed_data.data());
            stream.avail_in = compressed_data.size();

            std::vector<uint8_t> decompressed;

            const int chunk_size = 4096;
            std::vector<uint8_t> output_buffer(chunk_size);

            int ret;
            do {
                stream.next_out = output_buffer.data();
                stream.avail_out = chunk_size;

                ret = inflate(&stream, Z_NO_FLUSH);
                if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                    inflateEnd(&stream);
                    throw std::runtime_error("Zlib decompression error");
                }

                int decompressed_size = chunk_size - stream.avail_out;
                decompressed.insert(decompressed.end(), output_buffer.begin(),
                                  output_buffer.begin() + decompressed_size);

            } while (stream.avail_out == 0);

            inflateEnd(&stream);
            return decompressed;
        }
    };

    // Реализация основных классов

    // QuarantineManager
    QuarantineManager::QuarantineManager() : pImpl(std::make_unique<Impl>()) {}

    QuarantineManager::QuarantineManager(const QuarantineConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    QuarantineManager::~QuarantineManager() = default;

    bool QuarantineManager::Initialize() {
        if (pImpl->initialized) {
            return true;
        }

        if (!pImpl->InitializeDirectories()) {
            return false;
        }

        if (!pImpl->LoadMetadata()) {
            return false;
        }

        pImpl->initialized = true;
        return true;
    }

    void QuarantineManager::Shutdown() {
        pImpl->initialized = false;
    }

    bool QuarantineManager::IsInitialized() const {
        return pImpl->initialized;
    }

    QuarantineResult QuarantineManager::QuarantineFile(const std::filesystem::path& file_path,
                                                      QuarantineReason reason,
                                                      const std::string& detection_info,
                                                      QuarantineAction action) {
        if (!pImpl->initialized) {
            QuarantineResult result;
            result.error_message = "Quarantine manager not initialized";
            return result;
        }

        return pImpl->PerformQuarantine(file_path, reason, detection_info, action);
    }

    std::vector<QuarantinedFile> QuarantineManager::GetQuarantinedFiles() const {
        std::lock_guard<std::mutex> lock(pImpl->files_mutex);
        return pImpl->quarantined_files;
    }

    QuarantineStatistics QuarantineManager::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    // CryptoEngine
    CryptoEngine::CryptoEngine() : pImpl(std::make_unique<Impl>()) {}
    CryptoEngine::~CryptoEngine() = default;

    std::vector<uint8_t> CryptoEngine::Encrypt(const std::vector<uint8_t>& data,
                                              const std::string& password,
                                              EncryptionAlgorithm algorithm) {
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256_CBC:
                return pImpl->EncryptAES256CBC(data, password);
            default:
                throw std::invalid_argument("Unsupported encryption algorithm");
        }
    }

    std::vector<uint8_t> CryptoEngine::Decrypt(const std::vector<uint8_t>& encrypted_data,
                                              const std::string& password,
                                              EncryptionAlgorithm algorithm) {
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256_CBC:
                return pImpl->DecryptAES256CBC(encrypted_data, password);
            default:
                throw std::invalid_argument("Unsupported encryption algorithm");
        }
    }

    bool CryptoEngine::EncryptFile(const std::filesystem::path& input_path,
                                  const std::filesystem::path& output_path,
                                  const std::string& password,
                                  EncryptionAlgorithm algorithm) {
        try {
            std::ifstream input(input_path, std::ios::binary);
            if (!input.is_open()) return false;

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)),
                                     std::istreambuf_iterator<char>());

            auto encrypted = Encrypt(data, password, algorithm);

            std::ofstream output(output_path, std::ios::binary);
            if (!output.is_open()) return false;

            output.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
            return output.good();

        } catch (const std::exception&) {
            return false;
        }
    }

    std::string CryptoEngine::GeneratePassword(std::size_t length) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        std::uniform_int_distribution<> dis(0, chars.size() - 1);

        std::string password;
        password.reserve(length);

        for (std::size_t i = 0; i < length; ++i) {
            password += chars[dis(pImpl->gen)];
        }

        return password;
    }

    std::string CryptoEngine::CalculateFileHash(const std::filesystem::path& file_path, const std::string& algorithm) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file for hashing");
        }

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());

        return CalculateHash(buffer, algorithm);
    }

    std::string CryptoEngine::CalculateHash(const std::vector<uint8_t>& data, const std::string& algorithm) {
        if (algorithm == "SHA256") {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(data.data(), data.size(), hash);

            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        throw std::invalid_argument("Unsupported hash algorithm");
    }

    // CompressionEngine
    CompressionEngine::CompressionEngine() : pImpl(std::make_unique<Impl>()) {}
    CompressionEngine::~CompressionEngine() = default;

    std::vector<uint8_t> CompressionEngine::Compress(const std::vector<uint8_t>& data,
                                                     CompressionAlgorithm algorithm,
                                                     int level) {
        switch (algorithm) {
            case CompressionAlgorithm::ZLIB:
                return pImpl->CompressZlib(data, level);
            default:
                throw std::invalid_argument("Unsupported compression algorithm");
        }
    }

    std::vector<uint8_t> CompressionEngine::Decompress(const std::vector<uint8_t>& compressed_data,
                                                       CompressionAlgorithm algorithm) {
        switch (algorithm) {
            case CompressionAlgorithm::ZLIB:
                return pImpl->DecompressZlib(compressed_data);
            default:
                throw std::invalid_argument("Unsupported compression algorithm");
        }
    }

    bool CompressionEngine::CompressFile(const std::filesystem::path& input_path,
                                        const std::filesystem::path& output_path,
                                        CompressionAlgorithm algorithm,
                                        int level) {
        try {
            std::ifstream input(input_path, std::ios::binary);
            if (!input.is_open()) return false;

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)),
                                     std::istreambuf_iterator<char>());

            auto compressed = Compress(data, algorithm, level);

            std::ofstream output(output_path, std::ios::binary);
            if (!output.is_open()) return false;

            output.write(reinterpret_cast<const char*>(compressed.data()), compressed.size());
            return output.good();

        } catch (const std::exception&) {
            return false;
        }
    }

    double CompressionEngine::CalculateCompressionRatio(std::uintmax_t original_size, std::uintmax_t compressed_size) {
        if (original_size == 0) return 0.0;
        return (1.0 - static_cast<double>(compressed_size) / static_cast<double>(original_size)) * 100.0;
    }

    // Утилитарные функции
    namespace Utils {

        std::string QuarantineActionToString(QuarantineAction action) {
            switch (action) {
                case QuarantineAction::MOVE: return "move";
                case QuarantineAction::COPY: return "copy";
                case QuarantineAction::ENCRYPT: return "encrypt";
                case QuarantineAction::COMPRESS: return "compress";
                case QuarantineAction::ENCRYPT_AND_COMPRESS: return "encrypt_and_compress";
                default: return "unknown";
            }
        }

        QuarantineAction StringToQuarantineAction(const std::string& action_str) {
            if (action_str == "move") return QuarantineAction::MOVE;
            if (action_str == "copy") return QuarantineAction::COPY;
            if (action_str == "encrypt") return QuarantineAction::ENCRYPT;
            if (action_str == "compress") return QuarantineAction::COMPRESS;
            if (action_str == "encrypt_and_compress") return QuarantineAction::ENCRYPT_AND_COMPRESS;
            return QuarantineAction::MOVE;
        }

        std::string QuarantineStatusToString(QuarantineStatus status) {
            switch (status) {
                case QuarantineStatus::PENDING: return "pending";
                case QuarantineStatus::QUARANTINED: return "quarantined";
                case QuarantineStatus::RESTORED: return "restored";
                case QuarantineStatus::PERMANENTLY_DELETED: return "permanently_deleted";
                case QuarantineStatus::FAILED: return "failed";
                default: return "unknown";
            }
        }

        std::string GenerateQuarantineId() {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            ss << "Q";

            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            ss << std::hex << time_t;

            for (int i = 0; i < 16; ++i) {
                ss << std::hex << dis(gen);
            }

            return ss.str();
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

        bool SecureDeleteFile(const std::filesystem::path& file_path, int passes) {
            try {
                std::uintmax_t file_size = std::filesystem::file_size(file_path);
                std::fstream file(file_path, std::ios::binary | std::ios::in | std::ios::out);

                if (!file.is_open()) return false;

                std::vector<uint8_t> random_data(4096);
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dis(0, 255);

                for (int pass = 0; pass < passes; ++pass) {
                    file.seekp(0);

                    for (std::uintmax_t written = 0; written < file_size; written += random_data.size()) {
                        std::size_t write_size = std::min(random_data.size(),
                                                         static_cast<std::size_t>(file_size - written));

                        for (std::size_t i = 0; i < write_size; ++i) {
                            random_data[i] = dis(gen);
                        }

                        file.write(reinterpret_cast<const char*>(random_data.data()), write_size);
                    }

                    file.flush();
                }

                file.close();
                return std::filesystem::remove(file_path);

            } catch (const std::exception&) {
                return false;
            }
        }

        std::filesystem::path CreateTempFile(const std::filesystem::path& directory) {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            ss << "temp_";

            for (int i = 0; i < 16; ++i) {
                ss << std::hex << dis(gen);
            }

            ss << ".tmp";
            return directory / ss.str();
        }

        std::string GetCurrentUser() {
#ifdef _WIN32
            char username[UNLEN + 1];
            DWORD username_len = sizeof(username);
            if (GetUserNameA(username, &username_len)) {
                return std::string(username);
            }
            return "unknown";
#else
            const char* username = getpwuid(getuid())->pw_name;
            return username ? username : "unknown";
#endif
        }

        std::string GetComputerName() {
#ifdef _WIN32
            char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = sizeof(computer_name);
            if (GetComputerNameA(computer_name, &size)) {
                return std::string(computer_name);
            }
            return "unknown";
#else
            struct utsname uts;
            if (uname(&uts) == 0) {
                return std::string(uts.nodename);
            }
            return "unknown";
#endif
        }

        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp) {
            std::tm tm = {};
            std::istringstream ss(timestamp);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& time_point) {
            auto time_t = std::chrono::system_clock::to_time_t(time_point);
            std::tm* tm = std::gmtime(&time_t);

            std::stringstream ss;
            ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
            return ss.str();
        }
    }
}