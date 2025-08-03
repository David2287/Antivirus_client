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
#include <future>
#include <optional>
#include <unordered_map>
#include <queue>

// HTTP/HTTPS клиент
#include "network_client.h"

// Аутентификация
#include "auth_state.h"

// JSON для конфигурации
#include <json/json.h>

namespace Updater {

    // Типы обновлений
    enum class UpdateType {
        VIRUS_SIGNATURES,
        ENGINE_UPDATE,
        CONFIGURATION_UPDATE,
        MODULE_UPDATE,
        PLUGIN_UPDATE,
        BLACKLIST_UPDATE,
        WHITELIST_UPDATE,
        HEURISTIC_RULES,
        CUSTOM_RULES
    };

    // Статус обновления
    enum class UpdateStatus {
        NONE,
        CHECKING,
        AVAILABLE,
        DOWNLOADING,
        VERIFYING,
        INSTALLING,
        COMPLETED,
        FAILED,
        CANCELLED,
        ROLLBACK
    };

    // Приоритет обновления
    enum class UpdatePriority {
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        CRITICAL = 4,
        EMERGENCY = 5
    };

    // Канал обновлений
    enum class UpdateChannel {
        STABLE,
        BETA,
        ALPHA,
        EXPERIMENTAL,
        CUSTOM
    };

    // Информация о версии
    struct VersionInfo {
        int major;
        int minor;
        int patch;
        int build;
        std::string pre_release;
        std::string metadata;

        VersionInfo() : major(0), minor(0), patch(0), build(0) {}

        VersionInfo(int maj, int min, int p, int b = 0)
            : major(maj), minor(min), patch(p), build(b) {}

        std::string ToString() const {
            std::string version = std::to_string(major) + "." +
                                 std::to_string(minor) + "." +
                                 std::to_string(patch);
            if (build > 0) {
                version += "." + std::to_string(build);
            }
            if (!pre_release.empty()) {
                version += "-" + pre_release;
            }
            if (!metadata.empty()) {
                version += "+" + metadata;
            }
            return version;
        }

        bool operator<(const VersionInfo& other) const {
            if (major != other.major) return major < other.major;
            if (minor != other.minor) return minor < other.minor;
            if (patch != other.patch) return patch < other.patch;
            if (build != other.build) return build < other.build;
            return pre_release < other.pre_release;
        }

        bool operator==(const VersionInfo& other) const {
            return major == other.major && minor == other.minor &&
                   patch == other.patch && build == other.build &&
                   pre_release == other.pre_release;
        }

        bool operator>(const VersionInfo& other) const {
            return other < *this;
        }
    };

    // Информация об обновлении
    struct UpdateInfo {
        std::string update_id;
        UpdateType type;
        UpdatePriority priority;
        UpdateChannel channel;

        VersionInfo current_version;
        VersionInfo available_version;

        std::string title;
        std::string description;
        std::string changelog;
        std::string release_notes;

        std::string download_url;
        std::string signature_url;
        std::string checksum_url;

        std::uint64_t file_size;
        std::string sha256_hash;
        std::string signature_hash;

        std::chrono::system_clock::time_point release_date;
        std::chrono::system_clock::time_point expires_at;

        bool requires_restart;
        bool critical_update;
        bool security_update;

        std::vector<std::string> dependencies;
        std::vector<std::string> conflicts;

        std::unordered_map<std::string, std::string> metadata;

        UpdateInfo() : type(UpdateType::VIRUS_SIGNATURES),
                      priority(UpdatePriority::NORMAL),
                      channel(UpdateChannel::STABLE),
                      file_size(0),
                      requires_restart(false),
                      critical_update(false),
                      security_update(false) {
            release_date = std::chrono::system_clock::now();
            expires_at = release_date + std::chrono::hours{24 * 30}; // 30 дней
        }
    };

    // Результат операции обновления
    struct UpdateResult {
        bool success;
        std::string error_message;
        std::string error_code;
        UpdateStatus final_status;
        std::chrono::milliseconds operation_time{0};
        std::uint64_t bytes_downloaded;

        UpdateResult() : success(false), final_status(UpdateStatus::NONE), bytes_downloaded(0) {}
    };

    // Конфигурация обновлений
    struct UpdaterConfig {
        // Серверы обновлений
        std::vector<std::string> update_servers = {
            "https://updates.antivirus.com/api/v1",
            "https://backup-updates.antivirus.com/api/v1"
        };

        // Аутентификация
        std::string api_key;
        std::string client_id;
        std::string client_secret;

        // Планировщик
        bool auto_check_enabled = true;
        std::chrono::minutes check_interval{60}; // Каждый час
        std::chrono::hours scheduled_time{2};    // 02:00
        bool check_on_startup = true;

        // Каналы обновлений
        UpdateChannel default_channel = UpdateChannel::STABLE;
        bool allow_beta_updates = false;
        bool allow_experimental = false;

        // Загрузка
        std::filesystem::path download_directory;
        std::filesystem::path cache_directory;
        std::uint64_t max_cache_size = 1024 * 1024 * 1024; // 1GB
        int max_concurrent_downloads = 3;
        std::chrono::seconds download_timeout{300};

        // Верификация
        bool verify_signatures = true;
        bool verify_checksums = true;
        std::filesystem::path trusted_ca_path;

        // Установка
        bool auto_install_critical = true;
        bool auto_install_security = true;
        bool backup_before_install = true;
        std::filesystem::path backup_directory;
        int max_backup_versions = 5;

        // Сеть
        std::string proxy_server;
        int proxy_port = 0;
        std::string proxy_username;
        std::string proxy_password;

        // Ограничения
        std::chrono::hours maintenance_window_start{1};
        std::chrono::hours maintenance_window_end{5};
        bool respect_metered_connection = true;
        std::uint64_t bandwidth_limit_kbps = 0; // 0 = без ограничений

        UpdaterConfig() {
            download_directory = std::filesystem::temp_directory_path() / "antivirus_updates";
            cache_directory = std::filesystem::temp_directory_path() / "antivirus_cache";
            backup_directory = std::filesystem::temp_directory_path() / "antivirus_backups";
            trusted_ca_path = std::filesystem::current_path() / "certs" / "ca.pem";
        }
    };

    // Статистика обновлений
    struct UpdaterStatistics {
        std::atomic<std::uint64_t> total_checks{0};
        std::atomic<std::uint64_t> updates_found{0};
        std::atomic<std::uint64_t> updates_downloaded{0};
        std::atomic<std::uint64_t> updates_installed{0};
        std::atomic<std::uint64_t> updates_failed{0};

        std::chrono::system_clock::time_point last_check_time;
        std::chrono::system_clock::time_point last_update_time;

        std::unordered_map<UpdateType, std::uint64_t> update_type_counts;
        std::uint64_t total_bytes_downloaded{0};
        std::chrono::milliseconds average_download_time{0};

        void Reset() {
            total_checks = 0;
            updates_found = 0;
            updates_downloaded = 0;
            updates_installed = 0;
            updates_failed = 0;
            update_type_counts.clear();
            total_bytes_downloaded = 0;
            average_download_time = std::chrono::milliseconds{0};
        }
    };

    // Forward declarations
    class UpdateChecker;
    class UpdateDownloader;
    class UpdateInstaller;
    class UpdateVerifier;

    // Callback типы
    using UpdateAvailableCallback = std::function<void(const UpdateInfo& update_info)>;
    using DownloadProgressCallback = std::function<void(const std::string& update_id, std::uint64_t downloaded, std::uint64_t total)>;
    using UpdateStatusCallback = std::function<void(const std::string& update_id, UpdateStatus status, const std::string& message)>;
    using UpdateCompletedCallback = std::function<void(const std::string& update_id, const UpdateResult& result)>;

    // Основной класс управления обновлениями
    class UpdateManager {
    public:
        explicit UpdateManager(const UpdaterConfig& config = UpdaterConfig{});
        ~UpdateManager();

        // Инициализация и управление
        bool Initialize();
        void Shutdown();
        bool IsRunning() const;

        // Конфигурация
        void SetConfig(const UpdaterConfig& config);
        const UpdaterConfig& GetConfig() const;

        // Аутентификация
        void SetAuthManager(std::shared_ptr<AuthState::AuthStateManager> auth_manager);

        // Проверка обновлений
        std::vector<UpdateInfo> CheckForUpdates();
        std::future<std::vector<UpdateInfo>> CheckForUpdatesAsync();
        std::vector<UpdateInfo> CheckForUpdates(UpdateType type);
        std::vector<UpdateInfo> CheckForUpdates(const std::vector<UpdateType>& types);

        // Управление обновлениями
        std::string ScheduleUpdate(const UpdateInfo& update_info);
        UpdateResult DownloadUpdate(const std::string& update_id);
        UpdateResult InstallUpdate(const std::string& update_id);
        UpdateResult DownloadAndInstallUpdate(const std::string& update_id);

        // Асинхронные операции
        std::future<UpdateResult> DownloadUpdateAsync(const std::string& update_id);
        std::future<UpdateResult> InstallUpdateAsync(const std::string& update_id);
        std::future<UpdateResult> DownloadAndInstallUpdateAsync(const std::string& update_id);

        // Отмена операций
        bool CancelUpdate(const std::string& update_id);
        void CancelAllUpdates();

        // Получение информации
        std::vector<UpdateInfo> GetPendingUpdates() const;
        std::vector<UpdateInfo> GetAvailableUpdates() const;
        std::optional<UpdateInfo> GetUpdateInfo(const std::string& update_id) const;
        UpdateStatus GetUpdateStatus(const std::string& update_id) const;

        // Версии
        VersionInfo GetCurrentVersion(UpdateType type) const;
        void SetCurrentVersion(UpdateType type, const VersionInfo& version);
        std::unordered_map<UpdateType, VersionInfo> GetAllVersions() const;

        // Автоматические обновления
        void EnableAutoUpdates(bool enabled);
        bool IsAutoUpdatesEnabled() const;
        void SetAutoUpdateTypes(const std::vector<UpdateType>& types);

        // Планировщик
        void StartScheduler();
        void StopScheduler();
        void SetSchedule(std::chrono::minutes interval);
        std::chrono::system_clock::time_point GetNextScheduledCheck() const;

        // Callbacks
        void SetUpdateAvailableCallback(UpdateAvailableCallback callback);
        void SetDownloadProgressCallback(DownloadProgressCallback callback);
        void SetUpdateStatusCallback(UpdateStatusCallback callback);
        void SetUpdateCompletedCallback(UpdateCompletedCallback callback);

        // Управление кэшем
        void ClearCache();
        std::uint64_t GetCacheSize() const;
        void CleanupExpiredCache();

        // Статистика
        UpdaterStatistics GetStatistics() const;
        void ResetStatistics();

        // Откат обновлений
        bool CanRollback(const std::string& update_id) const;
        UpdateResult RollbackUpdate(const std::string& update_id);
        std::vector<std::string> GetRollbackableUpdates() const;

        // Резервное копирование
        bool CreateBackup(UpdateType type);
        bool RestoreBackup(UpdateType type, const std::string& backup_id);
        std::vector<std::string> GetAvailableBackups(UpdateType type) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Проверщик обновлений
    class UpdateChecker {
    public:
        explicit UpdateChecker(const UpdaterConfig& config);
        ~UpdateChecker();

        std::vector<UpdateInfo> CheckUpdates(const std::vector<UpdateType>& types);
        std::vector<UpdateInfo> CheckUpdatesFromServer(const std::string& server_url,
                                                      const std::vector<UpdateType>& types);

        bool ValidateUpdateInfo(const UpdateInfo& update_info) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Загрузчик обновлений
    class UpdateDownloader {
    public:
        explicit UpdateDownloader(const UpdaterConfig& config);
        ~UpdateDownloader();

        UpdateResult DownloadUpdate(const UpdateInfo& update_info,
                                   DownloadProgressCallback progress_callback = nullptr);

        bool ResumeDownload(const std::string& update_id);
        void CancelDownload(const std::string& update_id);

        std::uint64_t GetDownloadedSize(const std::string& update_id) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Верификатор обновлений
    class UpdateVerifier {
    public:
        explicit UpdateVerifier(const UpdaterConfig& config);
        ~UpdateVerifier();

        bool VerifyChecksum(const std::filesystem::path& file_path, const std::string& expected_hash);
        bool VerifySignature(const std::filesystem::path& file_path, const std::string& signature);
        bool VerifyUpdate(const UpdateInfo& update_info, const std::filesystem::path& file_path);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Установщик обновлений
    class UpdateInstaller {
    public:
        explicit UpdateInstaller(const UpdaterConfig& config);
        ~UpdateInstaller();

        UpdateResult InstallUpdate(const UpdateInfo& update_info,
                                  const std::filesystem::path& file_path);

        bool RequiresRestart(const UpdateInfo& update_info) const;
        bool CreateBackup(const UpdateInfo& update_info);
        UpdateResult RollbackUpdate(const std::string& update_id);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        // Конвертация типов
        std::string UpdateTypeToString(UpdateType type);
        UpdateType StringToUpdateType(const std::string& type_str);

        std::string UpdateStatusToString(UpdateStatus status);
        UpdateStatus StringToUpdateStatus(const std::string& status_str);

        std::string UpdatePriorityToString(UpdatePriority priority);
        UpdatePriority StringToUpdatePriority(const std::string& priority_str);

        std::string UpdateChannelToString(UpdateChannel channel);
        UpdateChannel StringToUpdateChannel(const std::string& channel_str);

        // Версии
        VersionInfo ParseVersion(const std::string& version_str);
        bool IsVersionNewer(const VersionInfo& current, const VersionInfo& available);

        // Файлы
        std::string CalculateFileHash(const std::filesystem::path& file_path);
        bool VerifyFileIntegrity(const std::filesystem::path& file_path, const std::string& expected_hash);
        std::uint64_t GetFileSize(const std::filesystem::path& file_path);

        // Сеть
        bool IsUpdateServerReachable(const std::string& server_url);
        bool IsNetworkMetered();
        std::uint64_t GetAvailableBandwidth();

        // Время
        std::string FormatDateTime(const std::chrono::system_clock::time_point& time_point);
        bool IsInMaintenanceWindow(const UpdaterConfig& config);

        // ID генерация
        std::string GenerateUpdateId();

        // JSON сериализация
        Json::Value UpdateInfoToJson(const UpdateInfo& update_info);
        UpdateInfo JsonToUpdateInfo(const Json::Value& json);

        Json::Value VersionInfoToJson(const VersionInfo& version);
        VersionInfo JsonToVersionInfo(const Json::Value& json);
    }
}