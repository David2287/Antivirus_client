//
// Created by WhySkyDie on 21.07.2025.
//

#include "updater.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace Updater {

    // ============================================================================
    // UpdateManager::Impl
    // ============================================================================

    class UpdateManager::Impl {
    public:
        UpdaterConfig config;
        std::atomic<bool> running{false};
        std::atomic<bool> auto_updates_enabled{true};

        // Компоненты
        std::unique_ptr<UpdateChecker> checker;
        std::unique_ptr<UpdateDownloader> downloader;
        std::unique_ptr<UpdateVerifier> verifier;
        std::unique_ptr<UpdateInstaller> installer;

        // Состояние
        std::unordered_map<UpdateType, VersionInfo> current_versions;
        std::unordered_map<std::string, UpdateInfo> available_updates;
        std::unordered_map<std::string, UpdateStatus> update_statuses;
        std::unordered_map<std::string, std::future<UpdateResult>> pending_operations;

        // Синхронизация
        mutable std::mutex versions_mutex;
        mutable std::mutex updates_mutex;
        mutable std::mutex operations_mutex;

        // Планировщик
        std::thread scheduler_thread;
        std::atomic<bool> scheduler_running{false};
        std::chrono::system_clock::time_point next_scheduled_check;

        // Callbacks
        UpdateAvailableCallback update_available_callback;
        DownloadProgressCallback download_progress_callback;
        UpdateStatusCallback update_status_callback;
        UpdateCompletedCallback update_completed_callback;

        // Сетевой клиент и аутентификация
        std::shared_ptr<NetworkClient::TLSHttpClient> http_client;
        std::shared_ptr<AuthState::AuthStateManager> auth_manager;

        // Статистика
        mutable std::mutex stats_mutex;
        UpdaterStatistics statistics;

        Impl() {
            InitializeComponents();
        }

        ~Impl() {
            Shutdown();
        }

        void InitializeComponents() {
            checker = std::make_unique<UpdateChecker>(config);
            downloader = std::make_unique<UpdateDownloader>(config);
            verifier = std::make_unique<UpdateVerifier>(config);
            installer = std::make_unique<UpdateInstaller>(config);

            // Создание HTTP клиента
            NetworkClient::ClientConfig net_config;
            net_config.server_host = ExtractHost(config.update_servers.front());
            net_config.server_port = 443;
            net_config.connection_type = NetworkClient::ConnectionType::HTTPS;
            net_config.tls_config.verify_peer = true;

            http_client = std::make_shared<NetworkClient::TLSHttpClient>(net_config);
        }

        bool Initialize() {
            if (running.load()) {
                return true;
            }

            try {
                // Создание директорий
                std::filesystem::create_directories(config.download_directory);
                std::filesystem::create_directories(config.cache_directory);
                std::filesystem::create_directories(config.backup_directory);

                // Подключение HTTP клиента
                if (!http_client->Connect()) {
                    throw std::runtime_error("Failed to connect to update server");
                }

                // Загрузка текущих версий
                LoadCurrentVersions();

                running = true;

                // Запуск планировщика если включен
                if (config.auto_check_enabled) {
                    StartScheduler();
                }

                // Проверка при старте если настроена
                if (config.check_on_startup) {
                    std::thread([this]() {
                        std::this_thread::sleep_for(std::chrono::seconds{5});
                        CheckForUpdatesAsync();
                    }).detach();
                }

                return true;

            } catch (const std::exception& e) {
                running = false;
                return false;
            }
        }

        void Shutdown() {
            if (!running.load()) {
                return;
            }

            running = false;

            // Остановка планировщика
            StopScheduler();

            // Отмена всех операций
            CancelAllUpdates();

            // Сохранение текущих версий
            SaveCurrentVersions();

            // Отключение HTTP клиента
            if (http_client) {
                http_client->Disconnect();
            }
        }

        std::vector<UpdateInfo> CheckForUpdatesImpl() {
            std::vector<UpdateInfo> all_updates;

            std::vector<UpdateType> types_to_check = {
                UpdateType::VIRUS_SIGNATURES,
                UpdateType::ENGINE_UPDATE,
                UpdateType::CONFIGURATION_UPDATE,
                UpdateType::MODULE_UPDATE
            };

            try {
                // Обновление статистики
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    statistics.total_checks++;
                    statistics.last_check_time = std::chrono::system_clock::now();
                }

                // Проверка каждого сервера
                for (const auto& server : config.update_servers) {
                    try {
                        auto updates = checker->CheckUpdatesFromServer(server, types_to_check);
                        all_updates.insert(all_updates.end(), updates.begin(), updates.end());
                        break; // Используем первый рабочий сервер

                    } catch (const std::exception& e) {
                        // Пробуем следующий сервер
                        continue;
                    }
                }

                // Фильтрация и валидация
                std::vector<UpdateInfo> valid_updates;
                for (const auto& update : all_updates) {
                    if (IsUpdateRelevant(update) && checker->ValidateUpdateInfo(update)) {
                        valid_updates.push_back(update);
                    }
                }

                // Сохранение доступных обновлений
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    for (const auto& update : valid_updates) {
                        available_updates[update.update_id] = update;
                        update_statuses[update.update_id] = UpdateStatus::AVAILABLE;
                    }
                }

                // Обновление статистики
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    statistics.updates_found += valid_updates.size();
                    for (const auto& update : valid_updates) {
                        statistics.update_type_counts[update.type]++;
                    }
                }

                // Уведомление о доступных обновлениях
                for (const auto& update : valid_updates) {
                    if (update_available_callback) {
                        update_available_callback(update);
                    }

                    // Автоматическая установка критических обновлений
                    if (auto_updates_enabled.load() && ShouldAutoInstall(update)) {
                        std::thread([this, update]() {
                            DownloadAndInstallUpdateAsync(update.update_id);
                        }).detach();
                    }
                }

                return valid_updates;

            } catch (const std::exception& e) {
                return {};
            }
        }

        UpdateResult DownloadUpdateImpl(const std::string& update_id) {
            UpdateResult result;
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                // Получение информации об обновлении
                UpdateInfo update_info;
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    auto it = available_updates.find(update_id);
                    if (it == available_updates.end()) {
                        result.error_message = "Update not found";
                        return result;
                    }
                    update_info = it->second;
                    update_statuses[update_id] = UpdateStatus::DOWNLOADING;
                }

                // Уведомление о начале загрузки
                if (update_status_callback) {
                    update_status_callback(update_id, UpdateStatus::DOWNLOADING, "Starting download");
                }

                // Загрузка обновления
                auto download_result = downloader->DownloadUpdate(update_info,
                    [this, update_id](std::uint64_t downloaded, std::uint64_t total) {
                        if (download_progress_callback) {
                            download_progress_callback(update_id, downloaded, total);
                        }
                    });

                if (!download_result.success) {
                    {
                        std::lock_guard<std::mutex> lock(updates_mutex);
                        update_statuses[update_id] = UpdateStatus::FAILED;
                    }

                    result.error_message = download_result.error_message;
                    result.final_status = UpdateStatus::FAILED;

                    if (update_status_callback) {
                        update_status_callback(update_id, UpdateStatus::FAILED, result.error_message);
                    }

                    return result;
                }

                // Верификация загруженного файла
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    update_statuses[update_id] = UpdateStatus::VERIFYING;
                }

                if (update_status_callback) {
                    update_status_callback(update_id, UpdateStatus::VERIFYING, "Verifying download");
                }

                std::filesystem::path downloaded_file = config.download_directory / (update_id + ".update");

                if (!verifier->VerifyUpdate(update_info, downloaded_file)) {
                    {
                        std::lock_guard<std::mutex> lock(updates_mutex);
                        update_statuses[update_id] = UpdateStatus::FAILED;
                    }

                    result.error_message = "File verification failed";
                    result.final_status = UpdateStatus::FAILED;

                    // Удаление поврежденного файла
                    std::filesystem::remove(downloaded_file);

                    return result;
                }

                auto end_time = std::chrono::high_resolution_clock::now();
                result.operation_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                result.bytes_downloaded = download_result.bytes_downloaded;
                result.success = true;
                result.final_status = UpdateStatus::COMPLETED;

                // Обновление статистики
                {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    statistics.updates_downloaded++;
                    statistics.total_bytes_downloaded += result.bytes_downloaded;

                    // Обновление среднего времени загрузки
                    auto downloads = statistics.updates_downloaded.load();
                    if (downloads > 0) {
                        auto current_avg = statistics.average_download_time.count();
                        auto new_avg = (current_avg * (downloads - 1) + result.operation_time.count()) / downloads;
                        statistics.average_download_time = std::chrono::milliseconds{static_cast<long long>(new_avg)};
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    update_statuses[update_id] = UpdateStatus::COMPLETED;
                }

                if (update_status_callback) {
                    update_status_callback(update_id, UpdateStatus::COMPLETED, "Download completed");
                }

                return result;

            } catch (const std::exception& e) {
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    update_statuses[update_id] = UpdateStatus::FAILED;
                }

                result.error_message = "Download exception: " + std::string(e.what());
                result.final_status = UpdateStatus::FAILED;

                auto end_time = std::chrono::high_resolution_clock::now();
                result.operation_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                statistics.updates_failed++;

                return result;
            }
        }

        UpdateResult InstallUpdateImpl(const std::string& update_id) {
            UpdateResult result;

            try {
                // Получение информации об обновлении
                UpdateInfo update_info;
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    auto it = available_updates.find(update_id);
                    if (it == available_updates.end()) {
                        result.error_message = "Update not found";
                        return result;
                    }
                    update_info = it->second;
                    update_statuses[update_id] = UpdateStatus::INSTALLING;
                }

                if (update_status_callback) {
                    update_status_callback(update_id, UpdateStatus::INSTALLING, "Installing update");
                }

                // Создание резервной копии если настроено
                if (config.backup_before_install) {
                    if (!installer->CreateBackup(update_info)) {
                        result.error_message = "Failed to create backup";
                        result.final_status = UpdateStatus::FAILED;
                        return result;
                    }
                }

                // Установка обновления
                std::filesystem::path update_file = config.download_directory / (update_id + ".update");
                auto install_result = installer->InstallUpdate(update_info, update_file);

                if (install_result.success) {
                    // Обновление версии
                    {
                        std::lock_guard<std::mutex> lock(versions_mutex);
                        current_versions[update_info.type] = update_info.available_version;
                    }

                    // Обновление статистики
                    {
                        std::lock_guard<std::mutex> lock(stats_mutex);
                        statistics.updates_installed++;
                        statistics.last_update_time = std::chrono::system_clock::now();
                    }

                    {
                        std::lock_guard<std::mutex> lock(updates_mutex);
                        update_statuses[update_id] = UpdateStatus::COMPLETED;
                    }

                    // Очистка загруженного файла
                    std::filesystem::remove(update_file);

                    result.success = true;
                    result.final_status = UpdateStatus::COMPLETED;

                    if (update_status_callback) {
                        update_status_callback(update_id, UpdateStatus::COMPLETED, "Installation completed");
                    }

                } else {
                    {
                        std::lock_guard<std::mutex> lock(updates_mutex);
                        update_statuses[update_id] = UpdateStatus::FAILED;
                    }

                    result.error_message = install_result.error_message;
                    result.final_status = UpdateStatus::FAILED;

                    statistics.updates_failed++;
                }

                return result;

            } catch (const std::exception& e) {
                {
                    std::lock_guard<std::mutex> lock(updates_mutex);
                    update_statuses[update_id] = UpdateStatus::FAILED;
                }

                result.error_message = "Installation exception: " + std::string(e.what());
                result.final_status = UpdateStatus::FAILED;
                statistics.updates_failed++;

                return result;
            }
        }

        void StartScheduler() {
            if (scheduler_running.load()) {
                return;
            }

            scheduler_running = true;
            next_scheduled_check = CalculateNextCheckTime();

            scheduler_thread = std::thread([this]() {
                while (scheduler_running.load()) {
                    auto now = std::chrono::system_clock::now();

                    if (now >= next_scheduled_check) {
                        // Проверка обновлений
                        try {
                            CheckForUpdatesImpl();
                        } catch (const std::exception& e) {
                            // Логирование ошибки
                        }

                        // Планирование следующей проверки
                        next_scheduled_check = CalculateNextCheckTime();
                    }

                    // Сон до следующей проверки времени
                    std::this_thread::sleep_for(std::chrono::minutes{1});
                }
            });
        }

        void StopScheduler() {
            if (!scheduler_running.load()) {
                return;
            }

            scheduler_running = false;

            if (scheduler_thread.joinable()) {
                scheduler_thread.join();
            }
        }

        void CancelAllUpdates() {
            std::lock_guard<std::mutex> lock(operations_mutex);

            for (auto& [update_id, future] : pending_operations) {
                // Отмена операции (в реальной реализации нужен механизм отмены)
                try {
                    if (future.valid()) {
                        future.wait_for(std::chrono::milliseconds{100});
                    }
                } catch (...) {
                    // Игнорируем ошибки при отмене
                }

                {
                    std::lock_guard<std::mutex> updates_lock(updates_mutex);
                    update_statuses[update_id] = UpdateStatus::CANCELLED;
                }
            }

            pending_operations.clear();
        }

        bool IsUpdateRelevant(const UpdateInfo& update_info) const {
            std::lock_guard<std::mutex> lock(versions_mutex);

            auto it = current_versions.find(update_info.type);
            if (it == current_versions.end()) {
                return true; // Нет текущей версии - обновление актуально
            }

            return update_info.available_version > it->second;
        }

        bool ShouldAutoInstall(const UpdateInfo& update_info) const {
            if (update_info.critical_update && config.auto_install_critical) {
                return true;
            }

            if (update_info.security_update && config.auto_install_security) {
                return true;
            }

            return false;
        }

        std::chrono::system_clock::time_point CalculateNextCheckTime() const {
            auto now = std::chrono::system_clock::now();

            if (config.scheduled_time.count() > 0) {
                // Запуск в определенное время
                auto today_scheduled = now;
                // Упрощенная логика - в реальности нужен точный расчет времени
                return today_scheduled + std::chrono::hours{24};
            } else {
                // Периодическая проверка
                return now + config.check_interval;
            }
        }

        std::string ExtractHost(const std::string& url) const {
            // Простое извлечение хоста из URL
            auto start = url.find("://");
            if (start == std::string::npos) {
                return url;
            }
            start += 3;

            auto end = url.find('/', start);
            if (end == std::string::npos) {
                end = url.length();
            }

            return url.substr(start, end - start);
        }

        void LoadCurrentVersions() {
            // Загрузка версий из файла конфигурации
            try {
                std::filesystem::path versions_file = config.cache_directory / "versions.json";
                if (!std::filesystem::exists(versions_file)) {
                    return;
                }

                std::ifstream file(versions_file);
                Json::Value root;
                file >> root;

                std::lock_guard<std::mutex> lock(versions_mutex);
                for (const auto& member : root.getMemberNames()) {
                    UpdateType type = Utils::StringToUpdateType(member);
                    current_versions[type] = Utils::JsonToVersionInfo(root[member]);
                }

            } catch (const std::exception& e) {
                // Ошибка загрузки - используем значения по умолчанию
            }
        }

        void SaveCurrentVersions() const {
            try {
                Json::Value root;

                {
                    std::lock_guard<std::mutex> lock(versions_mutex);
                    for (const auto& [type, version] : current_versions) {
                        root[Utils::UpdateTypeToString(type)] = Utils::VersionInfoToJson(version);
                    }
                }

                std::filesystem::path versions_file = config.cache_directory / "versions.json";
                std::ofstream file(versions_file);
                file << root;

            } catch (const std::exception& e) {
                // Ошибка сохранения - игнорируем
            }
        }
    };

    // ============================================================================
    // UpdateChecker::Impl
    // ============================================================================

    class UpdateChecker::Impl {
    public:
        UpdaterConfig config;
        std::shared_ptr<NetworkClient::TLSHttpClient> http_client;

        Impl(const UpdaterConfig& cfg) : config(cfg) {
            // Инициализация HTTP клиента
            NetworkClient::ClientConfig net_config;
            net_config.connection_type = NetworkClient::ConnectionType::HTTPS;

            http_client = std::make_shared<NetworkClient::TLSHttpClient>(net_config);
        }

        std::vector<UpdateInfo> CheckUpdatesFromServer(const std::string& server_url,
                                                      const std::vector<UpdateType>& types) {
            std::vector<UpdateInfo> updates;

            try {
                // Формирование запроса
                Json::Value request;
                request["client_id"] = config.client_id;
                request["api_version"] = "1.0";
                request["channel"] = Utils::UpdateChannelToString(config.default_channel);

                Json::Value types_array(Json::arrayValue);
                for (auto type : types) {
                    types_array.append(Utils::UpdateTypeToString(type));
                }
                request["update_types"] = types_array;

                // Отправка запроса
                std::string endpoint = "/check-updates";
                auto response = http_client->PostJson(endpoint, request);

                if (!response.success || response.status_code != 200) {
                    throw std::runtime_error("Server request failed: " + response.status_message);
                }

                // Парсинг ответа
                auto json_response = NetworkClient::Utils::StringToJson(response.body);
                if (!json_response) {
                    throw std::runtime_error("Invalid JSON response");
                }

                const Json::Value& updates_array = (*json_response)["updates"];
                if (!updates_array.isArray()) {
                    throw std::runtime_error("Invalid updates format");
                }

                for (const auto& update_json : updates_array) {
                    try {
                        UpdateInfo update_info = Utils::JsonToUpdateInfo(update_json);
                        if (ValidateUpdateInfo(update_info)) {
                            updates.push_back(update_info);
                        }
                    } catch (const std::exception& e) {
                        // Пропускаем некорректные обновления
                        continue;
                    }
                }

                return updates;

            } catch (const std::exception& e) {
                throw std::runtime_error("Update check failed: " + std::string(e.what()));
            }
        }

        bool ValidateUpdateInfo(const UpdateInfo& update_info) const {
            // Проверка обязательных полей
            if (update_info.update_id.empty() ||
                update_info.download_url.empty() ||
                update_info.sha256_hash.empty()) {
                return false;
            }

            // Проверка версии
            if (!(update_info.available_version > VersionInfo{0, 0, 0})) {
                return false;
            }

            // Проверка размера файла
            if (update_info.file_size == 0 || update_info.file_size > 1024ULL * 1024 * 1024) { // Макс 1GB
                return false;
            }

            // Проверка срока действия
            auto now = std::chrono::system_clock::now();
            if (update_info.expires_at < now) {
                return false;
            }

            return true;
        }
    };

    // ============================================================================
    // Реализация основных классов
    // ============================================================================

    // UpdateManager
    UpdateManager::UpdateManager(const UpdaterConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
        pImpl->InitializeComponents();
    }

    UpdateManager::~UpdateManager() = default;

    bool UpdateManager::Initialize() {
        return pImpl->Initialize();
    }

    void UpdateManager::Shutdown() {
        pImpl->Shutdown();
    }

    bool UpdateManager::IsRunning() const {
        return pImpl->running.load();
    }

    void UpdateManager::SetConfig(const UpdaterConfig& config) {
        pImpl->config = config;
        pImpl->InitializeComponents();
    }

    const UpdaterConfig& UpdateManager::GetConfig() const {
        return pImpl->config;
    }

    void UpdateManager::SetAuthManager(std::shared_ptr<AuthState::AuthStateManager> auth_manager) {
        pImpl->auth_manager = auth_manager;
    }

    std::vector<UpdateInfo> UpdateManager::CheckForUpdates() {
        return pImpl->CheckForUpdatesImpl();
    }

    std::future<std::vector<UpdateInfo>> UpdateManager::CheckForUpdatesAsync() {
        return std::async(std::launch::async, [this]() {
            return pImpl->CheckForUpdatesImpl();
        });
    }

    std::string UpdateManager::ScheduleUpdate(const UpdateInfo& update_info) {
        std::lock_guard<std::mutex> lock(pImpl->updates_mutex);
        pImpl->available_updates[update_info.update_id] = update_info;
        pImpl->update_statuses[update_info.update_id] = UpdateStatus::AVAILABLE;
        return update_info.update_id;
    }

    UpdateResult UpdateManager::DownloadUpdate(const std::string& update_id) {
        return pImpl->DownloadUpdateImpl(update_id);
    }

    UpdateResult UpdateManager::InstallUpdate(const std::string& update_id) {
        return pImpl->InstallUpdateImpl(update_id);
    }

    UpdateResult UpdateManager::DownloadAndInstallUpdate(const std::string& update_id) {
        auto download_result = DownloadUpdate(update_id);
        if (!download_result.success) {
            return download_result;
        }

        return InstallUpdate(update_id);
    }

    std::future<UpdateResult> UpdateManager::DownloadUpdateAsync(const std::string& update_id) {
        auto future = std::async(std::launch::async, [this, update_id]() {
            return pImpl->DownloadUpdateImpl(update_id);
        });

        {
            std::lock_guard<std::mutex> lock(pImpl->operations_mutex);
            pImpl->pending_operations[update_id] = std::move(future);
        }

        return std::async(std::launch::deferred, [this, update_id]() {
            std::lock_guard<std::mutex> lock(pImpl->operations_mutex);
            auto it = pImpl->pending_operations.find(update_id);
            if (it != pImpl->pending_operations.end()) {
                return it->second.get();
            }

            UpdateResult result;
            result.error_message = "Operation not found";
            return result;
        });
    }

    void UpdateManager::SetUpdateAvailableCallback(UpdateAvailableCallback callback) {
        pImpl->update_available_callback = std::move(callback);
    }

    void UpdateManager::SetDownloadProgressCallback(DownloadProgressCallback callback) {
        pImpl->download_progress_callback = std::move(callback);
    }

    void UpdateManager::SetUpdateStatusCallback(UpdateStatusCallback callback) {
        pImpl->update_status_callback = std::move(callback);
    }

    void UpdateManager::SetUpdateCompletedCallback(UpdateCompletedCallback callback) {
        pImpl->update_completed_callback = std::move(callback);
    }

    VersionInfo UpdateManager::GetCurrentVersion(UpdateType type) const {
        std::lock_guard<std::mutex> lock(pImpl->versions_mutex);
        auto it = pImpl->current_versions.find(type);
        return it != pImpl->current_versions.end() ? it->second : VersionInfo{};
    }

    void UpdateManager::SetCurrentVersion(UpdateType type, const VersionInfo& version) {
        std::lock_guard<std::mutex> lock(pImpl->versions_mutex);
        pImpl->current_versions[type] = version;
    }

    UpdaterStatistics UpdateManager::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    void UpdateManager::StartScheduler() {
        pImpl->StartScheduler();
    }

    void UpdateManager::StopScheduler() {
        pImpl->StopScheduler();
    }

    // UpdateChecker
    UpdateChecker::UpdateChecker(const UpdaterConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    UpdateChecker::~UpdateChecker() = default;

    std::vector<UpdateInfo> UpdateChecker::CheckUpdatesFromServer(const std::string& server_url,
                                                                 const std::vector<UpdateType>& types) {
        return pImpl->CheckUpdatesFromServer(server_url, types);
    }

    bool UpdateChecker::ValidateUpdateInfo(const UpdateInfo& update_info) const {
        return pImpl->ValidateUpdateInfo(update_info);
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string UpdateTypeToString(UpdateType type) {
            switch (type) {
                case UpdateType::VIRUS_SIGNATURES: return "VIRUS_SIGNATURES";
                case UpdateType::ENGINE_UPDATE: return "ENGINE_UPDATE";
                case UpdateType::CONFIGURATION_UPDATE: return "CONFIGURATION_UPDATE";
                case UpdateType::MODULE_UPDATE: return "MODULE_UPDATE";
                case UpdateType::PLUGIN_UPDATE: return "PLUGIN_UPDATE";
                case UpdateType::BLACKLIST_UPDATE: return "BLACKLIST_UPDATE";
                case UpdateType::WHITELIST_UPDATE: return "WHITELIST_UPDATE";
                case UpdateType::HEURISTIC_RULES: return "HEURISTIC_RULES";
                case UpdateType::CUSTOM_RULES: return "CUSTOM_RULES";
                default: return "UNKNOWN";
            }
        }

        UpdateType StringToUpdateType(const std::string& type_str) {
            if (type_str == "VIRUS_SIGNATURES") return UpdateType::VIRUS_SIGNATURES;
            if (type_str == "ENGINE_UPDATE") return UpdateType::ENGINE_UPDATE;
            if (type_str == "CONFIGURATION_UPDATE") return UpdateType::CONFIGURATION_UPDATE;
            if (type_str == "MODULE_UPDATE") return UpdateType::MODULE_UPDATE;
            if (type_str == "PLUGIN_UPDATE") return UpdateType::PLUGIN_UPDATE;
            if (type_str == "BLACKLIST_UPDATE") return UpdateType::BLACKLIST_UPDATE;
            if (type_str == "WHITELIST_UPDATE") return UpdateType::WHITELIST_UPDATE;
            if (type_str == "HEURISTIC_RULES") return UpdateType::HEURISTIC_RULES;
            if (type_str == "CUSTOM_RULES") return UpdateType::CUSTOM_RULES;
            return UpdateType::VIRUS_SIGNATURES;
        }

        std::string UpdateStatusToString(UpdateStatus status) {
            switch (status) {
                case UpdateStatus::NONE: return "NONE";
                case UpdateStatus::CHECKING: return "CHECKING";
                case UpdateStatus::AVAILABLE: return "AVAILABLE";
                case UpdateStatus::DOWNLOADING: return "DOWNLOADING";
                case UpdateStatus::VERIFYING: return "VERIFYING";
                case UpdateStatus::INSTALLING: return "INSTALLING";
                case UpdateStatus::COMPLETED: return "COMPLETED";
                case UpdateStatus::FAILED: return "FAILED";
                case UpdateStatus::CANCELLED: return "CANCELLED";
                case UpdateStatus::ROLLBACK: return "ROLLBACK";
                default: return "UNKNOWN";
            }
        }

        std::string UpdateChannelToString(UpdateChannel channel) {
            switch (channel) {
                case UpdateChannel::STABLE: return "STABLE";
                case UpdateChannel::BETA: return "BETA";
                case UpdateChannel::ALPHA: return "ALPHA";
                case UpdateChannel::EXPERIMENTAL: return "EXPERIMENTAL";
                case UpdateChannel::CUSTOM: return "CUSTOM";
                default: return "STABLE";
            }
        }

        VersionInfo ParseVersion(const std::string& version_str) {
            VersionInfo version;

            // Простой парсер версии в формате "major.minor.patch"
            std::istringstream iss(version_str);
            std::string part;

            if (std::getline(iss, part, '.')) {
                version.major = std::stoi(part);
            }
            if (std::getline(iss, part, '.')) {
                version.minor = std::stoi(part);
            }
            if (std::getline(iss, part, '.')) {
                version.patch = std::stoi(part);
            }
            if (std::getline(iss, part, '.')) {
                version.build = std::stoi(part);
            }

            return version;
        }

        bool IsVersionNewer(const VersionInfo& current, const VersionInfo& available) {
            return available > current;
        }

        std::string CalculateFileHash(const std::filesystem::path& file_path) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                return "";
            }

            SHA256_CTX sha256_ctx;
            SHA256_Init(&sha256_ctx);

            char buffer[8192];
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                SHA256_Update(&sha256_ctx, buffer, file.gcount());
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_Final(hash, &sha256_ctx);

            std::ostringstream oss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }

            return oss.str();
        }

        bool VerifyFileIntegrity(const std::filesystem::path& file_path, const std::string& expected_hash) {
            std::string calculated_hash = CalculateFileHash(file_path);
            return calculated_hash == expected_hash;
        }

        std::string GenerateUpdateId() {
            static std::atomic<uint64_t> counter{1};
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            return "upd_" + std::to_string(timestamp) + "_" + std::to_string(counter.fetch_add(1));
        }

        Json::Value UpdateInfoToJson(const UpdateInfo& update_info) {
            Json::Value json;

            json["update_id"] = update_info.update_id;
            json["type"] = UpdateTypeToString(update_info.type);
            json["priority"] = static_cast<int>(update_info.priority);
            json["channel"] = UpdateChannelToString(update_info.channel);

            json["current_version"] = VersionInfoToJson(update_info.current_version);
            json["available_version"] = VersionInfoToJson(update_info.available_version);

            json["title"] = update_info.title;
            json["description"] = update_info.description;
            json["download_url"] = update_info.download_url;
            json["file_size"] = static_cast<Json::Int64>(update_info.file_size);
            json["sha256_hash"] = update_info.sha256_hash;

            json["requires_restart"] = update_info.requires_restart;
            json["critical_update"] = update_info.critical_update;
            json["security_update"] = update_info.security_update;

            return json;
        }

        UpdateInfo JsonToUpdateInfo(const Json::Value& json) {
            UpdateInfo update_info;

            update_info.update_id = json.get("update_id", "").asString();
            update_info.type = StringToUpdateType(json.get("type", "VIRUS_SIGNATURES").asString());
            update_info.priority = static_cast<UpdatePriority>(json.get("priority", 2).asInt());

            if (json.isMember("current_version")) {
                update_info.current_version = JsonToVersionInfo(json["current_version"]);
            }
            if (json.isMember("available_version")) {
                update_info.available_version = JsonToVersionInfo(json["available_version"]);
            }

            update_info.title = json.get("title", "").asString();
            update_info.description = json.get("description", "").asString();
            update_info.download_url = json.get("download_url", "").asString();
            update_info.file_size = json.get("file_size", 0).asUInt64();
            update_info.sha256_hash = json.get("sha256_hash", "").asString();

            update_info.requires_restart = json.get("requires_restart", false).asBool();
            update_info.critical_update = json.get("critical_update", false).asBool();
            update_info.security_update = json.get("security_update", false).asBool();

            return update_info;
        }

        Json::Value VersionInfoToJson(const VersionInfo& version) {
            Json::Value json;
            json["major"] = version.major;
            json["minor"] = version.minor;
            json["patch"] = version.patch;
            json["build"] = version.build;
            if (!version.pre_release.empty()) {
                json["pre_release"] = version.pre_release;
            }
            return json;
        }

        VersionInfo JsonToVersionInfo(const Json::Value& json) {
            VersionInfo version;
            version.major = json.get("major", 0).asInt();
            version.minor = json.get("minor", 0).asInt();
            version.patch = json.get("patch", 0).asInt();
            version.build = json.get("build", 0).asInt();
            version.pre_release = json.get("pre_release", "").asString();
            return version;
        }
    }
}