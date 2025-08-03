//
// Created by WhySkyDie on 21.07.2025.
//

#include "auth_state.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <thread>
#include <iomanip>
#include <json/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

namespace AuthState {

    // ============================================================================
    // AuthStateManager::Impl
    // ============================================================================

    class AuthStateManager::Impl {
    public:
        AuthStateConfig config;
        std::atomic<bool> initialized{false};

        // Хранение ключей
        std::unordered_map<std::string, AuthKey> auth_keys;
        std::optional<std::string> current_key_value;
        mutable std::mutex keys_mutex;

        // Кэш информации о пользователях
        std::unordered_map<std::string, UserAuthInfo> user_info_cache;
        std::unordered_map<std::string, std::chrono::system_clock::time_point> cache_timestamps;
        mutable std::mutex cache_mutex;

        // Callbacks
        AuthEventCallback auth_event_callback;
        TokenRefreshCallback token_refresh_callback;
        UserInfoCallback user_info_callback;

        // Статистика
        std::atomic<std::chrono::system_clock::time_point> last_auth_check;
        std::atomic<size_t> auth_check_count{0};

        // Фоновые задачи
        std::thread cleanup_thread;
        std::atomic<bool> should_stop_cleanup{false};

        Impl() {
            last_auth_check = std::chrono::system_clock::now();
        }

        ~Impl() {
            Shutdown();
        }

        bool Initialize() {
            if (initialized.load()) {
                return true;
            }

            try {
                // Создание директории для хранения
                if (config.persistent_storage && !config.storage_path.empty()) {
                    std::filesystem::create_directories(config.storage_path);

                    // Загрузка сохраненных данных
                    auto auth_file = config.storage_path / "auth_keys.json";
                    if (std::filesystem::exists(auth_file)) {
                        LoadFromFileImpl(auth_file);
                    }
                }

                // Запуск фонового потока очистки
                if (config.auto_cleanup_expired) {
                    StartCleanupThread();
                }

                initialized = true;
                LogEvent("SYSTEM_INIT", "", "Auth state manager initialized");

                return true;

            } catch (const std::exception& e) {
                LogEvent("SYSTEM_ERROR", "", "Failed to initialize: " + std::string(e.what()));
                return false;
            }
        }

        void Shutdown() {
            if (!initialized.load()) {
                return;
            }

            // Остановка фонового потока
            should_stop_cleanup = true;
            if (cleanup_thread.joinable()) {
                cleanup_thread.join();
            }

            // Сохранение состояния
            if (config.persistent_storage) {
                auto auth_file = config.storage_path / "auth_keys.json";
                SaveToFileImpl(auth_file);
            }

            // Очистка
            {
                std::lock_guard<std::mutex> lock(keys_mutex);
                auth_keys.clear();
                current_key_value.reset();
            }

            {
                std::lock_guard<std::mutex> lock(cache_mutex);
                user_info_cache.clear();
                cache_timestamps.clear();
            }

            initialized = false;
            LogEvent("SYSTEM_SHUTDOWN", "", "Auth state manager shut down");
        }

        bool SetAuthKeyImpl(const AuthKey& key) {
            if (!initialized.load()) {
                return false;
            }

            try {
                std::lock_guard<std::mutex> lock(keys_mutex);

                // Валидация ключа
                if (!key.IsValid()) {
                    LogEvent("AUTH_ERROR", key.user_id, "Invalid auth key");
                    return false;
                }

                // Сохранение ключа
                auth_keys[key.key_value] = key;
                current_key_value = key.key_value;

                // Обновление времени последнего использования
                auth_keys[key.key_value].last_used = std::chrono::system_clock::now();

                LogEvent("AUTH_SET", key.user_id, "Auth key set successfully");
                return true;

            } catch (const std::exception& e) {
                LogEvent("AUTH_ERROR", key.user_id, "Failed to set auth key: " + std::string(e.what()));
                return false;
            }
        }

        AuthCheckResult CheckAuthorizationImpl(const std::string& key_value,
                                              std::optional<AccessLevel> required_level = std::nullopt,
                                              std::optional<std::string> required_permission = std::nullopt) const {
            auto start_time = std::chrono::high_resolution_clock::now();
            AuthCheckResult result;

            if (!initialized.load()) {
                result.error_message = "Auth state manager not initialized";
                result.status = AuthStatus::INVALID;
                return result;
            }

            try {
                std::lock_guard<std::mutex> lock(keys_mutex);

                // Обновление статистики
                last_auth_check = std::chrono::system_clock::now();
                auth_check_count++;

                // Поиск ключа
                auto it = auth_keys.find(key_value);
                if (it == auth_keys.end()) {
                    result.error_message = "Auth key not found";
                    result.status = AuthStatus::INVALID;
                    LogEvent("AUTH_CHECK_FAILED", "", "Key not found");
                    return result;
                }

                AuthKey& key = it->second;

                // Проверка активности ключа
                if (!key.is_active) {
                    result.error_message = "Auth key is inactive";
                    result.status = AuthStatus::BLOCKED;
                    LogEvent("AUTH_CHECK_FAILED", key.user_id, "Key inactive");
                    return result;
                }

                // Проверка срока действия
                if (config.strict_expiration_check && key.IsExpired()) {
                    result.error_message = "Auth key expired";
                    result.status = AuthStatus::EXPIRED;
                    LogEvent("AUTH_CHECK_FAILED", key.user_id, "Key expired");

                    // Попытка обновления токена
                    if (token_refresh_callback) {
                        auto new_key = token_refresh_callback(key);
                        if (new_key && new_key->IsValid()) {
                            const_cast<Impl*>(this)->SetAuthKeyImpl(*new_key);
                            result.authorized = true;
                            result.status = AuthStatus::AUTHORIZED;
                            result.effective_access_level = new_key->access_level;
                        }
                    }

                    return result;
                }

                // Обновление времени последнего использования
                key.last_used = std::chrono::system_clock::now();

                // Получение информации о пользователе
                auto user_info = GetUserInfoImpl(key.user_id);
                if (user_info) {
                    result.user_info = *user_info;

                    // Проверка уровня доступа
                    if (required_level) {
                        if (user_info->access_level < *required_level) {
                            result.error_message = "Insufficient access level";
                            result.status = AuthStatus::INVALID;
                            LogEvent("AUTH_CHECK_FAILED", key.user_id, "Insufficient access level");
                            return result;
                        }
                    }

                    // Проверка разрешений
                    if (required_permission) {
                        if (user_info->permissions.find(*required_permission) == user_info->permissions.end()) {
                            result.error_message = "Permission denied: " + *required_permission;
                            result.status = AuthStatus::INVALID;
                            LogEvent("AUTH_CHECK_FAILED", key.user_id, "Permission denied: " + *required_permission);
                            return result;
                        }
                    }

                    result.effective_access_level = user_info->access_level;
                } else {
                    result.effective_access_level = key.access_level;
                }

                result.authorized = true;
                result.status = AuthStatus::AUTHORIZED;

                auto end_time = std::chrono::high_resolution_clock::now();
                result.check_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Auth check error: " + std::string(e.what());
                result.status = AuthStatus::INVALID;
                LogEvent("AUTH_CHECK_ERROR", "", result.error_message);
                return result;
            }
        }

        std::optional<UserAuthInfo> GetUserInfoImpl(const std::string& user_id) const {
            // Проверка кэша
            if (config.cache_user_info) {
                std::lock_guard<std::mutex> lock(cache_mutex);

                auto cache_it = user_info_cache.find(user_id);
                auto timestamp_it = cache_timestamps.find(user_id);

                if (cache_it != user_info_cache.end() && timestamp_it != cache_timestamps.end()) {
                    auto cache_age = std::chrono::system_clock::now() - timestamp_it->second;
                    if (cache_age < config.cache_lifetime) {
                        return cache_it->second;
                    }
                }
            }

            // Запрос через callback
            std::optional<UserAuthInfo> user_info;
            if (user_info_callback) {
                user_info = user_info_callback(user_id);
            }

            // Обновление кэша
            if (user_info && config.cache_user_info) {
                std::lock_guard<std::mutex> lock(cache_mutex);
                user_info_cache[user_id] = *user_info;
                cache_timestamps[user_id] = std::chrono::system_clock::now();
            }

            return user_info;
        }

        bool RefreshCurrentTokenImpl() {
            std::lock_guard<std::mutex> lock(keys_mutex);

            if (!current_key_value || !token_refresh_callback) {
                return false;
            }

            auto it = auth_keys.find(*current_key_value);
            if (it == auth_keys.end()) {
                return false;
            }

            auto new_key = token_refresh_callback(it->second);
            if (new_key && new_key->IsValid()) {
                // Удаляем старый ключ
                auth_keys.erase(it);

                // Добавляем новый
                auth_keys[new_key->key_value] = *new_key;
                current_key_value = new_key->key_value;

                LogEvent("TOKEN_REFRESH", new_key->user_id, "Token refreshed successfully");
                return true;
            }

            return false;
        }

        size_t CleanupExpiredKeysImpl() {
            std::lock_guard<std::mutex> lock(keys_mutex);

            size_t removed_count = 0;
            auto now = std::chrono::system_clock::now();

            for (auto it = auth_keys.begin(); it != auth_keys.end();) {
                if (it->second.IsExpired()) {
                    LogEvent("KEY_CLEANUP", it->second.user_id, "Expired key removed");
                    it = auth_keys.erase(it);
                    removed_count++;
                } else {
                    ++it;
                }
            }

            return removed_count;
        }

        size_t CleanupExpiredCacheImpl() {
            std::lock_guard<std::mutex> lock(cache_mutex);

            size_t removed_count = 0;
            auto now = std::chrono::system_clock::now();

            for (auto it = cache_timestamps.begin(); it != cache_timestamps.end();) {
                auto cache_age = now - it->second;
                if (cache_age > config.cache_lifetime) {
                    user_info_cache.erase(it->first);
                    it = cache_timestamps.erase(it);
                    removed_count++;
                } else {
                    ++it;
                }
            }

            return removed_count;
        }

        void StartCleanupThread() {
            cleanup_thread = std::thread([this]() {
                while (!should_stop_cleanup.load()) {
                    try {
                        CleanupExpiredKeysImpl();
                        CleanupExpiredCacheImpl();

                        // Периодическое сохранение
                        if (config.persistent_storage) {
                            auto auth_file = config.storage_path / "auth_keys.json";
                            SaveToFileImpl(auth_file);
                        }

                    } catch (const std::exception& e) {
                        LogEvent("CLEANUP_ERROR", "", "Cleanup failed: " + std::string(e.what()));
                    }

                    // Ожидание следующего цикла
                    auto sleep_time = std::chrono::duration_cast<std::chrono::milliseconds>(config.cleanup_interval);
                    std::this_thread::sleep_for(sleep_time);
                }
            });
        }

        bool SaveToFileImpl(const std::filesystem::path& file_path) const {
            try {
                Json::Value root;
                Json::Value keys_array(Json::arrayValue);

                {
                    std::lock_guard<std::mutex> lock(keys_mutex);

                    for (const auto& [key_value, auth_key] : auth_keys) {
                        Json::Value key_obj;
                        key_obj["key_value"] = config.encryption_key.empty() ?
                            auth_key.key_value : Utils::EncryptKey(auth_key.key_value, config.encryption_key);
                        key_obj["key_type"] = Utils::KeyTypeToString(auth_key.key_type);
                        key_obj["user_id"] = auth_key.user_id;
                        key_obj["access_level"] = Utils::AccessLevelToString(auth_key.access_level);
                        key_obj["issued_at"] = Utils::FormatTimestamp(auth_key.issued_at);
                        key_obj["expires_at"] = Utils::FormatTimestamp(auth_key.expires_at);
                        key_obj["last_used"] = Utils::FormatTimestamp(auth_key.last_used);
                        key_obj["issuer"] = auth_key.issuer;
                        key_obj["scope"] = auth_key.scope;
                        key_obj["is_active"] = auth_key.is_active;

                        keys_array.append(key_obj);
                    }

                    if (current_key_value) {
                        root["current_key"] = config.encryption_key.empty() ?
                            *current_key_value : Utils::EncryptKey(*current_key_value, config.encryption_key);
                    }
                }

                root["keys"] = keys_array;
                root["version"] = "1.0";
                root["saved_at"] = Utils::FormatTimestamp(std::chrono::system_clock::now());

                std::ofstream file(file_path);
                if (!file.is_open()) {
                    return false;
                }

                Json::StreamWriterBuilder builder;
                std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
                writer->write(root, &file);

                return true;

            } catch (const std::exception& e) {
                LogEvent("SAVE_ERROR", "", "Failed to save: " + std::string(e.what()));
                return false;
            }
        }

        bool LoadFromFileImpl(const std::filesystem::path& file_path) {
            try {
                std::ifstream file(file_path);
                if (!file.is_open()) {
                    return false;
                }

                Json::Value root;
                Json::Reader reader;

                if (!reader.parse(file, root)) {
                    return false;
                }

                std::lock_guard<std::mutex> lock(keys_mutex);
                auth_keys.clear();
                current_key_value.reset();

                const Json::Value& keys_array = root["keys"];
                if (keys_array.isArray()) {
                    for (const auto& key_obj : keys_array) {
                        AuthKey auth_key;

                        std::string key_value_raw = key_obj["key_value"].asString();
                        auth_key.key_value = config.encryption_key.empty() ?
                            key_value_raw : Utils::DecryptKey(key_value_raw, config.encryption_key);

                        auth_key.key_type = Utils::StringToKeyType(key_obj["key_type"].asString());
                        auth_key.user_id = key_obj["user_id"].asString();
                        auth_key.access_level = Utils::StringToAccessLevel(key_obj["access_level"].asString());
                        auth_key.issued_at = Utils::ParseTimestamp(key_obj["issued_at"].asString());
                        auth_key.expires_at = Utils::ParseTimestamp(key_obj["expires_at"].asString());
                        auth_key.last_used = Utils::ParseTimestamp(key_obj["last_used"].asString());
                        auth_key.issuer = key_obj["issuer"].asString();
                        auth_key.scope = key_obj["scope"].asString();
                        auth_key.is_active = key_obj["is_active"].asBool();

                        if (auth_key.IsValid()) {
                            auth_keys[auth_key.key_value] = auth_key;
                        }
                    }
                }

                if (root.isMember("current_key")) {
                    std::string current_key_raw = root["current_key"].asString();
                    std::string decrypted_key = config.encryption_key.empty() ?
                        current_key_raw : Utils::DecryptKey(current_key_raw, config.encryption_key);

                    if (auth_keys.find(decrypted_key) != auth_keys.end()) {
                        current_key_value = decrypted_key;
                    }
                }

                LogEvent("LOAD_SUCCESS", "", "Auth keys loaded from file");
                return true;

            } catch (const std::exception& e) {
                LogEvent("LOAD_ERROR", "", "Failed to load: " + std::string(e.what()));
                return false;
            }
        }

        void LogEvent(const std::string& event, const std::string& user_id, const std::string& details) const {
            if (config.log_auth_events && auth_event_callback) {
                auth_event_callback(event, user_id, details);
            }
        }
    };

    // ============================================================================
    // Реализация основного класса
    // ============================================================================

    AuthStateManager::AuthStateManager(const AuthStateConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    AuthStateManager::~AuthStateManager() = default;

    bool AuthStateManager::Initialize() {
        return pImpl->Initialize();
    }

    void AuthStateManager::Shutdown() {
        pImpl->Shutdown();
    }

    bool AuthStateManager::IsInitialized() const {
        return pImpl->initialized.load();
    }

    void AuthStateManager::SetConfig(const AuthStateConfig& config) {
        pImpl->config = config;
    }

    const AuthStateConfig& AuthStateManager::GetConfig() const {
        return pImpl->config;
    }

    bool AuthStateManager::SetAuthKey(const AuthKey& key) {
        return pImpl->SetAuthKeyImpl(key);
    }

    bool AuthStateManager::SetAuthKey(const std::string& key_value, KeyType type,
                                     const std::string& user_id, AccessLevel access_level,
                                     std::chrono::minutes lifetime) {
        AuthKey key;
        key.key_value = key_value;
        key.key_type = type;
        key.user_id = user_id;
        key.access_level = access_level;
        key.issued_at = std::chrono::system_clock::now();
        key.expires_at = key.issued_at + lifetime;
        key.is_active = true;

        return SetAuthKey(key);
    }

    std::optional<AuthKey> AuthStateManager::GetCurrentAuthKey() const {
        std::lock_guard<std::mutex> lock(pImpl->keys_mutex);

        if (!pImpl->current_key_value) {
            return std::nullopt;
        }

        auto it = pImpl->auth_keys.find(*pImpl->current_key_value);
        return it != pImpl->auth_keys.end() ? std::make_optional(it->second) : std::nullopt;
    }

    std::optional<AuthKey> AuthStateManager::GetAuthKey(const std::string& key_value) const {
        std::lock_guard<std::mutex> lock(pImpl->keys_mutex);

        auto it = pImpl->auth_keys.find(key_value);
        return it != pImpl->auth_keys.end() ? std::make_optional(it->second) : std::nullopt;
    }

    AuthCheckResult AuthStateManager::CheckAuthorization() const {
        if (!pImpl->current_key_value) {
            AuthCheckResult result;
            result.error_message = "No current auth key set";
            result.status = AuthStatus::NOT_AUTHORIZED;
            return result;
        }

        return pImpl->CheckAuthorizationImpl(*pImpl->current_key_value);
    }

    AuthCheckResult AuthStateManager::CheckAuthorization(const std::string& key_value) const {
        return pImpl->CheckAuthorizationImpl(key_value);
    }

    AuthCheckResult AuthStateManager::CheckAuthorization(const std::string& key_value,
                                                        AccessLevel required_level) const {
        return pImpl->CheckAuthorizationImpl(key_value, required_level);
    }

    AuthCheckResult AuthStateManager::CheckAuthorization(const std::string& key_value,
                                                        const std::string& required_permission) const {
        return pImpl->CheckAuthorizationImpl(key_value, std::nullopt, required_permission);
    }

    bool AuthStateManager::HasPermission(const std::string& permission) const {
        auto current_key = GetCurrentAuthKey();
        if (!current_key) {
            return false;
        }

        auto result = CheckAuthorization(current_key->key_value, permission);
        return result.authorized;
    }

    bool AuthStateManager::HasAccessLevel(AccessLevel required_level) const {
        auto current_key = GetCurrentAuthKey();
        if (!current_key) {
            return false;
        }

        auto result = CheckAuthorization(current_key->key_value, required_level);
        return result.authorized;
    }

    std::unordered_set<std::string> AuthStateManager::GetUserPermissions() const {
        auto user_info = GetCurrentUserInfo();
        return user_info ? user_info->permissions : std::unordered_set<std::string>{};
    }

    AccessLevel AuthStateManager::GetUserAccessLevel() const {
        auto user_info = GetCurrentUserInfo();
        return user_info ? user_info->access_level : AccessLevel::NONE;
    }

    std::optional<UserAuthInfo> AuthStateManager::GetCurrentUserInfo() const {
        auto current_key = GetCurrentAuthKey();
        if (!current_key) {
            return std::nullopt;
        }

        return pImpl->GetUserInfoImpl(current_key->user_id);
    }

    std::optional<UserAuthInfo> AuthStateManager::GetUserInfo(const std::string& user_id) const {
        return pImpl->GetUserInfoImpl(user_id);
    }

    bool AuthStateManager::RefreshCurrentToken() {
        return pImpl->RefreshCurrentTokenImpl();
    }

    bool AuthStateManager::RevokeAuthKey(const std::string& key_value) {
        std::lock_guard<std::mutex> lock(pImpl->keys_mutex);

        auto it = pImpl->auth_keys.find(key_value);
        if (it != pImpl->auth_keys.end()) {
            pImpl->LogEvent("KEY_REVOKE", it->second.user_id, "Auth key revoked");
            pImpl->auth_keys.erase(it);

            if (pImpl->current_key_value && *pImpl->current_key_value == key_value) {
                pImpl->current_key_value.reset();
            }

            return true;
        }

        return false;
    }

    bool AuthStateManager::IsCurrentSessionValid() const {
        auto result = CheckAuthorization();
        return result.authorized && result.status == AuthStatus::AUTHORIZED;
    }

    size_t AuthStateManager::CleanupExpiredKeys() {
        return pImpl->CleanupExpiredKeysImpl();
    }

    size_t AuthStateManager::CleanupExpiredCache() {
        return pImpl->CleanupExpiredCacheImpl();
    }

    void AuthStateManager::SetAuthEventCallback(AuthEventCallback callback) {
        pImpl->auth_event_callback = std::move(callback);
    }

    void AuthStateManager::SetTokenRefreshCallback(TokenRefreshCallback callback) {
        pImpl->token_refresh_callback = std::move(callback);
    }

    void AuthStateManager::SetUserInfoCallback(UserInfoCallback callback) {
        pImpl->user_info_callback = std::move(callback);
    }

    size_t AuthStateManager::GetActiveKeysCount() const {
        std::lock_guard<std::mutex> lock(pImpl->keys_mutex);

        size_t count = 0;
        auto now = std::chrono::system_clock::now();

        for (const auto& [key_value, auth_key] : pImpl->auth_keys) {
            if (auth_key.is_active && !auth_key.IsExpired()) {
                count++;
            }
        }

        return count;
    }

    bool AuthStateManager::SaveToFile(const std::filesystem::path& file_path) const {
        return pImpl->SaveToFileImpl(file_path);
    }

    bool AuthStateManager::LoadFromFile(const std::filesystem::path& file_path) {
        return pImpl->LoadFromFileImpl(file_path);
    }

    // ============================================================================
    // AuthDecorator
    // ============================================================================

    AuthDecorator::AuthDecorator(std::shared_ptr<AuthStateManager> auth_manager)
        : auth_manager_(std::move(auth_manager)) {}

    // ============================================================================
    // GlobalAuthState
    // ============================================================================

    GlobalAuthState& GlobalAuthState::Instance() {
        static GlobalAuthState instance;
        return instance;
    }

    void GlobalAuthState::Initialize(const AuthStateConfig& config) {
        std::call_once(initialized_flag_, [this, &config]() {
            auth_manager_ = std::make_shared<AuthStateManager>(config);
            auth_manager_->Initialize();
        });
    }

    void GlobalAuthState::Shutdown() {
        if (auth_manager_) {
            auth_manager_->Shutdown();
            auth_manager_.reset();
        }
    }

    std::shared_ptr<AuthStateManager> GlobalAuthState::GetAuthManager() {
        return auth_manager_;
    }

    AuthCheckResult GlobalAuthState::QuickAuthCheck() {
        if (!auth_manager_) {
            AuthCheckResult result;
            result.error_message = "Global auth state not initialized";
            result.status = AuthStatus::NOT_AUTHORIZED;
            return result;
        }

        return auth_manager_->CheckAuthorization();
    }

    bool GlobalAuthState::IsGloballyAuthorized() {
        auto result = QuickAuthCheck();
        return result.authorized;
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string AccessLevelToString(AccessLevel level) {
            switch (level) {
                case AccessLevel::NONE: return "NONE";
                case AccessLevel::READ_ONLY: return "READ_ONLY";
                case AccessLevel::READ_WRITE: return "READ_WRITE";
                case AccessLevel::ADMIN: return "ADMIN";
                case AccessLevel::SUPER_ADMIN: return "SUPER_ADMIN";
                default: return "UNKNOWN";
            }
        }

        AccessLevel StringToAccessLevel(const std::string& level_str) {
            if (level_str == "READ_ONLY") return AccessLevel::READ_ONLY;
            if (level_str == "READ_WRITE") return AccessLevel::READ_WRITE;
            if (level_str == "ADMIN") return AccessLevel::ADMIN;
            if (level_str == "SUPER_ADMIN") return AccessLevel::SUPER_ADMIN;
            return AccessLevel::NONE;
        }

        std::string AuthStatusToString(AuthStatus status) {
            switch (status) {
                case AuthStatus::NOT_AUTHORIZED: return "NOT_AUTHORIZED";
                case AuthStatus::AUTHORIZED: return "AUTHORIZED";
                case AuthStatus::EXPIRED: return "EXPIRED";
                case AuthStatus::INVALID: return "INVALID";
                case AuthStatus::BLOCKED: return "BLOCKED";
                case AuthStatus::PENDING_REFRESH: return "PENDING_REFRESH";
                default: return "UNKNOWN";
            }
        }

        std::string KeyTypeToString(KeyType type) {
            switch (type) {
                case KeyType::BEARER_TOKEN: return "BEARER_TOKEN";
                case KeyType::API_KEY: return "API_KEY";
                case KeyType::SESSION_TOKEN: return "SESSION_TOKEN";
                case KeyType::REFRESH_TOKEN: return "REFRESH_TOKEN";
                default: return "UNKNOWN";
            }
        }

        KeyType StringToKeyType(const std::string& type_str) {
            if (type_str == "BEARER_TOKEN") return KeyType::BEARER_TOKEN;
            if (type_str == "API_KEY") return KeyType::API_KEY;
            if (type_str == "SESSION_TOKEN") return KeyType::SESSION_TOKEN;
            if (type_str == "REFRESH_TOKEN") return KeyType::REFRESH_TOKEN;
            return KeyType::BEARER_TOKEN;
        }

        std::string GenerateSecureToken(size_t length) {
            const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, chars.size() - 1);

            std::string token;
            token.reserve(length);

            for (size_t i = 0; i < length; ++i) {
                token += chars[dis(gen)];
            }

            return token;
        }

        std::string GenerateSessionId() {
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            return "sess_" + std::to_string(timestamp) + "_" + GenerateSecureToken(16);
        }

        bool ValidateTokenFormat(const std::string& token) {
            if (token.empty() || token.length() < 16) {
                return false;
            }

            // Проверка на допустимые символы
            for (char c : token) {
                if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
                    return false;
                }
            }

            return true;
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()) % 1000;

            std::tm* tm = std::gmtime(&time_t);
            std::ostringstream oss;
            oss << std::put_time(tm, "%Y-%m-%dT%H:%M:%S");
            oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";

            return oss.str();
        }

        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str) {
            std::tm tm = {};
            std::istringstream ss(timestamp_str);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

            auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));

            // Парсинг миллисекунд если есть
            size_t dot_pos = timestamp_str.find('.');
            if (dot_pos != std::string::npos) {
                size_t ms_end = timestamp_str.find('Z', dot_pos);
                if (ms_end != std::string::npos && ms_end > dot_pos + 1) {
                    std::string ms_str = timestamp_str.substr(dot_pos + 1, ms_end - dot_pos - 1);
                    int ms = std::stoi(ms_str);
                    tp += std::chrono::milliseconds(ms);
                }
            }

            return tp;
        }

        std::string EncryptKey(const std::string& key, const std::string& encryption_key) {
            // Простое XOR шифрование (в реальной системе использовать AES)
            std::string encrypted = key;

            for (size_t i = 0; i < encrypted.length(); ++i) {
                encrypted[i] ^= encryption_key[i % encryption_key.length()];
            }

            // Base64 кодирование результата
            std::ostringstream encoded;
            encoded << std::hex;
            for (unsigned char c : encrypted) {
                encoded << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }

            return encoded.str();
        }

        std::string DecryptKey(const std::string& encrypted_key, const std::string& encryption_key) {
            // Декодирование из hex
            std::string binary;
            for (size_t i = 0; i < encrypted_key.length(); i += 2) {
                std::string byte_str = encrypted_key.substr(i, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
                binary += byte;
            }

            // XOR дешифрование
            for (size_t i = 0; i < binary.length(); ++i) {
                binary[i] ^= encryption_key[i % encryption_key.length()];
            }

            return binary;
        }

        std::string HashString(const std::string& input) {
            // Простое хэширование (в реальной системе использовать SHA-256)
            std::hash<std::string> hasher;
            return std::to_string(hasher(input));
        }

        bool VerifyHash(const std::string& input, const std::string& hash) {
            return HashString(input) == hash;
        }
    }
}