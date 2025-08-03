//
// Created by WhySkyDie on 21.07.2025.
//

#pragma once

#include <string>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <optional>
#include <unordered_set>
#include <filesystem>

namespace AuthState {

    // Уровень доступа
    enum class AccessLevel {
        NONE = 0,
        READ_ONLY = 1,
        READ_WRITE = 2,
        ADMIN = 3,
        SUPER_ADMIN = 4
    };

    // Статус авторизации
    enum class AuthStatus {
        NOT_AUTHORIZED,
        AUTHORIZED,
        EXPIRED,
        INVALID,
        BLOCKED,
        PENDING_REFRESH
    };

    // Тип ключа авторизации
    enum class KeyType {
        BEARER_TOKEN,
        API_KEY,
        SESSION_TOKEN,
        REFRESH_TOKEN
    };

    // Информация об авторизованном пользователе
    struct UserAuthInfo {
        std::string user_id;
        std::string username;
        std::string email;
        AccessLevel access_level;
        std::unordered_set<std::string> permissions;
        std::chrono::system_clock::time_point login_time;
        std::chrono::system_clock::time_point expires_at;
        std::string session_id;
        std::string client_ip;
        std::unordered_map<std::string, std::string> metadata;

        UserAuthInfo() : access_level(AccessLevel::NONE) {}

        bool IsExpired() const {
            return std::chrono::system_clock::now() >= expires_at;
        }
    };

    // Ключ авторизации
    struct AuthKey {
        std::string key_value;
        KeyType key_type;
        std::string user_id;
        AccessLevel access_level;
        std::chrono::system_clock::time_point issued_at;
        std::chrono::system_clock::time_point expires_at;
        std::chrono::system_clock::time_point last_used;
        std::string issuer;
        std::string scope;
        bool is_active;

        AuthKey() : key_type(KeyType::BEARER_TOKEN), access_level(AccessLevel::NONE), is_active(true) {
            issued_at = std::chrono::system_clock::now();
            last_used = issued_at;
        }

        bool IsExpired() const {
            return std::chrono::system_clock::now() >= expires_at;
        }

        bool IsValid() const {
            return is_active && !IsExpired() && !key_value.empty();
        }
    };

    // Результат проверки авторизации
    struct AuthCheckResult {
        bool authorized;
        AuthStatus status;
        std::string error_message;
        std::optional<UserAuthInfo> user_info;
        AccessLevel effective_access_level;
        std::chrono::milliseconds check_time{0};

        AuthCheckResult() : authorized(false), status(AuthStatus::NOT_AUTHORIZED),
                           effective_access_level(AccessLevel::NONE) {}
    };

    // Конфигурация состояния авторизации
    struct AuthStateConfig {
        // Время жизни токенов
        std::chrono::minutes default_token_lifetime{60};
        std::chrono::minutes refresh_token_lifetime{1440}; // 24 часа

        // Проверки безопасности
        bool strict_expiration_check = true;
        bool validate_ip_address = false;
        bool require_https = true;

        // Кэширование
        bool cache_user_info = true;
        std::chrono::minutes cache_lifetime{15};

        // Хранение
        bool persistent_storage = true;
        std::filesystem::path storage_path;
        std::string encryption_key;

        // Логирование
        bool log_auth_events = true;
        bool log_failed_attempts = true;

        // Очистка
        std::chrono::minutes cleanup_interval{30};
        bool auto_cleanup_expired = true;

        AuthStateConfig() {
            storage_path = std::filesystem::temp_directory_path() / "auth_state";
        }
    };

    // Callback типы
    using AuthEventCallback = std::function<void(const std::string& event, const std::string& user_id, const std::string& details)>;
    using TokenRefreshCallback = std::function<std::optional<AuthKey>(const AuthKey& expired_key)>;
    using UserInfoCallback = std::function<std::optional<UserAuthInfo>(const std::string& user_id)>;

    // Основной класс управления состоянием авторизации
    class AuthStateManager {
    public:
        explicit AuthStateManager(const AuthStateConfig& config = AuthStateConfig{});
        ~AuthStateManager();

        // Инициализация
        bool Initialize();
        void Shutdown();
        bool IsInitialized() const;

        // Конфигурация
        void SetConfig(const AuthStateConfig& config);
        const AuthStateConfig& GetConfig() const;

        // Установка ключей авторизации
        bool SetAuthKey(const AuthKey& key);
        bool SetAuthKey(const std::string& key_value, KeyType type,
                       const std::string& user_id, AccessLevel access_level,
                       std::chrono::minutes lifetime = std::chrono::minutes{60});

        // Получение текущего ключа
        std::optional<AuthKey> GetCurrentAuthKey() const;
        std::optional<AuthKey> GetAuthKey(const std::string& key_value) const;

        // Проверка авторизации
        AuthCheckResult CheckAuthorization() const;
        AuthCheckResult CheckAuthorization(const std::string& key_value) const;
        AuthCheckResult CheckAuthorization(const std::string& key_value,
                                          AccessLevel required_level) const;
        AuthCheckResult CheckAuthorization(const std::string& key_value,
                                          const std::string& required_permission) const;

        // Проверка разрешений
        bool HasPermission(const std::string& permission) const;
        bool HasAccessLevel(AccessLevel required_level) const;
        std::unordered_set<std::string> GetUserPermissions() const;
        AccessLevel GetUserAccessLevel() const;

        // Информация о пользователе
        std::optional<UserAuthInfo> GetCurrentUserInfo() const;
        std::optional<UserAuthInfo> GetUserInfo(const std::string& user_id) const;
        bool UpdateUserInfo(const UserAuthInfo& user_info);

        // Управление сессией
        bool RefreshCurrentToken();
        bool RevokeAuthKey(const std::string& key_value);
        bool RevokeAllUserKeys(const std::string& user_id);
        bool IsCurrentSessionValid() const;

        // Очистка и обслуживание
        size_t CleanupExpiredKeys();
        size_t CleanupExpiredCache();
        void ClearAllKeys();

        // Настройка callbacks
        void SetAuthEventCallback(AuthEventCallback callback);
        void SetTokenRefreshCallback(TokenRefreshCallback callback);
        void SetUserInfoCallback(UserInfoCallback callback);

        // Статистика
        size_t GetActiveKeysCount() const;
        size_t GetExpiredKeysCount() const;
        std::chrono::system_clock::time_point GetLastAuthCheck() const;

        // Сериализация/десериализация
        bool SaveToFile(const std::filesystem::path& file_path) const;
        bool LoadFromFile(const std::filesystem::path& file_path);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Декоратор для автоматической проверки авторизации
    class AuthDecorator {
    public:
        explicit AuthDecorator(std::shared_ptr<AuthStateManager> auth_manager);

        // Обертки для методов с проверкой авторизации
        template<typename Func, typename... Args>
        auto WithAuth(Func&& func, Args&&... args)
            -> decltype(func(std::forward<Args>(args)...)) {

            auto auth_result = auth_manager_->CheckAuthorization();
            if (!auth_result.authorized) {
                throw std::runtime_error("Not authorized: " + auth_result.error_message);
            }

            return func(std::forward<Args>(args)...);
        }

        template<typename Func, typename... Args>
        auto WithAuthLevel(AccessLevel required_level, Func&& func, Args&&... args)
            -> decltype(func(std::forward<Args>(args)...)) {

            auto auth_result = auth_manager_->CheckAuthorization();
            if (!auth_result.authorized) {
                throw std::runtime_error("Not authorized: " + auth_result.error_message);
            }

            if (auth_result.effective_access_level < required_level) {
                throw std::runtime_error("Insufficient access level");
            }

            return func(std::forward<Args>(args)...);
        }

        template<typename Func, typename... Args>
        auto WithPermission(const std::string& permission, Func&& func, Args&&... args)
            -> decltype(func(std::forward<Args>(args)...)) {

            auto auth_result = auth_manager_->CheckAuthorization(
                auth_manager_->GetCurrentAuthKey()->key_value, permission);

            if (!auth_result.authorized) {
                throw std::runtime_error("Permission denied: " + permission);
            }

            return func(std::forward<Args>(args)...);
        }

    private:
        std::shared_ptr<AuthStateManager> auth_manager_;
    };

    // Singleton для глобального доступа к состоянию авторизации
    class GlobalAuthState {
    public:
        static GlobalAuthState& Instance();

        void Initialize(const AuthStateConfig& config = AuthStateConfig{});
        void Shutdown();

        std::shared_ptr<AuthStateManager> GetAuthManager();
        AuthCheckResult QuickAuthCheck();
        bool IsGloballyAuthorized();

    private:
        GlobalAuthState() = default;
        ~GlobalAuthState() = default;
        GlobalAuthState(const GlobalAuthState&) = delete;
        GlobalAuthState& operator=(const GlobalAuthState&) = delete;

        std::shared_ptr<AuthStateManager> auth_manager_;
        std::once_flag initialized_flag_;
    };

    // Утилитарные функции
    namespace Utils {
        // Конвертация enum'ов в строки
        std::string AccessLevelToString(AccessLevel level);
        AccessLevel StringToAccessLevel(const std::string& level_str);

        std::string AuthStatusToString(AuthStatus status);
        AuthStatus StringToAuthStatus(const std::string& status_str);

        std::string KeyTypeToString(KeyType type);
        KeyType StringToKeyType(const std::string& type_str);

        // Генерация токенов
        std::string GenerateSecureToken(size_t length = 32);
        std::string GenerateSessionId();

        // Валидация
        bool ValidateTokenFormat(const std::string& token);
        bool ValidateUserPermissions(const std::unordered_set<std::string>& permissions);

        // Время
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str);

        // Шифрование
        std::string EncryptKey(const std::string& key, const std::string& encryption_key);
        std::string DecryptKey(const std::string& encrypted_key, const std::string& encryption_key);

        // Хэширование
        std::string HashString(const std::string& input);
        bool VerifyHash(const std::string& input, const std::string& hash);

        // IP адреса
        bool ValidateIPAddress(const std::string& ip);
        bool IsIPInRange(const std::string& ip, const std::string& range);
    }

    // Макросы для удобной проверки авторизации
    #define REQUIRE_AUTH(auth_manager) \
        do { \
            auto __auth_result = (auth_manager)->CheckAuthorization(); \
            if (!__auth_result.authorized) { \
                throw std::runtime_error("Authorization required: " + __auth_result.error_message); \
            } \
        } while(0)

    #define REQUIRE_ACCESS_LEVEL(auth_manager, level) \
        do { \
            auto __auth_result = (auth_manager)->CheckAuthorization(); \
            if (!__auth_result.authorized || __auth_result.effective_access_level < (level)) { \
                throw std::runtime_error("Insufficient access level required"); \
            } \
        } while(0)

    #define REQUIRE_PERMISSION(auth_manager, permission) \
        do { \
            if (!(auth_manager)->HasPermission(permission)) { \
                throw std::runtime_error("Permission required: " + std::string(permission)); \
            } \
        } while(0)
}