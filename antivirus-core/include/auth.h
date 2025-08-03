//
// Created by WhySkyDie on 21.07.2025.
//

#ifndef AUTH_H
#define AUTH_H

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <unordered_map>
#include <optional>

namespace ClientAuth {

    // Статус аутентификации клиента
    enum class AuthStatus {
        NOT_AUTHENTICATED,
        AUTHENTICATING,
        AUTHENTICATED,
        TOKEN_EXPIRED,
        TOKEN_INVALID,
        CONNECTION_ERROR,
        SERVER_ERROR
    };

    // Типы токенов
    enum class TokenType {
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        REGISTRATION_TOKEN
    };

    // Информация о пользователе
    struct UserInfo {
        std::string user_id;
        std::string username;
        std::string email;
        std::string display_name;
        std::string role;
        std::vector<std::string> permissions;

        std::chrono::system_clock::time_point login_time;
        std::chrono::system_clock::time_point token_expires_at;

        bool is_active;
        std::unordered_map<std::string, std::string> metadata;

        UserInfo() : is_active(false) {}
    };

    // Токен аутентификации
    struct AuthToken {
        std::string token_value;
        TokenType type;
        std::chrono::system_clock::time_point issued_at;
        std::chrono::system_clock::time_point expires_at;
        std::string scope;
        bool is_valid;

        AuthToken() : type(TokenType::ACCESS_TOKEN), is_valid(false) {}

        bool IsExpired() const {
            return std::chrono::system_clock::now() >= expires_at;
        }
    };

    // Результат операции аутентификации
    struct AuthResult {
        bool success;
        AuthStatus status;
        std::string error_message;
        std::string error_code;

        std::optional<UserInfo> user_info;
        std::optional<AuthToken> access_token;
        std::optional<AuthToken> refresh_token;

        std::chrono::milliseconds operation_time{0};

        AuthResult() : success(false), status(AuthStatus::NOT_AUTHENTICATED) {}
    };

    // Конфигурация клиента
    struct ClientConfig {
        std::string server_url;
        std::string api_version = "v1";
        std::string client_id;
        std::string client_secret;

        // SSL/TLS настройки
        std::string ca_cert_path;
        bool verify_ssl = true;

        // Тайм-ауты
        std::chrono::seconds connection_timeout{30};
        std::chrono::seconds request_timeout{60};

        // Токены
        std::chrono::minutes token_refresh_threshold{5}; // Обновлять токен за 5 минут до истечения
        bool auto_refresh_tokens = true;

        // Кэширование
        bool cache_tokens = true;
        std::filesystem::path cache_file_path;

        // Прокси
        std::string proxy_url;
        std::string proxy_username;
        std::string proxy_password;

        ClientConfig() {
            cache_file_path = std::filesystem::temp_directory_path() / "auth_cache.dat";
        }
    };

    struct AuthToken {
        std::string token;
        std::chrono::system_clock::time_point expiry_time;
        std::string device_id;
        std::string email;
        bool is_valid;

        AuthToken() : is_valid(false) {}
        AuthToken(const std::string& tk, const std::chrono::system_clock::time_point& expiry,
                  const std::string& dev_id, const std::string& user_email);

        bool is_expired() const;
    };

    struct DeviceInfo {
        std::string device_id;
        std::string email;
        std::chrono::system_clock::time_point registration_time;
        std::chrono::system_clock::time_point last_login_time;
        bool is_active;

        DeviceInfo() : is_active(false) {}
        DeviceInfo(const std::string& dev_id, const std::string& user_email);
    };

    // Callback типы
    using AuthStatusCallback = std::function<void(AuthStatus status, const std::string& message)>;
    using TokenRefreshCallback = std::function<void(const AuthToken& new_token)>;
    using ConnectionErrorCallback = std::function<void(const std::string& error_message)>;

    class AuthManager {
    private:
        std::filesystem::path auth_state_file;
        std::string current_device_id;
        AuthToken current_token;
        std::unordered_map<std::string, DeviceInfo> registered_devices;
        std::mutex auth_mutex;

        // Настройки
        std::chrono::hours token_validity_period;
        size_t max_devices_per_email;

        // Вспомогательные методы
        std::string generate_device_id() const;
        std::string hash_token(const std::string& token) const;
        bool validate_email(const std::string& email) const;
        bool validate_token_format(const std::string& token) const;
        std::string encrypt_data(const std::string& data) const;
        std::string decrypt_data(const std::string& encrypted_data) const;

    public:
        explicit AuthManager(const std::filesystem::path& state_file = "./auth_state.dat",
                            std::chrono::hours token_validity = std::chrono::hours(24),
                            size_t max_devices = 5);
        ~AuthManager();

        // Основные методы с исправленными сигнатурами
        bool login(const std::string& device_id, const std::string& token);
        bool register_device(const std::string& email, const std::string& token);
        bool is_authenticated() const;
        void save_auth_state();
        void load_auth_state();

        // Дополнительные методы
        bool logout();
        bool revoke_device(const std::string& device_id);
        bool refresh_token(const std::string& new_token);
        std::vector<DeviceInfo> get_registered_devices(const std::string& email) const;
        void cleanup_expired_tokens();

        // Настройки
        void set_token_validity_period(std::chrono::hours hours);
        void set_max_devices_per_email(size_t max_devices);

        // Информационные методы
        std::string get_current_device_id() const;
        std::string get_current_email() const;
        std::chrono::system_clock::time_point get_token_expiry() const;
        size_t get_registered_devices_count() const;
    };

    // Основной класс клиента аутентификации
    class AuthClient {
    public:
        AuthClient();
        explicit AuthClient(const ClientConfig& config);
        ~AuthClient();

        // Инициализация
        bool Initialize();
        bool Initialize(const ClientConfig& config);
        void Shutdown();
        bool IsInitialized() const;

        // Конфигурация
        void SetConfig(const ClientConfig& config);
        const ClientConfig& GetConfig() const;

        // Callbacks
        void SetAuthStatusCallback(AuthStatusCallback callback);
        void SetTokenRefreshCallback(TokenRefreshCallback callback);
        void SetConnectionErrorCallback(ConnectionErrorCallback callback);

        // Аутентификация
        AuthResult Login(const std::string& username, const std::string& password);
        AuthResult LoginWithToken(const std::string& token_value);

        // Регистрация
        AuthResult RegisterWithToken(const std::string& registration_token,
                                    const std::string& username,
                                    const std::string& password,
                                    const std::string& email = "");

        // Управление сессией
        bool Logout();
        bool IsAuthenticated() const;
        AuthStatus GetAuthStatus() const;

        // Информация о пользователе
        std::optional<UserInfo> GetCurrentUser() const;
        std::vector<std::string> GetUserPermissions() const;
        bool HasPermission(const std::string& permission) const;

        // Управление токенами
        std::optional<AuthToken> GetAccessToken() const;
        std::optional<AuthToken> GetRefreshToken() const;
        AuthResult RefreshAccessToken();
        bool IsTokenExpired() const;
        std::chrono::seconds GetTokenTimeToExpiry() const;

        // Автоматическое обновление
        void StartAutoRefresh();
        void StopAutoRefresh();
        bool IsAutoRefreshEnabled() const;

        // Проверка соединения
        bool CheckServerConnection() const;
        bool ValidateCurrentToken() const;

        // Кэширование
        bool SaveTokensToCache() const;
        bool LoadTokensFromCache();
        void ClearTokenCache();

        // Утилиты
        std::string GetAuthorizationHeader() const;
        std::chrono::system_clock::time_point GetLastActivity() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // HTTP клиент для взаимодействия с сервером
    class HttpClient {
    public:
        HttpClient();
        ~HttpClient();

        struct HttpResponse {
            int status_code;
            std::string body;
            std::unordered_map<std::string, std::string> headers;
            bool success;
            std::string error_message;
        };

        // HTTP методы
        HttpResponse Get(const std::string& url,
                        const std::unordered_map<std::string, std::string>& headers = {});
        HttpResponse Post(const std::string& url,
                         const std::string& body,
                         const std::unordered_map<std::string, std::string>& headers = {});

        // Настройки
        void SetTimeout(std::chrono::seconds timeout);
        void SetProxy(const std::string& proxy_url,
                     const std::string& username = "",
                     const std::string& password = "");
        void SetSSLVerification(bool verify);
        void SetCACertPath(const std::string& ca_cert_path);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер токенов
    class TokenManager {
    public:
        TokenManager();
        ~TokenManager();

        // Управление токенами
        void StoreTokens(const AuthToken& access_token,
                        const AuthToken& refresh_token = AuthToken{});
        std::optional<AuthToken> GetAccessToken() const;
        std::optional<AuthToken> GetRefreshToken() const;
        void ClearTokens();

        // Проверки
        bool HasValidAccessToken() const;
        bool IsAccessTokenExpired() const;
        bool ShouldRefreshToken(std::chrono::minutes threshold = std::chrono::minutes{5}) const;

        // Сериализация
        bool SaveToFile(const std::filesystem::path& file_path) const;
        bool LoadFromFile(const std::filesystem::path& file_path);

        // Шифрование токенов
        void SetEncryptionKey(const std::string& key);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        std::string AuthStatusToString(AuthStatus status);
        AuthStatus StringToAuthStatus(const std::string& status_str);

        std::string TokenTypeToString(TokenType type);
        TokenType StringToTokenType(const std::string& type_str);

        // Время
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str);

        // Валидация
        bool IsValidEmail(const std::string& email);
        bool IsValidUsername(const std::string& username);
        bool IsValidPassword(const std::string& password, int min_length = 8);

        // Кодирование
        std::string Base64Encode(const std::string& data);
        std::string Base64Decode(const std::string& encoded_data);
        std::string UrlEncode(const std::string& data);

        // Шифрование
        std::string EncryptString(const std::string& data, const std::string& key);
        std::string DecryptString(const std::string& encrypted_data, const std::string& key);

        // Разное
        std::string GenerateClientId();
        std::string GetUserAgent();
        std::string CreateDeviceFingerprint();
    }
}

#endif // AUTH_H