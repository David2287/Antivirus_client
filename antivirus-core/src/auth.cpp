//
// Created by WhySkyDie on 21.07.2025.
//


#include "auth.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <thread>
#include <json/json.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/utsname.h>
#endif

using json = nlohmann::json;

namespace ClientAuth {

    // Структура для обработки ответов CURL
    struct CurlWriteData {
        std::string data;

        static size_t WriteCallback(void* contents, size_t size, size_t nmemb, CurlWriteData* write_data) {
            size_t total_size = size * nmemb;
            write_data->data.append(static_cast<char*>(contents), total_size);
            return total_size;
        }
    };

    AuthToken::AuthToken(const std::string& tk, const std::chrono::system_clock::time_point& expiry,
                     const std::string& dev_id, const std::string& user_email)
    : token(tk), expiry_time(expiry), device_id(dev_id), email(user_email), is_valid(true) {}

    bool AuthToken::is_expired() const {
        return std::chrono::system_clock::now() > expiry_time;
    }

    DeviceInfo::DeviceInfo(const std::string& dev_id, const std::string& user_email)
        : device_id(dev_id), email(user_email),
          registration_time(std::chrono::system_clock::now()),
          last_login_time(std::chrono::system_clock::now()),
          is_active(true) {}

    AuthManager::AuthManager(const std::filesystem::path& state_file,
                            std::chrono::hours token_validity, size_t max_devices)
        : auth_state_file(state_file),
          token_validity_period(token_validity),
          max_devices_per_email(max_devices) {

        load_auth_state();
    }

    AuthManager::~AuthManager() {
        save_auth_state();
    }

    // Реализация HttpClient::Impl
    class HttpClient::Impl {
    public:
        CURL* curl_handle;
        std::chrono::seconds timeout{30};

        Impl() {
            curl_handle = curl_easy_init();
            if (curl_handle) {
                curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, timeout.count());
                curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, Utils::GetUserAgent().c_str());
            }
        }

        ~Impl() {
            if (curl_handle) {
                curl_easy_cleanup(curl_handle);
            }
        }

        HttpResponse ExecuteRequest(const std::string& method, const std::string& url,
                                   const std::string& body = "",
                                   const std::unordered_map<std::string, std::string>& headers = {}) {
            HttpResponse response;

            if (!curl_handle) {
                response.error_message = "CURL not initialized";
                return response;
            }

            CurlWriteData write_data;

            // Основные настройки
            curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, CurlWriteData::WriteCallback);
            curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &write_data);

            // Заголовки
            struct curl_slist* header_list = nullptr;
            for (const auto& header : headers) {
                std::string header_str = header.first + ": " + header.second;
                header_list = curl_slist_append(header_list, header_str.c_str());
            }

            if (header_list) {
                curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, header_list);
            }

            // Метод и тело запроса
            if (method == "POST") {
                curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
                if (!body.empty()) {
                    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, body.c_str());
                    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, body.length());
                }
            }

            // Выполнение запроса
            CURLcode res = curl_easy_perform(curl_handle);

            if (header_list) {
                curl_slist_free_all(header_list);
            }

            if (res != CURLE_OK) {
                response.error_message = curl_easy_strerror(res);
                return response;
            }

            // Получение кода статуса
            long response_code;
            curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);

            response.success = true;
            response.status_code = static_cast<int>(response_code);
            response.body = write_data.data;

            return response;
        }
    };

    // Реализация TokenManager::Impl
    class TokenManager::Impl {
    public:
        std::optional<AuthToken> access_token;
        std::optional<AuthToken> refresh_token;
        std::string encryption_key;
        mutable std::mutex tokens_mutex;

        Json::Value TokenToJson(const AuthToken& token) const {
            Json::Value json_token;
            json_token["token_value"] = token.token_value;
            json_token["type"] = static_cast<int>(token.type);
            json_token["issued_at"] = Utils::FormatTimestamp(token.issued_at);
            json_token["expires_at"] = Utils::FormatTimestamp(token.expires_at);
            json_token["scope"] = token.scope;
            json_token["is_valid"] = token.is_valid;
            return json_token;
        }

        AuthToken JsonToToken(const Json::Value& json_token) const {
            AuthToken token;
            token.token_value = json_token.get("token_value", "").asString();
            token.type = static_cast<TokenType>(json_token.get("type", 0).asInt());
            token.issued_at = Utils::ParseTimestamp(json_token.get("issued_at", "").asString());
            token.expires_at = Utils::ParseTimestamp(json_token.get("expires_at", "").asString());
            token.scope = json_token.get("scope", "").asString();
            token.is_valid = json_token.get("is_valid", false).asBool();
            return token;
        }
    };

    // Реализация AuthClient::Impl
    class AuthClient::Impl {
    public:
        ClientConfig config;
        std::atomic<bool> initialized{false};
        std::atomic<bool> authenticated{false};
        std::atomic<AuthStatus> auth_status{AuthStatus::NOT_AUTHENTICATED};

        std::optional<UserInfo> current_user;
        TokenManager token_manager;
        HttpClient http_client;

        mutable std::mutex auth_mutex;

        // Callbacks
        AuthStatusCallback auth_status_callback;
        TokenRefreshCallback token_refresh_callback;
        ConnectionErrorCallback connection_error_callback;

        // Автообновление токенов
        std::thread auto_refresh_thread;
        std::atomic<bool> auto_refresh_enabled{false};
        std::atomic<bool> should_stop_auto_refresh{false};

        std::chrono::system_clock::time_point last_activity;

        Impl() {
            last_activity = std::chrono::system_clock::now();
        }

        ~Impl() {
            StopAutoRefresh();
        }

        bool InitializeImpl() {
            if (initialized.load()) {
                return true;
            }

            try {
                // Настройка HTTP клиента
                http_client.SetTimeout(config.connection_timeout);
                if (!config.proxy_url.empty()) {
                    http_client.SetProxy(config.proxy_url, config.proxy_username, config.proxy_password);
                }
                http_client.SetSSLVerification(config.verify_ssl);
                if (!config.ca_cert_path.empty()) {
                    http_client.SetCACertPath(config.ca_cert_path);
                }

                // Загрузка кэшированных токенов
                if (config.cache_tokens && !config.cache_file_path.empty()) {
                    token_manager.LoadFromFile(config.cache_file_path);

                    // Проверка валидности загруженных токенов
                    if (token_manager.HasValidAccessToken()) {
                        authenticated = true;
                        auth_status = AuthStatus::AUTHENTICATED;

                        // Попытка получить информацию о пользователе
                        LoadUserInfo();
                    }
                }

                initialized = true;
                return true;

            } catch (const std::exception& e) {
                NotifyConnectionError("Initialization failed: " + std::string(e.what()));
                return false;
            }
        }

        void Shutdown() {
            StopAutoRefresh();

            if (config.cache_tokens && token_manager.HasValidAccessToken()) {
                token_manager.SaveToFile(config.cache_file_path);
            }

            initialized = false;
            authenticated = false;
            auth_status = AuthStatus::NOT_AUTHENTICATED;
        }

        AuthResult LoginImpl(const std::string& username, const std::string& password) {
            AuthResult result;
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                UpdateAuthStatus(AuthStatus::AUTHENTICATING);

                // Подготовка данных для запроса
                Json::Value request_data;
                request_data["grant_type"] = "password";
                request_data["username"] = username;
                request_data["password"] = password;
                request_data["client_id"] = config.client_id;
                if (!config.client_secret.empty()) {
                    request_data["client_secret"] = config.client_secret;
                }
                request_data["device_fingerprint"] = Utils::CreateDeviceFingerprint();

                Json::StreamWriterBuilder builder;
                std::string json_body = Json::writeString(builder, request_data);

                // Подготовка заголовков
                std::unordered_map<std::string, std::string> headers;
                headers["Content-Type"] = "application/json";
                headers["Accept"] = "application/json";
                headers["User-Agent"] = Utils::GetUserAgent();

                // Отправка запроса
                std::string url = config.server_url + "/auth/" + config.api_version + "/login";
                auto response = http_client.Post(url, json_body, headers);

                if (!response.success) {
                    result.error_message = "HTTP request failed: " + response.error_message;
                    result.status = AuthStatus::CONNECTION_ERROR;
                    UpdateAuthStatus(AuthStatus::CONNECTION_ERROR);
                    NotifyConnectionError(result.error_message);
                    return result;
                }

                // Обработка ответа сервера
                if (response.status_code >= 200 && response.status_code < 300) {
                    result = ProcessLoginResponse(response.body);

                    if (result.success) {
                        authenticated = true;
                        UpdateAuthStatus(AuthStatus::AUTHENTICATED);

                        // Сохранение токенов
                        if (result.access_token && result.refresh_token) {
                            token_manager.StoreTokens(*result.access_token, *result.refresh_token);

                            if (config.cache_tokens) {
                                token_manager.SaveToFile(config.cache_file_path);
                            }
                        }

                        // Сохранение информации о пользователе
                        if (result.user_info) {
                            std::lock_guard<std::mutex> lock(auth_mutex);
                            current_user = *result.user_info;
                        }

                        // Запуск автообновления токенов
                        if (config.auto_refresh_tokens) {
                            StartAutoRefresh();
                        }

                        last_activity = std::chrono::system_clock::now();
                    } else {
                        UpdateAuthStatus(AuthStatus::TOKEN_INVALID);
                    }
                } else {
                    result.error_message = "Server error: " + std::to_string(response.status_code);
                    result.status = AuthStatus::SERVER_ERROR;

                    // Попытка извлечь детали ошибки из ответа
                    try {
                        Json::Value error_response;
                        Json::Reader reader;
                        if (reader.parse(response.body, error_response)) {
                            if (error_response.isMember("error_description")) {
                                result.error_message = error_response["error_description"].asString();
                            }
                            if (error_response.isMember("error_code")) {
                                result.error_code = error_response["error_code"].asString();
                            }
                        }
                    } catch (...) {
                        // Игнорируем ошибки парсинга
                    }

                    UpdateAuthStatus(AuthStatus::SERVER_ERROR);
                }

                auto end_time = std::chrono::high_resolution_clock::now();
                result.operation_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Login error: " + std::string(e.what());
                result.status = AuthStatus::CONNECTION_ERROR;
                UpdateAuthStatus(AuthStatus::CONNECTION_ERROR);
                NotifyConnectionError(result.error_message);
                return result;
            }
        }

        AuthResult RegisterImpl(const std::string& registration_token,
                               const std::string& username,
                               const std::string& password,
                               const std::string& email) {
            AuthResult result;

            try {
                // Валидация входных данных
                if (!Utils::IsValidUsername(username)) {
                    result.error_message = "Invalid username format";
                    return result;
                }

                if (!Utils::IsValidPassword(password)) {
                    result.error_message = "Password does not meet requirements";
                    return result;
                }

                if (!email.empty() && !Utils::IsValidEmail(email)) {
                    result.error_message = "Invalid email format";
                    return result;
                }

                // Подготовка данных
                Json::Value request_data;
                request_data["registration_token"] = registration_token;
                request_data["username"] = username;
                request_data["password"] = password;
                if (!email.empty()) {
                    request_data["email"] = email;
                }
                request_data["client_id"] = config.client_id;
                request_data["device_fingerprint"] = Utils::CreateDeviceFingerprint();

                Json::StreamWriterBuilder builder;
                std::string json_body = Json::writeString(builder, request_data);

                // Подготовка заголовков
                std::unordered_map<std::string, std::string> headers;
                headers["Content-Type"] = "application/json";
                headers["Accept"] = "application/json";

                // Отправка запроса
                std::string url = config.server_url + "/auth/" + config.api_version + "/register";
                auto response = http_client.Post(url, json_body, headers);

                if (!response.success) {
                    result.error_message = "HTTP request failed: " + response.error_message;
                    return result;
                }

                if (response.status_code >= 200 && response.status_code < 300) {
                    result.success = true;
                    result.status = AuthStatus::NOT_AUTHENTICATED; // После регистрации нужен отдельный логин
                } else {
                    result.error_message = "Registration failed: " + std::to_string(response.status_code);
                }

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Registration error: " + std::string(e.what());
                return result;
            }
        }

        AuthResult ProcessLoginResponse(const std::string& response_body) {
            AuthResult result;

            try {
                Json::Value response_json;
                Json::Reader reader;

                if (!reader.parse(response_body, response_json)) {
                    result.error_message = "Invalid server response format";
                    return result;
                }

                // Извлечение токенов
                if (response_json.isMember("access_token")) {
                    AuthToken access_token;
                    access_token.token_value = response_json["access_token"].asString();
                    access_token.type = TokenType::ACCESS_TOKEN;
                    access_token.issued_at = std::chrono::system_clock::now();

                    // Время истечения токена
                    if (response_json.isMember("expires_in")) {
                        int expires_in = response_json["expires_in"].asInt();
                        access_token.expires_at = access_token.issued_at + std::chrono::seconds{expires_in};
                    } else {
                        access_token.expires_at = access_token.issued_at + std::chrono::hours{1}; // По умолчанию 1 час
                    }

                    if (response_json.isMember("scope")) {
                        access_token.scope = response_json["scope"].asString();
                    }

                    access_token.is_valid = true;
                    result.access_token = access_token;
                }

                // Refresh token
                if (response_json.isMember("refresh_token")) {
                    AuthToken refresh_token;
                    refresh_token.token_value = response_json["refresh_token"].asString();
                    refresh_token.type = TokenType::REFRESH_TOKEN;
                    refresh_token.issued_at = std::chrono::system_clock::now();
                    refresh_token.expires_at = refresh_token.issued_at + std::chrono::hours{24 * 7}; // 7 дней
                    refresh_token.is_valid = true;
                    result.refresh_token = refresh_token;
                }

                // Информация о пользователе
                if (response_json.isMember("user")) {
                    const Json::Value& user_json = response_json["user"];

                    UserInfo user_info;
                    user_info.user_id = user_json.get("user_id", "").asString();
                    user_info.username = user_json.get("username", "").asString();
                    user_info.email = user_json.get("email", "").asString();
                    user_info.display_name = user_json.get("display_name", "").asString();
                    user_info.role = user_json.get("role", "user").asString();
                    user_info.is_active = user_json.get("is_active", true).asBool();
                    user_info.login_time = std::chrono::system_clock::now();

                    if (result.access_token) {
                        user_info.token_expires_at = result.access_token->expires_at;
                    }

                    // Разрешения
                    if (user_json.isMember("permissions") && user_json["permissions"].isArray()) {
                        for (const auto& perm : user_json["permissions"]) {
                            user_info.permissions.push_back(perm.asString());
                        }
                    }

                    // Метаданные
                    if (user_json.isMember("metadata") && user_json["metadata"].isObject()) {
                        for (const auto& key : user_json["metadata"].getMemberNames()) {
                            user_info.metadata[key] = user_json["metadata"][key].asString();
                        }
                    }

                    result.user_info = user_info;
                }

                result.success = true;
                result.status = AuthStatus::AUTHENTICATED;

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Response processing error: " + std::string(e.what());
                return result;
            }
        }

        bool LogoutImpl() {
            try {
                if (authenticated.load()) {
                    // Уведомление сервера о выходе
                    auto access_token = token_manager.GetAccessToken();
                    if (access_token) {
                        std::unordered_map<std::string, std::string> headers;
                        headers["Authorization"] = "Bearer " + access_token->token_value;
                        headers["Content-Type"] = "application/json";

                        std::string url = config.server_url + "/auth/" + config.api_version + "/logout";
                        http_client.Post(url, "{}", headers);
                    }
                }

                StopAutoRefresh();

                // Очистка состояния
                {
                    std::lock_guard<std::mutex> lock(auth_mutex);
                    current_user.reset();
                }

                token_manager.ClearTokens();

                if (config.cache_tokens) {
                    std::filesystem::remove(config.cache_file_path);
                }

                authenticated = false;
                UpdateAuthStatus(AuthStatus::NOT_AUTHENTICATED);

                return true;

            } catch (const std::exception& e) {
                NotifyConnectionError("Logout error: " + std::string(e.what()));
                return false;
            }
        }

        AuthResult RefreshTokenImpl() {
            AuthResult result;

            try {
                auto refresh_token = token_manager.GetRefreshToken();
                if (!refresh_token || refresh_token->IsExpired()) {
                    result.error_message = "No valid refresh token available";
                    result.status = AuthStatus::TOKEN_EXPIRED;
                    UpdateAuthStatus(AuthStatus::TOKEN_EXPIRED);
                    return result;
                }

                // Подготовка запроса
                Json::Value request_data;
                request_data["grant_type"] = "refresh_token";
                request_data["refresh_token"] = refresh_token->token_value;
                request_data["client_id"] = config.client_id;

                Json::StreamWriterBuilder builder;
                std::string json_body = Json::writeString(builder, request_data);

                std::unordered_map<std::string, std::string> headers;
                headers["Content-Type"] = "application/json";
                headers["Accept"] = "application/json";

                std::string url = config.server_url + "/auth/" + config.api_version + "/refresh";
                auto response = http_client.Post(url, json_body, headers);

                if (!response.success) {
                    result.error_message = "HTTP request failed: " + response.error_message;
                    result.status = AuthStatus::CONNECTION_ERROR;
                    return result;
                }

                if (response.status_code >= 200 && response.status_code < 300) {
                    result = ProcessLoginResponse(response.body);

                    if (result.success && result.access_token) {
                        // Обновление токенов
                        AuthToken new_refresh = refresh_token.value();
                        if (result.refresh_token) {
                            new_refresh = *result.refresh_token;
                        }

                        token_manager.StoreTokens(*result.access_token, new_refresh);

                        if (config.cache_tokens) {
                            token_manager.SaveToFile(config.cache_file_path);
                        }

                        last_activity = std::chrono::system_clock::now();

                        // Callback
                        if (token_refresh_callback) {
                            token_refresh_callback(*result.access_token);
                        }
                    }
                } else {
                    result.error_message = "Token refresh failed: " + std::to_string(response.status_code);
                    result.status = AuthStatus::TOKEN_INVALID;
                    UpdateAuthStatus(AuthStatus::TOKEN_INVALID);
                }

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Token refresh error: " + std::string(e.what());
                result.status = AuthStatus::CONNECTION_ERROR;
                return result;
            }
        }

        void LoadUserInfo() {
            try {
                auto access_token = token_manager.GetAccessToken();
                if (!access_token) {
                    return;
                }

                std::unordered_map<std::string, std::string> headers;
                headers["Authorization"] = "Bearer " + access_token->token_value;
                headers["Accept"] = "application/json";

                std::string url = config.server_url + "/auth/" + config.api_version + "/userinfo";
                auto response = http_client.Get(url, headers);

                if (response.success && response.status_code == 200) {
                    Json::Value user_json;
                    Json::Reader reader;

                    if (reader.parse(response.body, user_json)) {
                        UserInfo user_info;
                        user_info.user_id = user_json.get("user_id", "").asString();
                        user_info.username = user_json.get("username", "").asString();
                        user_info.email = user_json.get("email", "").asString();
                        user_info.display_name = user_json.get("display_name", "").asString();
                        user_info.role = user_json.get("role", "user").asString();
                        user_info.is_active = user_json.get("is_active", true).asBool();
                        user_info.token_expires_at = access_token->expires_at;

                        if (user_json.isMember("permissions") && user_json["permissions"].isArray()) {
                            for (const auto& perm : user_json["permissions"]) {
                                user_info.permissions.push_back(perm.asString());
                            }
                        }

                        std::lock_guard<std::mutex> lock(auth_mutex);
                        current_user = user_info;
                    }
                }

            } catch (const std::exception&) {
                // Игнорируем ошибки получения пользовательской информации
            }
        }

        void StartAutoRefresh() {
            if (auto_refresh_enabled.load() || !config.auto_refresh_tokens) {
                return;
            }

            should_stop_auto_refresh = false;
            auto_refresh_enabled = true;

            auto_refresh_thread = std::thread([this]() {
                while (!should_stop_auto_refresh.load()) {
                    std::this_thread::sleep_for(std::chrono::minutes{1});

                    if (should_stop_auto_refresh.load()) {
                        break;
                    }

                    if (token_manager.ShouldRefreshToken(config.token_refresh_threshold)) {
                        auto result = RefreshTokenImpl();
                        if (!result.success) {
                            // При неудаче обновления токена уведомляем об ошибке
                            NotifyConnectionError("Auto token refresh failed: " + result.error_message);
                        }
                    }
                }

                auto_refresh_enabled = false;
            });
        }

        void StopAutoRefresh() {
            if (auto_refresh_enabled.load()) {
                should_stop_auto_refresh = true;

                if (auto_refresh_thread.joinable()) {
                    auto_refresh_thread.join();
                }

                auto_refresh_enabled = false;
            }
        }

        void UpdateAuthStatus(AuthStatus new_status) {
            auth_status = new_status;

            if (auth_status_callback) {
                std::string message;
                switch (new_status) {
                    case AuthStatus::AUTHENTICATED:
                        message = "Successfully authenticated";
                        break;
                    case AuthStatus::AUTHENTICATING:
                        message = "Authentication in progress";
                        break;
                    case AuthStatus::TOKEN_EXPIRED:
                        message = "Authentication token expired";
                        break;
                    case AuthStatus::CONNECTION_ERROR:
                        message = "Connection error";
                        break;
                    case AuthStatus::SERVER_ERROR:
                        message = "Server error";
                        break;
                    default:
                        message = "Not authenticated";
                        break;
                }

                auth_status_callback(new_status, message);
            }
        }

        void NotifyConnectionError(const std::string& error_message) {
            if (connection_error_callback) {
                connection_error_callback(error_message);
            }
        }
    };

    // Реализация основных классов

    // AuthClient
    AuthClient::AuthClient() : pImpl(std::make_unique<Impl>()) {}

    AuthClient::AuthClient(const ClientConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    AuthClient::~AuthClient() = default;

    bool AuthClient::Initialize() {
        return pImpl->InitializeImpl();
    }

    bool AuthClient::Initialize(const ClientConfig& config) {
        pImpl->config = config;
        return pImpl->InitializeImpl();
    }

    void AuthClient::Shutdown() {
        pImpl->Shutdown();
    }

    bool AuthClient::IsInitialized() const {
        return pImpl->initialized.load();
    }

    void AuthClient::SetConfig(const ClientConfig& config) {
        pImpl->config = config;
    }

    const ClientConfig& AuthClient::GetConfig() const {
        return pImpl->config;
    }

    void AuthClient::SetAuthStatusCallback(AuthStatusCallback callback) {
        pImpl->auth_status_callback = std::move(callback);
    }

    void AuthClient::SetTokenRefreshCallback(TokenRefreshCallback callback) {
        pImpl->token_refresh_callback = std::move(callback);
    }

    void AuthClient::SetConnectionErrorCallback(ConnectionErrorCallback callback) {
        pImpl->connection_error_callback = std::move(callback);
    }

    AuthResult AuthClient::Login(const std::string& username, const std::string& password) {
        return pImpl->LoginImpl(username, password);
    }

    AuthResult AuthClient::RegisterWithToken(const std::string& registration_token,
                                            const std::string& username,
                                            const std::string& password,
                                            const std::string& email) {
        return pImpl->RegisterImpl(registration_token, username, password, email);
    }

    bool AuthClient::Logout() {
        return pImpl->LogoutImpl();
    }

    bool AuthClient::IsAuthenticated() const {
        return pImpl->authenticated.load();
    }

    AuthStatus AuthClient::GetAuthStatus() const {
        return pImpl->auth_status.load();
    }

    std::optional<UserInfo> AuthClient::GetCurrentUser() const {
        std::lock_guard<std::mutex> lock(pImpl->auth_mutex);
        return pImpl->current_user;
    }

    std::vector<std::string> AuthClient::GetUserPermissions() const {
        std::lock_guard<std::mutex> lock(pImpl->auth_mutex);
        if (pImpl->current_user) {
            return pImpl->current_user->permissions;
        }
        return {};
    }

    bool AuthClient::HasPermission(const std::string& permission) const {
        auto permissions = GetUserPermissions();
        return std::find(permissions.begin(), permissions.end(), permission) != permissions.end();
    }

    std::optional<AuthToken> AuthClient::GetAccessToken() const {
        return pImpl->token_manager.GetAccessToken();
    }

    AuthResult AuthClient::RefreshAccessToken() {
        return pImpl->RefreshTokenImpl();
    }

    bool AuthClient::IsTokenExpired() const {
        return pImpl->token_manager.IsAccessTokenExpired();
    }

    void AuthClient::StartAutoRefresh() {
        pImpl->StartAutoRefresh();
    }

    void AuthClient::StopAutoRefresh() {
        pImpl->StopAutoRefresh();
    }

    bool AuthClient::IsAutoRefreshEnabled() const {
        return pImpl->auto_refresh_enabled.load();
    }

    std::string AuthClient::GetAuthorizationHeader() const {
        auto token = GetAccessToken();
        if (token && !token->IsExpired()) {
            return "Bearer " + token->token_value;
        }
        return "";
    }

    bool AuthClient::SaveTokensToCache() const {
        return pImpl->token_manager.SaveToFile(pImpl->config.cache_file_path);
    }

    bool AuthClient::LoadTokensFromCache() {
        return pImpl->token_manager.LoadFromFile(pImpl->config.cache_file_path);
    }

    void AuthClient::ClearTokenCache() {
        pImpl->token_manager.ClearTokens();
        if (std::filesystem::exists(pImpl->config.cache_file_path)) {
            std::filesystem::remove(pImpl->config.cache_file_path);
        }
    }

    // HttpClient
    HttpClient::HttpClient() : pImpl(std::make_unique<Impl>()) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    HttpClient::~HttpClient() {
        curl_global_cleanup();
    }

    HttpClient::HttpResponse HttpClient::Get(const std::string& url,
                                            const std::unordered_map<std::string, std::string>& headers) {
        return pImpl->ExecuteRequest("GET", url, "", headers);
    }

    HttpClient::HttpResponse HttpClient::Post(const std::string& url,
                                             const std::string& body,
                                             const std::unordered_map<std::string, std::string>& headers) {
        return pImpl->ExecuteRequest("POST", url, body, headers);
    }

    void HttpClient::SetTimeout(std::chrono::seconds timeout) {
        pImpl->timeout = timeout;
        if (pImpl->curl_handle) {
            curl_easy_setopt(pImpl->curl_handle, CURLOPT_TIMEOUT, timeout.count());
        }
    }

    void HttpClient::SetSSLVerification(bool verify) {
        if (pImpl->curl_handle) {
            curl_easy_setopt(pImpl->curl_handle, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
            curl_easy_setopt(pImpl->curl_handle, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
        }
    }

    // TokenManager
    TokenManager::TokenManager() : pImpl(std::make_unique<Impl>()) {}
    TokenManager::~TokenManager() = default;

    void TokenManager::StoreTokens(const AuthToken& access_token, const AuthToken& refresh_token) {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        pImpl->access_token = access_token;
        if (refresh_token.is_valid) {
            pImpl->refresh_token = refresh_token;
        }
    }

    std::optional<AuthToken> TokenManager::GetAccessToken() const {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        return pImpl->access_token;
    }

    std::optional<AuthToken> TokenManager::GetRefreshToken() const {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        return pImpl->refresh_token;
    }

    void TokenManager::ClearTokens() {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        pImpl->access_token.reset();
        pImpl->refresh_token.reset();
    }

    bool TokenManager::HasValidAccessToken() const {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        return pImpl->access_token && pImpl->access_token->is_valid && !pImpl->access_token->IsExpired();
    }

    bool TokenManager::IsAccessTokenExpired() const {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        return !pImpl->access_token || pImpl->access_token->IsExpired();
    }

    bool TokenManager::ShouldRefreshToken(std::chrono::minutes threshold) const {
        std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);
        if (!pImpl->access_token) {
            return false;
        }

        auto now = std::chrono::system_clock::now();
        auto time_to_expiry = pImpl->access_token->expires_at - now;

        return time_to_expiry <= threshold;
    }

    bool TokenManager::SaveToFile(const std::filesystem::path& file_path) const {
        try {
            std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);

            Json::Value root;

            if (pImpl->access_token) {
                root["access_token"] = pImpl->TokenToJson(*pImpl->access_token);
            }

            if (pImpl->refresh_token) {
                root["refresh_token"] = pImpl->TokenToJson(*pImpl->refresh_token);
            }

            std::ofstream file(file_path);
            if (!file.is_open()) {
                return false;
            }

            Json::StreamWriterBuilder builder;
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(root, &file);

            return true;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool TokenManager::LoadFromFile(const std::filesystem::path& file_path) {
        try {
            if (!std::filesystem::exists(file_path)) {
                return false;
            }

            std::ifstream file(file_path);
            if (!file.is_open()) {
                return false;
            }

            Json::Value root;
            Json::Reader reader;

            if (!reader.parse(file, root)) {
                return false;
            }

            std::lock_guard<std::mutex> lock(pImpl->tokens_mutex);

            if (root.isMember("access_token")) {
                pImpl->access_token = pImpl->JsonToToken(root["access_token"]);
            }

            if (root.isMember("refresh_token")) {
                pImpl->refresh_token = pImpl->JsonToToken(root["refresh_token"]);
            }

            return true;

        } catch (const std::exception&) {
            return false;
        }
    }

    std::string AuthManager::generate_device_id() const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << "DEV_";
    ss << std::hex;
    for (int i = 0; i < 16; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

    std::string AuthManager::hash_token(const std::string& token) const {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, token.c_str(), token.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    bool AuthManager::validate_email(const std::string& email) const {
        const std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        return std::regex_match(email, email_regex);
    }

    bool AuthManager::validate_token_format(const std::string& token) const {
        // Проверяем что токен не пустой и имеет минимальную длину
        if (token.empty() || token.length() < 16) {
            return false;
        }

        // Проверяем что токен содержит только допустимые символы
        const std::regex token_regex(R"([a-zA-Z0-9._-]+)");
        return std::regex_match(token, token_regex);
    }

    std::string AuthManager::encrypt_data(const std::string& data) const {
        // Простое XOR шифрование для демонстрации
        // В продакшене следует использовать более надежное шифрование
        std::string encrypted = data;
        const std::string key = "AUTH_ENCRYPTION_KEY_2024";

        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
        }

        return encrypted;
    }

    std::string AuthManager::decrypt_data(const std::string& encrypted_data) const {
        // Обратная операция XOR
        return encrypt_data(encrypted_data);
    }

    bool AuthManager::login(const std::string& device_id, const std::string& token) {
        std::lock_guard<std::mutex> lock(auth_mutex);

        if (device_id.empty() || token.empty()) {
            std::cerr << "Device ID или токен не могут быть пустыми" << std::endl;
            return false;
        }

        if (!validate_token_format(token)) {
            std::cerr << "Неверный формат токена" << std::endl;
            return false;
        }

        // Проверяем что устройство зарегистрировано
        auto device_it = registered_devices.find(device_id);
        if (device_it == registered_devices.end()) {
            std::cerr << "Устройство не зарегистрировано: " << device_id << std::endl;
            return false;
        }

        if (!device_it->second.is_active) {
            std::cerr << "Устройство деактивировано: " << device_id << std::endl;
            return false;
        }

        // Создаем новый токен с временем истечения
        auto expiry_time = std::chrono::system_clock::now() + token_validity_period;
        current_token = AuthToken(hash_token(token), expiry_time, device_id, device_it->second.email);
        current_device_id = device_id;

        // Обновляем время последнего входа
        device_it->second.last_login_time = std::chrono::system_clock::now();

        save_auth_state();

        std::cout << "Успешный вход для устройства: " << device_id << std::endl;
        return true;
    }

    bool AuthManager::register_device(const std::string& email, const std::string& token) {
        std::lock_guard<std::mutex> lock(auth_mutex);

        if (email.empty() || token.empty()) {
            std::cerr << "Email или токен не могут быть пустыми" << std::endl;
            return false;
        }

        if (!validate_email(email)) {
            std::cerr << "Неверный формат email: " << email << std::endl;
            return false;
        }

        if (!validate_token_format(token)) {
            std::cerr << "Неверный формат токена" << std::endl;
            return false;
        }

        // Проверяем количество устройств для данного email
        size_t device_count = 0;
        for (const auto& pair : registered_devices) {
            if (pair.second.email == email && pair.second.is_active) {
                device_count++;
            }
        }

        if (device_count >= max_devices_per_email) {
            std::cerr << "Превышено максимальное количество устройств для email: " << email << std::endl;
            return false;
        }

        // Генерируем новый device_id
        std::string new_device_id = generate_device_id();

        // Убеждаемся что device_id уникальный
        while (registered_devices.find(new_device_id) != registered_devices.end()) {
            new_device_id = generate_device_id();
        }

        // Регистрируем устройство
        registered_devices[new_device_id] = DeviceInfo(new_device_id, email);

        // Автоматически выполняем вход для нового устройства
        auto expiry_time = std::chrono::system_clock::now() + token_validity_period;
        current_token = AuthToken(hash_token(token), expiry_time, new_device_id, email);
        current_device_id = new_device_id;

        save_auth_state();

        std::cout << "Устройство зарегистрировано с ID: " << new_device_id << std::endl;
        return true;
    }

    bool AuthManager::is_authenticated() const {
        std::lock_guard<std::mutex> lock(auth_mutex);

        if (!current_token.is_valid) {
            return false;
        }

        if (current_token.is_expired()) {
            return false;
        }

        if (current_device_id.empty()) {
            return false;
        }

        // Проверяем что устройство все еще зарегистрировано и активно
        auto device_it = registered_devices.find(current_device_id);
        if (device_it == registered_devices.end() || !device_it->second.is_active) {
            return false;
        }

        return true;
    }

    void AuthManager::save_auth_state() {
        try {
            json j;

            // Сохраняем текущее состояние аутентификации
            if (current_token.is_valid) {
                auto expiry_time_t = std::chrono::system_clock::to_time_t(current_token.expiry_time);
                j["current_session"] = {
                    {"device_id", current_device_id},
                    {"token_hash", current_token.token},
                    {"expiry_time", expiry_time_t},
                    {"email", current_token.email},
                    {"is_valid", current_token.is_valid}
                };
            }

            // Сохраняем зарегистрированные устройства
            j["registered_devices"] = json::array();
            for (const auto& pair : registered_devices) {
                const DeviceInfo& device = pair.second;

                auto reg_time_t = std::chrono::system_clock::to_time_t(device.registration_time);
                auto login_time_t = std::chrono::system_clock::to_time_t(device.last_login_time);

                json device_json = {
                    {"device_id", device.device_id},
                    {"email", device.email},
                    {"registration_time", reg_time_t},
                    {"last_login_time", login_time_t},
                    {"is_active", device.is_active}
                };

                j["registered_devices"].push_back(device_json);
            }

            // Сохраняем настройки
            j["settings"] = {
                {"token_validity_hours", token_validity_period.count()},
                {"max_devices_per_email", max_devices_per_email}
            };

            std::string json_str = j.dump();
            std::string encrypted_data = encrypt_data(json_str);

            std::ofstream file(auth_state_file, std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "Не удалось создать файл состояния аутентификации" << std::endl;
                return;
            }

            file.write(encrypted_data.c_str(), encrypted_data.size());

        } catch (const std::exception& e) {
            std::cerr << "Ошибка сохранения состояния аутентификации: " << e.what() << std::endl;
        }
    }

    void AuthManager::load_auth_state() {
        try {
            if (!std::filesystem::exists(auth_state_file)) {
                return; // Файл не существует - нормально для первого запуска
            }

            std::ifstream file(auth_state_file, std::ios::binary);
            if (!file.is_open()) {
                std::cerr << "Не удалось открыть файл состояния аутентификации" << std::endl;
                return;
            }

            std::string encrypted_data((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());

            std::string json_str = decrypt_data(encrypted_data);
            json j = json::parse(json_str);

            // Загружаем текущую сессию
            if (j.contains("current_session")) {
                auto session = j["current_session"];

                current_device_id = session["device_id"];
                std::time_t expiry_time_t = session["expiry_time"];
                auto expiry_time = std::chrono::system_clock::from_time_t(expiry_time_t);

                current_token = AuthToken(
                    session["token_hash"],
                    expiry_time,
                    session["device_id"],
                    session["email"]
                );
                current_token.is_valid = session["is_valid"];
            }

            // Загружаем зарегистрированные устройства
            if (j.contains("registered_devices")) {
                registered_devices.clear();

                for (const auto& device_json : j["registered_devices"]) {
                    DeviceInfo device;
                    device.device_id = device_json["device_id"];
                    device.email = device_json["email"];
                    device.is_active = device_json["is_active"];

                    std::time_t reg_time_t = device_json["registration_time"];
                    std::time_t login_time_t = device_json["last_login_time"];

                    device.registration_time = std::chrono::system_clock::from_time_t(reg_time_t);
                    device.last_login_time = std::chrono::system_clock::from_time_t(login_time_t);

                    registered_devices[device.device_id] = device;
                }
            }

            // Загружаем настройки
            if (j.contains("settings")) {
                auto settings = j["settings"];
                token_validity_period = std::chrono::hours(settings["token_validity_hours"]);
                max_devices_per_email = settings["max_devices_per_email"];
            }

            std::cout << "Состояние аутентификации загружено. Устройств: "
                      << registered_devices.size() << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "Ошибка загрузки состояния аутентификации: " << e.what() << std::endl;
        }
    }

    bool AuthManager::logout() {
        std::lock_guard<std::mutex> lock(auth_mutex);

        current_token = AuthToken(); // Сброс токена
        current_device_id.clear();

        save_auth_state();

        std::cout << "Выход выполнен успешно" << std::endl;
        return true;
    }

    bool AuthManager::revoke_device(const std::string& device_id) {
        std::lock_guard<std::mutex> lock(auth_mutex);

        auto device_it = registered_devices.find(device_id);
        if (device_it == registered_devices.end()) {
            std::cerr << "Устройство не найдено: " << device_id << std::endl;
            return false;
        }

        device_it->second.is_active = false;

        // Если это текущее устройство, выполняем выход
        if (current_device_id == device_id) {
            current_token = AuthToken();
            current_device_id.clear();
        }

        save_auth_state();

        std::cout << "Устройство деактивировано: " << device_id << std::endl;
        return true;
    }

    bool AuthManager::refresh_token(const std::string& new_token) {
        std::lock_guard<std::mutex> lock(auth_mutex);

        if (!is_authenticated()) {
            std::cerr << "Пользователь не аутентифицирован" << std::endl;
            return false;
        }

        if (!validate_token_format(new_token)) {
            std::cerr << "Неверный формат нового токена" << std::endl;
            return false;
        }

        // Обновляем токен и продлеваем срок действия
        current_token.token = hash_token(new_token);
        current_token.expiry_time = std::chrono::system_clock::now() + token_validity_period;

        save_auth_state();

        std::cout << "Токен обновлен успешно" << std::endl;
        return true;
    }

    std::vector<DeviceInfo> AuthManager::get_registered_devices(const std::string& email) const {
        std::lock_guard<std::mutex> lock(auth_mutex);

        std::vector<DeviceInfo> devices;
        for (const auto& pair : registered_devices) {
            if (pair.second.email == email) {
                devices.push_back(pair.second);
            }
        }

        return devices;
    }

    void AuthManager::cleanup_expired_tokens() {
        std::lock_guard<std::mutex> lock(auth_mutex);

        // Очищаем текущий токен если истек
        if (current_token.is_valid && current_token.is_expired()) {
            current_token = AuthToken();
            current_device_id.clear();
        }

        save_auth_state();
    }

    void AuthManager::set_token_validity_period(std::chrono::hours hours) {
        token_validity_period = hours;
    }

    void AuthManager::set_max_devices_per_email(size_t max_devices) {
        max_devices_per_email = max_devices;
    }

    std::string AuthManager::get_current_device_id() const {
        return current_device_id;
    }

    std::string AuthManager::get_current_email() const {
        if (is_authenticated()) {
            return current_token.email;
        }
        return "";
    }

    std::chrono::system_clock::time_point AuthManager::get_token_expiry() const {
        return current_token.expiry_time;
    }

    size_t AuthManager::get_registered_devices_count() const {
        std::lock_guard<std::mutex> lock(auth_mutex);
        return registered_devices.size();
    }

    // Утилитарные функции
    namespace Utils {

        std::string AuthStatusToString(AuthStatus status) {
            switch (status) {
                case AuthStatus::NOT_AUTHENTICATED: return "not_authenticated";
                case AuthStatus::AUTHENTICATING: return "authenticating";
                case AuthStatus::AUTHENTICATED: return "authenticated";
                case AuthStatus::TOKEN_EXPIRED: return "token_expired";
                case AuthStatus::TOKEN_INVALID: return "token_invalid";
                case AuthStatus::CONNECTION_ERROR: return "connection_error";
                case AuthStatus::SERVER_ERROR: return "server_error";
                default: return "unknown";
            }
        }

        AuthStatus StringToAuthStatus(const std::string& status_str) {
            if (status_str == "not_authenticated") return AuthStatus::NOT_AUTHENTICATED;
            if (status_str == "authenticating") return AuthStatus::AUTHENTICATING;
            if (status_str == "authenticated") return AuthStatus::AUTHENTICATED;
            if (status_str == "token_expired") return AuthStatus::TOKEN_EXPIRED;
            if (status_str == "token_invalid") return AuthStatus::TOKEN_INVALID;
            if (status_str == "connection_error") return AuthStatus::CONNECTION_ERROR;
            if (status_str == "server_error") return AuthStatus::SERVER_ERROR;
            return AuthStatus::NOT_AUTHENTICATED;
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            std::tm* tm = std::gmtime(&time_t);

            std::ostringstream oss;
            oss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
            return oss.str();
        }

        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str) {
            std::tm tm = {};
            std::istringstream ss(timestamp_str);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }

        bool IsValidEmail(const std::string& email) {
            const std::regex email_regex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
            return std::regex_match(email, email_regex);
        }

        bool IsValidUsername(const std::string& username) {
            if (username.length() < 3 || username.length() > 50) {
                return false;
            }

            const std::regex username_regex(R"(^[a-zA-Z0-9._-]+$)");
            return std::regex_match(username, username_regex);
        }

        bool IsValidPassword(const std::string& password, int min_length) {
            if (password.length() < static_cast<std::size_t>(min_length)) {
                return false;
            }

            // Проверка сложности пароля
            bool has_lower = false, has_upper = false, has_digit = false;
            for (char c : password) {
                if (std::islower(c)) has_lower = true;
                else if (std::isupper(c)) has_upper = true;
                else if (std::isdigit(c)) has_digit = true;
            }

            return has_lower && has_upper && has_digit;
        }

        std::string Base64Encode(const std::string& data) {
            BIO* bio = BIO_new(BIO_s_mem());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            BIO_write(bio, data.c_str(), data.length());
            BIO_flush(bio);

            BUF_MEM* buffer_ptr;
            BIO_get_mem_ptr(bio, &buffer_ptr);

            std::string result(buffer_ptr->data, buffer_ptr->length);
            BIO_free_all(bio);

            return result;
        }

        std::string Base64Decode(const std::string& encoded_data) {
            BIO* bio = BIO_new_mem_buf(encoded_data.c_str(), encoded_data.length());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bio = BIO_push(b64, bio);

            std::string result(encoded_data.length(), '\0');
            int decoded_length = BIO_read(bio, &result[0], encoded_data.length());

            BIO_free_all(bio);

            if (decoded_length > 0) {
                result.resize(decoded_length);
            } else {
                result.clear();
            }

            return result;
        }

        std::string GetUserAgent() {
            return "AntivirusClient/1.0";
        }

        std::string CreateDeviceFingerprint() {
            std::stringstream ss;

#ifdef _WIN32
            char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = sizeof(computer_name);
            if (GetComputerNameA(computer_name, &size)) {
                ss << "win_" << computer_name;
            }
#else
            char hostname[256];
            if (gethostname(hostname, sizeof(hostname)) == 0) {
                ss << "linux_" << hostname;
            }
#endif

            return ss.str();
        }

        std::string GenerateClientId() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            ss << "client_";
            for (int i = 0; i < 16; ++i) {
                ss << std::hex << dis(gen);
            }

            return ss.str();
        }
    }
}