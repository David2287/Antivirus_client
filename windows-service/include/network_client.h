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
#include <optional>
#include <unordered_map>
#include <future>

// OpenSSL для TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// gRPC
#include <grpcpp/grpcpp.h>

// JSON
#include <json/json.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
#endif

namespace NetworkClient {

    // Типы соединений
    enum class ConnectionType {
        HTTP,
        HTTPS,
        GRPC,
        GRPC_TLS
    };

    // Статус соединения
    enum class ConnectionStatus {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        RECONNECTING,
        ERROR
    };

    // HTTP методы
    enum class HttpMethod {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH
    };

    // Уровень логирования
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    // Конфигурация TLS
    struct TLSConfig {
        bool verify_peer = true;
        bool verify_hostname = true;
        std::string ca_cert_file;
        std::string client_cert_file;
        std::string client_key_file;
        std::string cipher_list = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
        int ssl_version = 0; // 0 = auto

        TLSConfig() = default;
    };

    // Конфигурация клиента
    struct ClientConfig {
        std::string server_host = "localhost";
        int server_port = 443;
        ConnectionType connection_type = ConnectionType::HTTPS;

        // Таймауты
        std::chrono::seconds connect_timeout{30};
        std::chrono::seconds read_timeout{30};
        std::chrono::seconds write_timeout{30};

        // TLS настройки
        TLSConfig tls_config;

        // HTTP настройки
        std::string user_agent = "NetworkClient/1.0";
        std::unordered_map<std::string, std::string> default_headers;

        // gRPC настройки
        std::string grpc_service_config;
        bool grpc_compression = true;

        // Retry политика
        int max_retries = 3;
        std::chrono::milliseconds retry_delay{1000};
        bool exponential_backoff = true;

        // Прокси
        std::string proxy_host;
        int proxy_port = 0;
        std::string proxy_username;
        std::string proxy_password;

        // Производительность
        size_t buffer_size = 64 * 1024; // 64KB
        bool keep_alive = true;
        bool tcp_nodelay = true;

        ClientConfig() {
            default_headers["Accept"] = "application/json";
            default_headers["Content-Type"] = "application/json";
        }
    };

    // HTTP ответ
    struct HttpResponse {
        int status_code = 0;
        std::string status_message;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        std::chrono::milliseconds response_time{0};
        bool success = false;
        std::string error_message;

        HttpResponse() = default;
    };

    // HTTP запрос
    struct HttpRequest {
        HttpMethod method = HttpMethod::GET;
        std::string path = "/";
        std::unordered_map<std::string, std::string> headers;
        std::string body;
        std::unordered_map<std::string, std::string> query_params;

        HttpRequest() = default;

        explicit HttpRequest(HttpMethod m, const std::string& p = "/")
            : method(m), path(p) {}
    };

    // Результат операции
    struct OperationResult {
        bool success = false;
        std::string error_message;
        std::string error_code;
        std::chrono::milliseconds operation_time{0};

        OperationResult() = default;
    };

    // Callback типы
    using LogCallback = std::function<void(LogLevel level, const std::string& message)>;
    using ConnectionCallback = std::function<void(ConnectionStatus status)>;
    using ProgressCallback = std::function<void(size_t bytes_transferred, size_t total_bytes)>;

    // Базовый класс клиента
    class NetworkClientBase {
    public:
        explicit NetworkClientBase(const ClientConfig& config = ClientConfig{});
        virtual ~NetworkClientBase();

        // Управление соединением
        virtual bool Connect() = 0;
        virtual void Disconnect() = 0;
        virtual bool IsConnected() const = 0;
        virtual ConnectionStatus GetStatus() const = 0;

        // Конфигурация
        void SetConfig(const ClientConfig& config);
        const ClientConfig& GetConfig() const;

        // Callbacks
        void SetLogCallback(LogCallback callback);
        void SetConnectionCallback(ConnectionCallback callback);

        // Статистика
        virtual size_t GetBytesSent() const = 0;
        virtual size_t GetBytesReceived() const = 0;
        virtual std::chrono::milliseconds GetLastResponseTime() const = 0;

    protected:
        ClientConfig config_;
        std::atomic<ConnectionStatus> status_{ConnectionStatus::DISCONNECTED};
        LogCallback log_callback_;
        ConnectionCallback connection_callback_;
        mutable std::mutex config_mutex_;

        void Log(LogLevel level, const std::string& message);
        void NotifyStatusChange(ConnectionStatus status);
    };

    // TLS HTTP клиент
    class TLSHttpClient : public NetworkClientBase {
    public:
        explicit TLSHttpClient(const ClientConfig& config = ClientConfig{});
        ~TLSHttpClient() override;

        // Соединение
        bool Connect() override;
        void Disconnect() override;
        bool IsConnected() const override;
        ConnectionStatus GetStatus() const override;

        // HTTP запросы
        HttpResponse Get(const std::string& path,
                        const std::unordered_map<std::string, std::string>& headers = {});
        HttpResponse Post(const std::string& path, const std::string& body,
                         const std::unordered_map<std::string, std::string>& headers = {});
        HttpResponse Put(const std::string& path, const std::string& body,
                        const std::unordered_map<std::string, std::string>& headers = {});
        HttpResponse Delete(const std::string& path,
                           const std::unordered_map<std::string, std::string>& headers = {});

        // JSON запросы
        HttpResponse PostJson(const std::string& path, const Json::Value& json_data);
        HttpResponse PutJson(const std::string& path, const Json::Value& json_data);
        std::optional<Json::Value> GetJson(const std::string& path);

        // Асинхронные запросы
        std::future<HttpResponse> GetAsync(const std::string& path);
        std::future<HttpResponse> PostAsync(const std::string& path, const std::string& body);

        // Загрузка файлов
        HttpResponse UploadFile(const std::string& path, const std::string& file_path,
                               const std::string& field_name = "file");
        HttpResponse DownloadFile(const std::string& path, const std::string& save_path);

        // Статистика
        size_t GetBytesSent() const override;
        size_t GetBytesReceived() const override;
        std::chrono::milliseconds GetLastResponseTime() const override;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // gRPC клиент
    class GrpcClient : public NetworkClientBase {
    public:
        explicit GrpcClient(const ClientConfig& config = ClientConfig{});
        ~GrpcClient() override;

        // Соединение
        bool Connect() override;
        void Disconnect() override;
        bool IsConnected() const override;
        ConnectionStatus GetStatus() const override;

        // gRPC операции
        template<typename TRequest, typename TResponse>
        grpc::Status CallUnary(const std::string& method_name,
                               const TRequest& request,
                               TResponse& response);

        template<typename TRequest, typename TResponse>
        std::unique_ptr<grpc::ClientReader<TResponse>> CallServerStreaming(
            const std::string& method_name, const TRequest& request);

        template<typename TRequest, typename TResponse>
        std::unique_ptr<grpc::ClientWriter<TRequest>> CallClientStreaming(
            const std::string& method_name, TResponse& response);

        template<typename TRequest, typename TResponse>
        std::unique_ptr<grpc::ClientReaderWriter<TRequest, TResponse>> CallBidirectionalStreaming(
            const std::string& method_name);

        // Управление каналом
        void SetChannelArguments(const grpc::ChannelArguments& args);
        std::shared_ptr<grpc::Channel> GetChannel() const;

        // Статистика
        size_t GetBytesSent() const override;
        size_t GetBytesReceived() const override;
        std::chrono::milliseconds GetLastResponseTime() const override;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер клиентов
    class ClientManager {
    public:
        static ClientManager& Instance();

        // Создание клиентов
        std::shared_ptr<TLSHttpClient> CreateHttpClient(const ClientConfig& config);
        std::shared_ptr<GrpcClient> CreateGrpcClient(const ClientConfig& config);

        // Пул соединений
        std::shared_ptr<TLSHttpClient> GetPooledHttpClient(const std::string& host, int port);
        void ReturnToPool(std::shared_ptr<NetworkClientBase> client);

        // Глобальные настройки
        void SetGlobalTLSConfig(const TLSConfig& config);
        void SetGlobalLogLevel(LogLevel level);

        // Очистка
        void CleanupIdleConnections();
        void Shutdown();

    private:
        ClientManager() = default;
        ~ClientManager() = default;
        ClientManager(const ClientManager&) = delete;
        ClientManager& operator=(const ClientManager&) = delete;

        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        // URL кодирование
        std::string UrlEncode(const std::string& value);
        std::string UrlDecode(const std::string& encoded);

        // HTTP заголовки
        std::string BuildQueryString(const std::unordered_map<std::string, std::string>& params);
        std::unordered_map<std::string, std::string> ParseHeaders(const std::string& headers_str);

        // JSON утилиты
        std::string JsonToString(const Json::Value& json);
        std::optional<Json::Value> StringToJson(const std::string& json_str);
        bool ValidateJson(const std::string& json_str);

        // TLS утилиты
        std::string GetTLSVersion(SSL* ssl);
        std::string GetCipherName(SSL* ssl);
        bool VerifyCertificate(SSL* ssl, const std::string& hostname);

        // Сетевые утилиты
        std::string ResolveHostname(const std::string& hostname);
        bool IsValidIP(const std::string& ip);
        int GetAvailablePort();

        // Время
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str);

        // Файлы
        std::string ReadFile(const std::string& file_path);
        bool WriteFile(const std::string& file_path, const std::string& content);
        std::string GetMimeType(const std::string& file_path);

        // Конвертация
        std::string HttpMethodToString(HttpMethod method);
        HttpMethod StringToHttpMethod(const std::string& method_str);

        std::string ConnectionTypeToString(ConnectionType type);
        ConnectionType StringToConnectionType(const std::string& type_str);

        std::string ConnectionStatusToString(ConnectionStatus status);
        LogLevel StringToLogLevel(const std::string& level_str);
    }
}