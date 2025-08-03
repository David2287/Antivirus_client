//
// Created by WhySkyDie on 21.07.2025.
//

#include "network_client.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <thread>
#include <algorithm>
#include <random>
#include <regex>

#ifdef _WIN32
    #pragma comment(lib, "openssl")
    #pragma comment(lib, "crypto")
#endif

namespace NetworkClient {

    // ============================================================================
    // TLSHttpClient::Impl
    // ============================================================================

    class TLSHttpClient::Impl {
    public:
        ClientConfig config;
        SSL_CTX* ssl_ctx = nullptr;
        SSL* ssl = nullptr;
        int socket_fd = -1;

        std::atomic<bool> connected{false};
        std::atomic<size_t> bytes_sent{0};
        std::atomic<size_t> bytes_received{0};
        std::chrono::milliseconds last_response_time{0};

        mutable std::mutex connection_mutex;
        LogCallback log_callback;

        Impl() {
            InitializeSSL();
        }

        ~Impl() {
            Disconnect();
            CleanupSSL();
        }

        void InitializeSSL() {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();

            ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (!ssl_ctx) {
                LogError("Failed to create SSL context");
                return;
            }

            // Настройка SSL контекста
            SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

            if (!config.tls_config.cipher_list.empty()) {
                SSL_CTX_set_cipher_list(ssl_ctx, config.tls_config.cipher_list.c_str());
            }

            if (config.tls_config.verify_peer) {
                SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);

                if (!config.tls_config.ca_cert_file.empty()) {
                    if (!SSL_CTX_load_verify_locations(ssl_ctx, config.tls_config.ca_cert_file.c_str(), nullptr)) {
                        LogError("Failed to load CA certificate");
                    }
                } else {
                    SSL_CTX_set_default_verify_paths(ssl_ctx);
                }
            }

            // Клиентские сертификаты
            if (!config.tls_config.client_cert_file.empty()) {
                if (SSL_CTX_use_certificate_file(ssl_ctx, config.tls_config.client_cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
                    LogError("Failed to load client certificate");
                }
            }

            if (!config.tls_config.client_key_file.empty()) {
                if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config.tls_config.client_key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
                    LogError("Failed to load client private key");
                }
            }
        }

        void CleanupSSL() {
            if (ssl_ctx) {
                SSL_CTX_free(ssl_ctx);
                ssl_ctx = nullptr;
            }
        }

        bool Connect() {
            std::lock_guard<std::mutex> lock(connection_mutex);

            if (connected.load()) {
                return true;
            }

            try {
                // Создание сокета
                socket_fd = CreateSocket();
                if (socket_fd < 0) {
                    LogError("Failed to create socket");
                    return false;
                }

                // Подключение к серверу
                if (!ConnectSocket()) {
                    CloseSocket();
                    return false;
                }

                // Настройка SSL
                ssl = SSL_new(ssl_ctx);
                if (!ssl) {
                    LogError("Failed to create SSL object");
                    CloseSocket();
                    return false;
                }

                SSL_set_fd(ssl, socket_fd);

                // SNI (Server Name Indication)
                if (config.tls_config.verify_hostname) {
                    SSL_set_tlsext_host_name(ssl, config.server_host.c_str());
                }

                // TLS рукопожатие
                int result = SSL_connect(ssl);
                if (result <= 0) {
                    int ssl_error = SSL_get_error(ssl, result);
                    LogError("SSL handshake failed: " + std::to_string(ssl_error));
                    Disconnect();
                    return false;
                }

                // Проверка сертификата
                if (config.tls_config.verify_peer && config.tls_config.verify_hostname) {
                    if (!Utils::VerifyCertificate(ssl, config.server_host)) {
                        LogError("Certificate verification failed");
                        Disconnect();
                        return false;
                    }
                }

                connected = true;
                LogInfo("Successfully connected to " + config.server_host + ":" + std::to_string(config.server_port));
                return true;

            } catch (const std::exception& e) {
                LogError("Connection failed: " + std::string(e.what()));
                Disconnect();
                return false;
            }
        }

        void Disconnect() {
            std::lock_guard<std::mutex> lock(connection_mutex);

            connected = false;

            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                ssl = nullptr;
            }

            CloseSocket();
        }

        HttpResponse SendRequest(const HttpRequest& request) {
            HttpResponse response;
            auto start_time = std::chrono::high_resolution_clock::now();

            if (!connected.load()) {
                response.error_message = "Not connected";
                return response;
            }

            try {
                // Построение HTTP запроса
                std::string http_request = BuildHttpRequest(request);

                // Отправка запроса
                int sent = SSL_write(ssl, http_request.c_str(), http_request.length());
                if (sent <= 0) {
                    response.error_message = "Failed to send request";
                    return response;
                }

                bytes_sent += sent;

                // Получение ответа
                std::string response_data = ReceiveResponse();
                if (response_data.empty()) {
                    response.error_message = "Failed to receive response";
                    return response;
                }

                bytes_received += response_data.length();

                // Парсинг ответа
                ParseHttpResponse(response_data, response);
                response.success = true;

                auto end_time = std::chrono::high_resolution_clock::now();
                response.response_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
                last_response_time = response.response_time;

            } catch (const std::exception& e) {
                response.error_message = "Request failed: " + std::string(e.what());
            }

            return response;
        }

    private:
        int CreateSocket() {
#ifdef _WIN32
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                return -1;
            }
#endif

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                return -1;
            }

            // Настройка сокета
            if (config.tcp_nodelay) {
                int flag = 1;
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&flag), sizeof(flag));
            }

            // Таймауты
            struct timeval timeout;
            timeout.tv_sec = config.connect_timeout.count();
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

            return sock;
        }

        bool ConnectSocket() {
            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(config.server_port);

            // Резолв хоста
            struct hostent* host_entry = gethostbyname(config.server_host.c_str());
            if (!host_entry) {
                LogError("Failed to resolve hostname: " + config.server_host);
                return false;
            }

            memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);

            // Подключение
            int result = connect(socket_fd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr));
            if (result < 0) {
                LogError("Failed to connect to server");
                return false;
            }

            return true;
        }

        void CloseSocket() {
            if (socket_fd >= 0) {
#ifdef _WIN32
                closesocket(socket_fd);
                WSACleanup();
#else
                close(socket_fd);
#endif
                socket_fd = -1;
            }
        }

        std::string BuildHttpRequest(const HttpRequest& request) {
            std::ostringstream oss;

            // Строка запроса
            oss << Utils::HttpMethodToString(request.method) << " " << request.path;

            // Query параметры
            if (!request.query_params.empty()) {
                oss << "?" << Utils::BuildQueryString(request.query_params);
            }

            oss << " HTTP/1.1\r\n";

            // Обязательные заголовки
            oss << "Host: " << config.server_host << "\r\n";
            oss << "User-Agent: " << config.user_agent << "\r\n";

            // Заголовки по умолчанию
            for (const auto& header : config.default_headers) {
                oss << header.first << ": " << header.second << "\r\n";
            }

            // Заголовки запроса
            for (const auto& header : request.headers) {
                oss << header.first << ": " << header.second << "\r\n";
            }

            // Content-Length для POST/PUT
            if (!request.body.empty()) {
                oss << "Content-Length: " << request.body.length() << "\r\n";
            }

            if (config.keep_alive) {
                oss << "Connection: keep-alive\r\n";
            } else {
                oss << "Connection: close\r\n";
            }

            oss << "\r\n";

            // Тело запроса
            if (!request.body.empty()) {
                oss << request.body;
            }

            return oss.str();
        }

        std::string ReceiveResponse() {
            std::string response;
            char buffer[4096];

            while (true) {
                int received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (received <= 0) {
                    int ssl_error = SSL_get_error(ssl, received);
                    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                        // Соединение закрыто корректно
                        break;
                    } else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                        // Нужно повторить операцию
                        std::this_thread::sleep_for(std::chrono::milliseconds{10});
                        continue;
                    } else {
                        // Ошибка
                        break;
                    }
                }

                buffer[received] = '\0';
                response.append(buffer, received);

                // Проверяем конец заголовков
                size_t header_end = response.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    // Парсим Content-Length
                    size_t content_length = ParseContentLength(response);
                    size_t body_start = header_end + 4;
                    size_t current_body_size = response.length() - body_start;

                    if (content_length == 0 || current_body_size >= content_length) {
                        break;
                    }
                }
            }

            return response;
        }

        size_t ParseContentLength(const std::string& response) {
            std::regex content_length_regex(R"(Content-Length:\s*(\d+))", std::regex_constants::icase);
            std::smatch match;

            if (std::regex_search(response, match, content_length_regex)) {
                return std::stoull(match[1].str());
            }

            return 0;
        }

        void ParseHttpResponse(const std::string& response_data, HttpResponse& response) {
            std::istringstream iss(response_data);
            std::string line;

            // Статус строка
            if (std::getline(iss, line)) {
                std::istringstream status_line(line);
                std::string http_version;
                status_line >> http_version >> response.status_code >> response.status_message;
            }

            // Заголовки
            while (std::getline(iss, line) && line != "\r") {
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string name = line.substr(0, colon_pos);
                    std::string value = line.substr(colon_pos + 1);

                    // Удаляем пробелы
                    name.erase(name.find_last_not_of(" \t\r\n") + 1);
                    value.erase(0, value.find_first_not_of(" \t\r\n"));
                    value.erase(value.find_last_not_of(" \t\r\n") + 1);

                    response.headers[name] = value;
                }
            }

            // Тело ответа
            std::ostringstream body_stream;
            body_stream << iss.rdbuf();
            response.body = body_stream.str();
        }

        void LogInfo(const std::string& message) {
            if (log_callback) {
                log_callback(LogLevel::INFO, message);
            }
        }

        void LogError(const std::string& message) {
            if (log_callback) {
                log_callback(LogLevel::ERROR, message);
            }
        }
    };

    // ============================================================================
    // GrpcClient::Impl
    // ============================================================================

    class GrpcClient::Impl {
    public:
        ClientConfig config;
        std::shared_ptr<grpc::Channel> channel;
        grpc::ClientContext context;

        std::atomic<bool> connected{false};
        std::atomic<size_t> bytes_sent{0};
        std::atomic<size_t> bytes_received{0};
        std::chrono::milliseconds last_response_time{0};

        LogCallback log_callback;

        Impl() = default;

        bool Connect() {
            try {
                // Создание учетных данных
                std::shared_ptr<grpc::ChannelCredentials> creds;

                if (config.connection_type == ConnectionType::GRPC_TLS) {
                    grpc::SslCredentialsOptions ssl_opts;

                    if (!config.tls_config.ca_cert_file.empty()) {
                        ssl_opts.pem_root_certs = Utils::ReadFile(config.tls_config.ca_cert_file);
                    }

                    if (!config.tls_config.client_cert_file.empty()) {
                        ssl_opts.pem_cert_chain = Utils::ReadFile(config.tls_config.client_cert_file);
                    }

                    if (!config.tls_config.client_key_file.empty()) {
                        ssl_opts.pem_private_key = Utils::ReadFile(config.tls_config.client_key_file);
                    }

                    creds = grpc::SslCredentials(ssl_opts);
                } else {
                    creds = grpc::InsecureChannelCredentials();
                }

                // Создание канала
                std::string target = config.server_host + ":" + std::to_string(config.server_port);

                grpc::ChannelArguments args;
                if (config.grpc_compression) {
                    args.SetCompressionAlgorithm(GRPC_COMPRESS_GZIP);
                }

                // Таймауты
                args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 30000);
                args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 5000);
                args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);

                channel = grpc::CreateCustomChannel(target, creds, args);

                if (!channel) {
                    LogError("Failed to create gRPC channel");
                    return false;
                }

                // Проверка соединения
                auto state = channel->GetState(true);
                if (state == GRPC_CHANNEL_READY || state == GRPC_CHANNEL_CONNECTING) {
                    connected = true;
                    LogInfo("gRPC channel created successfully");
                    return true;
                } else {
                    LogError("gRPC channel is not ready");
                    return false;
                }

            } catch (const std::exception& e) {
                LogError("gRPC connection failed: " + std::string(e.what()));
                return false;
            }
        }

        void Disconnect() {
            connected = false;
            channel.reset();
        }

        void LogInfo(const std::string& message) {
            if (log_callback) {
                log_callback(LogLevel::INFO, message);
            }
        }

        void LogError(const std::string& message) {
            if (log_callback) {
                log_callback(LogLevel::ERROR, message);
            }
        }
    };

    // ============================================================================
    // Реализация основных классов
    // ============================================================================

    // NetworkClientBase
    NetworkClientBase::NetworkClientBase(const ClientConfig& config) : config_(config) {}
    NetworkClientBase::~NetworkClientBase() = default;

    void NetworkClientBase::SetConfig(const ClientConfig& config) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_ = config;
    }

    const ClientConfig& NetworkClientBase::GetConfig() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return config_;
    }

    void NetworkClientBase::SetLogCallback(LogCallback callback) {
        log_callback_ = std::move(callback);
    }

    void NetworkClientBase::SetConnectionCallback(ConnectionCallback callback) {
        connection_callback_ = std::move(callback);
    }

    void NetworkClientBase::Log(LogLevel level, const std::string& message) {
        if (log_callback_) {
            log_callback_(level, message);
        }
    }

    void NetworkClientBase::NotifyStatusChange(ConnectionStatus status) {
        status_ = status;
        if (connection_callback_) {
            connection_callback_(status);
        }
    }

    // TLSHttpClient
    TLSHttpClient::TLSHttpClient(const ClientConfig& config)
        : NetworkClientBase(config), pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
        pImpl->log_callback = [this](LogLevel level, const std::string& message) {
            Log(level, message);
        };
    }

    TLSHttpClient::~TLSHttpClient() = default;

    bool TLSHttpClient::Connect() {
        NotifyStatusChange(ConnectionStatus::CONNECTING);
        bool result = pImpl->Connect();
        NotifyStatusChange(result ? ConnectionStatus::CONNECTED : ConnectionStatus::ERROR);
        return result;
    }

    void TLSHttpClient::Disconnect() {
        pImpl->Disconnect();
        NotifyStatusChange(ConnectionStatus::DISCONNECTED);
    }

    bool TLSHttpClient::IsConnected() const {
        return pImpl->connected.load();
    }

    ConnectionStatus TLSHttpClient::GetStatus() const {
        return status_.load();
    }

    HttpResponse TLSHttpClient::Get(const std::string& path,
                                   const std::unordered_map<std::string, std::string>& headers) {
        HttpRequest request(HttpMethod::GET, path);
        request.headers = headers;
        return pImpl->SendRequest(request);
    }

    HttpResponse TLSHttpClient::Post(const std::string& path, const std::string& body,
                                    const std::unordered_map<std::string, std::string>& headers) {
        HttpRequest request(HttpMethod::POST, path);
        request.body = body;
        request.headers = headers;
        return pImpl->SendRequest(request);
    }

    HttpResponse TLSHttpClient::PostJson(const std::string& path, const Json::Value& json_data) {
        std::unordered_map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";

        std::string json_string = Utils::JsonToString(json_data);
        return Post(path, json_string, headers);
    }

    std::optional<Json::Value> TLSHttpClient::GetJson(const std::string& path) {
        auto response = Get(path);
        if (response.success && response.status_code == 200) {
            return Utils::StringToJson(response.body);
        }
        return std::nullopt;
    }

    std::future<HttpResponse> TLSHttpClient::GetAsync(const std::string& path) {
        return std::async(std::launch::async, [this, path]() {
            return Get(path);
        });
    }

    size_t TLSHttpClient::GetBytesSent() const {
        return pImpl->bytes_sent.load();
    }

    size_t TLSHttpClient::GetBytesReceived() const {
        return pImpl->bytes_received.load();
    }

    std::chrono::milliseconds TLSHttpClient::GetLastResponseTime() const {
        return pImpl->last_response_time;
    }

    // GrpcClient
    GrpcClient::GrpcClient(const ClientConfig& config)
        : NetworkClientBase(config), pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
        pImpl->log_callback = [this](LogLevel level, const std::string& message) {
            Log(level, message);
        };
    }

    GrpcClient::~GrpcClient() = default;

    bool GrpcClient::Connect() {
        NotifyStatusChange(ConnectionStatus::CONNECTING);
        bool result = pImpl->Connect();
        NotifyStatusChange(result ? ConnectionStatus::CONNECTED : ConnectionStatus::ERROR);
        return result;
    }

    void GrpcClient::Disconnect() {
        pImpl->Disconnect();
        NotifyStatusChange(ConnectionStatus::DISCONNECTED);
    }

    bool GrpcClient::IsConnected() const {
        return pImpl->connected.load();
    }

    ConnectionStatus GrpcClient::GetStatus() const {
        return status_.load();
    }

    std::shared_ptr<grpc::Channel> GrpcClient::GetChannel() const {
        return pImpl->channel;
    }

    size_t GrpcClient::GetBytesSent() const {
        return pImpl->bytes_sent.load();
    }

    size_t GrpcClient::GetBytesReceived() const {
        return pImpl->bytes_received.load();
    }

    std::chrono::milliseconds GrpcClient::GetLastResponseTime() const {
        return pImpl->last_response_time;
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string HttpMethodToString(HttpMethod method) {
            switch (method) {
                case HttpMethod::GET: return "GET";
                case HttpMethod::POST: return "POST";
                case HttpMethod::PUT: return "PUT";
                case HttpMethod::DELETE: return "DELETE";
                case HttpMethod::PATCH: return "PATCH";
                default: return "GET";
            }
        }

        HttpMethod StringToHttpMethod(const std::string& method_str) {
            if (method_str == "GET") return HttpMethod::GET;
            if (method_str == "POST") return HttpMethod::POST;
            if (method_str == "PUT") return HttpMethod::PUT;
            if (method_str == "DELETE") return HttpMethod::DELETE;
            if (method_str == "PATCH") return HttpMethod::PATCH;
            return HttpMethod::GET;
        }

        std::string UrlEncode(const std::string& value) {
            std::ostringstream encoded;
            encoded.fill('0');
            encoded << std::hex;

            for (unsigned char c : value) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    encoded << c;
                } else {
                    encoded << '%' << std::setw(2) << int(c);
                }
            }

            return encoded.str();
        }

        std::string BuildQueryString(const std::unordered_map<std::string, std::string>& params) {
            std::ostringstream oss;
            bool first = true;

            for (const auto& param : params) {
                if (!first) {
                    oss << "&";
                }
                oss << UrlEncode(param.first) << "=" << UrlEncode(param.second);
                first = false;
            }

            return oss.str();
        }

        std::string JsonToString(const Json::Value& json) {
            Json::StreamWriterBuilder builder;
            builder["commentStyle"] = "None";
            builder["indentation"] = "";
            return Json::writeString(builder, json);
        }

        std::optional<Json::Value> StringToJson(const std::string& json_str) {
            Json::Value json;
            Json::Reader reader;

            if (reader.parse(json_str, json)) {
                return json;
            }

            return std::nullopt;
        }

        bool ValidateJson(const std::string& json_str) {
            Json::Value json;
            Json::Reader reader;
            return reader.parse(json_str, json);
        }

        std::string GetTLSVersion(SSL* ssl) {
            if (!ssl) return "Unknown";
            return SSL_get_version(ssl);
        }

        std::string GetCipherName(SSL* ssl) {
            if (!ssl) return "Unknown";
            const char* cipher = SSL_get_cipher(ssl);
            return cipher ? cipher : "Unknown";
        }

        bool VerifyCertificate(SSL* ssl, const std::string& hostname) {
            if (!ssl) return false;

            // Проверка результата верификации
            long verify_result = SSL_get_verify_result(ssl);
            if (verify_result != X509_V_OK) {
                return false;
            }

            // Получение сертификата
            X509* cert = SSL_get_peer_certificate(ssl);
            if (!cert) {
                return false;
            }

            // Проверка имени хоста
            bool hostname_valid = false;

            // Проверка Subject Alternative Names
            STACK_OF(GENERAL_NAME)* san_list = static_cast<STACK_OF(GENERAL_NAME)*>(
                X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

            if (san_list) {
                int san_count = sk_GENERAL_NAME_num(san_list);
                for (int i = 0; i < san_count && !hostname_valid; i++) {
                    GENERAL_NAME* san = sk_GENERAL_NAME_value(san_list, i);
                    if (san->type == GEN_DNS) {
                        const char* san_hostname = reinterpret_cast<const char*>(
                            ASN1_STRING_get0_data(san->d.dNSName));
                        if (san_hostname && hostname == san_hostname) {
                            hostname_valid = true;
                        }
                    }
                }
                sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
            }

            X509_free(cert);
            return hostname_valid;
        }

        std::string ReadFile(const std::string& file_path) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file) {
                return "";
            }

            std::ostringstream content;
            content << file.rdbuf();
            return content.str();
        }

        bool WriteFile(const std::string& file_path, const std::string& content) {
            std::ofstream file(file_path, std::ios::binary);
            if (!file) {
                return false;
            }

            file << content;
            return file.good();
        }

        std::string ConnectionStatusToString(ConnectionStatus status) {
            switch (status) {
                case ConnectionStatus::DISCONNECTED: return "DISCONNECTED";
                case ConnectionStatus::CONNECTING: return "CONNECTING";
                case ConnectionStatus::CONNECTED: return "CONNECTED";
                case ConnectionStatus::RECONNECTING: return "RECONNECTING";
                case ConnectionStatus::ERROR: return "ERROR";
                default: return "UNKNOWN";
            }
        }
    }
}