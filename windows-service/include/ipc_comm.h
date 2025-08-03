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
#include <thread>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <optional>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/types.h>
#endif

namespace IPCComm {

    // Типы IPC транспорта
    enum class TransportType {
        NAMED_PIPES,
        SHARED_MEMORY,
        AUTO_SELECT
    };

    // Тип клиента
    enum class ClientType {
        UI_CLIENT,
        CORE_CLIENT,
        UNKNOWN_CLIENT
    };

    // Приоритет сообщения
    enum class MessagePriority {
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        CRITICAL = 4
    };

    // Статус соединения
    enum class ConnectionStatus {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        ERROR
    };

    // Тип команды
    enum class CommandType {
        // Основные операции
        START_SCAN,
        STOP_SCAN,
        PAUSE_SCAN,
        RESUME_SCAN,

        // Файловые операции
        QUARANTINE_FILE,
        RESTORE_FILE,
        DELETE_FILE,

        // Управление службой
        SHUTDOWN_SERVICE,
        RESTART_SERVICE,
        GET_STATUS,

        // Конфигурация
        UPDATE_CONFIG,
        GET_CONFIG,

        // Аутентификация
        AUTHENTICATE,
        LOGOUT,

        // Пользовательские команды
        CUSTOM_COMMAND
    };

    // Заголовок IPC сообщения
    struct MessageHeader {
        uint32_t magic;           // Магическое число для валидации
        uint32_t version;         // Версия протокола
        uint32_t message_id;      // Уникальный ID сообщения
        uint32_t client_id;       // ID клиента
        ClientType client_type;   // Тип клиента
        CommandType command_type; // Тип команды
        MessagePriority priority; // Приоритет
        uint32_t data_size;       // Размер данных после заголовка
        uint32_t checksum;        // Контрольная сумма
        uint64_t timestamp;       // Время создания сообщения

        MessageHeader() : magic(0x12345678), version(1), message_id(0),
                         client_id(0), client_type(ClientType::UNKNOWN_CLIENT),
                         command_type(CommandType::CUSTOM_COMMAND),
                         priority(MessagePriority::NORMAL), data_size(0),
                         checksum(0), timestamp(0) {}
    };

    // IPC сообщение
    struct IPCMessage {
        MessageHeader header;
        std::vector<uint8_t> data;

        IPCMessage() = default;

        explicit IPCMessage(CommandType cmd, const std::string& payload = "") {
            header.command_type = cmd;
            if (!payload.empty()) {
                data.assign(payload.begin(), payload.end());
                header.data_size = static_cast<uint32_t>(data.size());
            }
            header.timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        }
    };

    // Результат операции
    struct IPCResult {
        bool success;
        std::string error_message;
        std::string response_data;
        std::chrono::milliseconds operation_time{0};

        IPCResult() : success(false) {}
    };

    // Конфигурация IPC
    struct IPCConfig {
        TransportType transport = TransportType::AUTO_SELECT;
        std::string pipe_name = "antivirus_ipc";
        std::string shared_memory_name = "antivirus_shm";

        // Настройки буферизации
        std::size_t buffer_size = 64 * 1024;     // 64KB
        std::size_t max_message_size = 1024 * 1024; // 1MB
        std::size_t max_clients = 10;

        // Таймауты
        std::chrono::milliseconds connect_timeout{5000};
        std::chrono::milliseconds read_timeout{10000};
        std::chrono::milliseconds write_timeout{5000};

        // Безопасность
        bool require_authentication = true;
        std::string access_token;

        // Производительность
        bool use_async_processing = true;
        int worker_thread_count = 2;
        std::size_t message_queue_size = 1000;
    };

    // Forward declarations
    class IPCServer;
    class IPCClient;

    // Callback типы
    using MessageHandler = std::function<IPCResult(const IPCMessage& message, ClientType client_type)>;
    using ClientConnectedHandler = std::function<void(uint32_t client_id, ClientType client_type)>;
    using ClientDisconnectedHandler = std::function<void(uint32_t client_id, ClientType client_type)>;
    using ErrorHandler = std::function<void(const std::string& error_message)>;

    // Базовый класс для IPC транспорта
    class IPCTransport {
    public:
        virtual ~IPCTransport() = default;

        virtual bool Initialize() = 0;
        virtual void Shutdown() = 0;
        virtual bool IsConnected() const = 0;

        virtual IPCResult SendMessage(const IPCMessage& message) = 0;
        virtual std::optional<IPCMessage> ReceiveMessage(std::chrono::milliseconds timeout) = 0;

        virtual ConnectionStatus GetStatus() const = 0;
    };

    // Named Pipes транспорт
    class NamedPipeTransport : public IPCTransport {
    public:
        explicit NamedPipeTransport(const IPCConfig& config, bool is_server = true);
        ~NamedPipeTransport() override;

        bool Initialize() override;
        void Shutdown() override;
        bool IsConnected() const override;

        IPCResult SendMessage(const IPCMessage& message) override;
        std::optional<IPCMessage> ReceiveMessage(std::chrono::milliseconds timeout) override;

        ConnectionStatus GetStatus() const override;

        // Специфичные для Named Pipes методы
        bool WaitForConnection();
        void DisconnectClient();

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Shared Memory транспорт
    class SharedMemoryTransport : public IPCTransport {
    public:
        explicit SharedMemoryTransport(const IPCConfig& config, bool is_server = true);
        ~SharedMemoryTransport() override;

        bool Initialize() override;
        void Shutdown() override;
        bool IsConnected() const override;

        IPCResult SendMessage(const IPCMessage& message) override;
        std::optional<IPCMessage> ReceiveMessage(std::chrono::milliseconds timeout) override;

        ConnectionStatus GetStatus() const override;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // IPC сервер - принимает команды от клиентов
    class IPCServer {
    public:
        explicit IPCServer(const IPCConfig& config = IPCConfig{});
        ~IPCServer();

        // Инициализация и управление
        bool Start();
        void Stop();
        bool IsRunning() const;

        // Регистрация обработчиков
        void SetMessageHandler(MessageHandler handler);
        void SetClientConnectedHandler(ClientConnectedHandler handler);
        void SetClientDisconnectedHandler(ClientDisconnectedHandler handler);
        void SetErrorHandler(ErrorHandler handler);

        // Отправка сообщений клиентам
        IPCResult SendToClient(uint32_t client_id, const IPCMessage& message);
        IPCResult BroadcastMessage(const IPCMessage& message, ClientType client_type = ClientType::UNKNOWN_CLIENT);

        // Управление клиентами
        std::vector<uint32_t> GetConnectedClients() const;
        ClientType GetClientType(uint32_t client_id) const;
        void DisconnectClient(uint32_t client_id);

        // Статистика
        std::size_t GetClientCount() const;
        std::size_t GetTotalMessagesReceived() const;
        std::size_t GetTotalMessagesSent() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // IPC клиент - отправляет команды серверу
    class IPCClient {
    public:
        explicit IPCClient(const IPCConfig& config = IPCConfig{});
        ~IPCClient();

        // Подключение и отключение
        bool Connect(ClientType client_type = ClientType::UI_CLIENT);
        void Disconnect();
        bool IsConnected() const;

        // Отправка команд
        IPCResult SendCommand(CommandType command, const std::string& data = "");
        IPCResult SendMessage(const IPCMessage& message);

        // Получение ответов (для асинхронных операций)
        std::optional<IPCMessage> ReceiveResponse(std::chrono::milliseconds timeout = std::chrono::milliseconds{5000});

        // Синхронные команды с ожиданием ответа
        IPCResult ExecuteCommand(CommandType command, const std::string& data = "",
                                std::chrono::milliseconds timeout = std::chrono::milliseconds{10000});

        // Регистрация обработчиков
        void SetErrorHandler(ErrorHandler handler);

        // Статистика
        std::size_t GetMessagesSent() const;
        std::size_t GetMessagesReceived() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер IPC соединений
    class IPCManager {
    public:
        static IPCManager& Instance();

        // Автоматический выбор лучшего транспорта
        static TransportType SelectBestTransport();

        // Создание транспортов
        std::unique_ptr<IPCTransport> CreateTransport(TransportType type,
                                                     const IPCConfig& config,
                                                     bool is_server = true);

        // Валидация конфигурации
        bool ValidateConfig(const IPCConfig& config) const;

        // Утилиты для сериализации
        std::vector<uint8_t> SerializeMessage(const IPCMessage& message) const;
        std::optional<IPCMessage> DeserializeMessage(const std::vector<uint8_t>& data) const;

        // Вычисление контрольной суммы
        uint32_t CalculateChecksum(const IPCMessage& message) const;
        bool ValidateChecksum(const IPCMessage& message) const;

    private:
        IPCManager() = default;
        ~IPCManager() = default;
        IPCManager(const IPCManager&) = delete;
        IPCManager& operator=(const IPCManager&) = delete;
    };

    // Утилитарные функции
    namespace Utils {
        std::string CommandTypeToString(CommandType type);
        CommandType StringToCommandType(const std::string& str);

        std::string ClientTypeToString(ClientType type);
        ClientType StringToClientType(const std::string& str);

        std::string TransportTypeToString(TransportType type);
        TransportType StringToTransportType(const std::string& str);

        // Генерация уникальных ID
        uint32_t GenerateMessageId();
        uint32_t GenerateClientId();

        // Безопасность
        bool ValidateAccessToken(const std::string& token);
        std::string GenerateAccessToken();

        // Время
        uint64_t GetCurrentTimestamp();
        std::chrono::system_clock::time_point TimestampToTimePoint(uint64_t timestamp);

        // Сетевые утилиты
        std::string GetProcessName();
        uint32_t GetProcessId();
    }
}