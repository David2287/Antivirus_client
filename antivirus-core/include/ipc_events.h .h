//
// Created by WhySkyDie on 21.07.2025.
//

#ifndef IPC_EVENTS_H
#define IPC_EVENTS_H

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
#include <queue>
#include <thread>
#include <condition_variable>
#include <optional>

namespace IPCEvents {

    // Типы событий от UI
    enum class EventType {
        // Основные операции
        SCAN_START,
        SCAN_STOP,
        SCAN_PAUSE,
        SCAN_RESUME,
        SCAN_FILE,
        SCAN_DIRECTORY,

        // Управление файлами
        QUARANTINE_FILE,
        RESTORE_FILE,
        DELETE_FILE,
        DELETE_PERMANENTLY,
        DELETE_QUARANTINED,

        // Очистка
        CLEAR_QUARANTINE,
        CLEAR_LOGS,
        CLEAR_CACHE,
        CLEAR_STATISTICS,

        // Конфигурация
        UPDATE_SETTINGS,
        UPDATE_SIGNATURES,
        RELOAD_CONFIG,
        SAVE_CONFIG,

        // Базы данных
        UPDATE_SIGNATURES,
        RELOAD_SIGNATURES,
        EXPORT_SIGNATURES,

        // Аутентификация
        LOGIN_REQUEST,
        LOGOUT_REQUEST,
        REFRESH_TOKEN,

        // Отчеты и экспорт
        GENERATE_REPORT,
        EXPORT_LOGS,
        EXPORT_DATA,

        // Сервисные команды
        RESTART_SERVICE,
        SHUTDOWN_SERVICE,
        CHECK_STATUS,
        GET_SCAN_STATUS,
        GET_QUARANTINE_LIST,

        // Пользовательские команды
        SHOW_ABOUT,
        OPEN_HELP,
        CUSTOM_COMMAND
    };

    // Приоритет обработки события
    enum class EventPriority {
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        CRITICAL = 4
    };

    // Статус выполнения команды
    enum class CommandStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        FAILED,
        CANCELLED,
        TIMEOUT
    };

    // Тип ответа
    enum class ResponseType {
        SUCCESS,
        ERROR,
        PROGRESS,
        INFO,
        WARNING,
        CONFIRMATION_REQUIRED
    };

    // Параметры события
    struct EventParameters {
        std::unordered_map<std::string, std::string> string_params;
        std::unordered_map<std::string, int> int_params;
        std::unordered_map<std::string, bool> bool_params;
        std::unordered_map<std::string, double> double_params;
        std::vector<std::string> file_paths;
        std::vector<std::string> string_list;

        // Утилитарные методы
        void SetParam(const std::string& key, const std::string& value) {
            string_params[key] = value;
        }

        void SetParam(const std::string& key, int value) {
            int_params[key] = value;
        }

        void SetParam(const std::string& key, bool value) {
            bool_params[key] = value;
        }

        void SetParam(const std::string& key, double value) {
            double_params[key] = value;
        }

        std::string GetStringParam(const std::string& key, const std::string& default_value = "") const {
            auto it = string_params.find(key);
            return it != string_params.end() ? it->second : default_value;
        }

        int GetIntParam(const std::string& key, int default_value = 0) const {
            auto it = int_params.find(key);
            return it != int_params.end() ? it->second : default_value;
        }

        bool GetBoolParam(const std::string& key, bool default_value = false) const {
            auto it = bool_params.find(key);
            return it != bool_params.end() ? it->second : default_value;
        }

        double GetDoubleParam(const std::string& key, double default_value = 0.0) const {
            auto it = double_params.find(key);
            return it != double_params.end() ? it->second : default_value;
        }
    };

    struct CommandResponse {
        CommandResult result;
        std::string message;
        json data;
        std::string request_id;

        CommandResponse(CommandResult res = CommandResult::ERROR,
                       const std::string& msg = "",
                       const json& response_data = json{},
                       const std::string& req_id = "");
    };

    // Событие от UI
    struct UIEvent {
        std::string event_id;
        EventType type;
        EventPriority priority;
        std::string source_component;
        std::string user_id;
        std::chrono::system_clock::time_point timestamp;
        EventParameters parameters;
        std::string description;

        // Контекст выполнения
        std::string session_id;
        std::string correlation_id;

        UIEvent() : type(EventType::CUSTOM_COMMAND), priority(EventPriority::NORMAL) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    // Ответ на событие
    struct EventResponse {
        std::string event_id;
        std::string response_id;
        ResponseType type;
        CommandStatus status;
        std::string message;
        std::string error_code;
        EventParameters data;
        std::chrono::system_clock::time_point timestamp;
        std::chrono::milliseconds processing_time{0};

        // Прогресс выполнения (для длительных операций)
        int progress_percentage = 0;
        std::string current_operation;
        std::string estimated_time_remaining;

        EventResponse() : type(ResponseType::SUCCESS), status(CommandStatus::PENDING) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    // Конфигурация обработчика событий
    struct EventHandlerConfig {
        int max_worker_threads = 4;
        std::size_t max_queue_size = 1000;
        std::chrono::milliseconds event_timeout{30000}; // 30 секунд
        std::chrono::milliseconds response_timeout{5000}; // 5 секунд

        bool enable_event_logging = true;
        bool enable_performance_monitoring = true;
        bool enable_async_processing = true;

        std::filesystem::path log_directory;
        std::size_t max_log_files = 10;
        std::size_t max_log_file_size = 10 * 1024 * 1024; // 10MB

        EventHandlerConfig() {
            log_directory = std::filesystem::temp_directory_path() / "ipc_events";
        }
    };

    // Статистика обработки событий
    struct EventStatistics {
        std::atomic<std::uint64_t> total_events{0};
        std::atomic<std::uint64_t> processed_events{0};
        std::atomic<std::uint64_t> failed_events{0};
        std::atomic<std::uint64_t> timeout_events{0};
        std::atomic<std::uint64_t> cancelled_events{0};

        std::unordered_map<EventType, std::uint64_t> event_type_counts;
        std::unordered_map<std::string, std::uint64_t> component_counts;

        double average_processing_time_ms = 0.0;
        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_event_time;

        void Reset() {
            total_events = 0;
            processed_events = 0;
            failed_events = 0;
            timeout_events = 0;
            cancelled_events = 0;
            event_type_counts.clear();
            component_counts.clear();
            average_processing_time_ms = 0.0;
            start_time = std::chrono::system_clock::now();
        }
    };

    // Callback типы
    using EventCallback = std::function<EventResponse(const UIEvent& event)>;
    using ProgressCallback = std::function<void(const std::string& event_id, int percentage, const std::string& operation)>;
    using ErrorCallback = std::function<void(const std::string& error_message, const UIEvent& event)>;
    using StatusCallback = std::function<void(const std::string& status_message)>;

    class IPCEventHandler {
    private:
        // Очереди команд и ответов
        std::queue<json> command_queue;
        std::queue<CommandResponse> response_queue;

        // Синхронизация
        std::mutex command_mutex;
        std::mutex response_mutex;
        std::condition_variable command_cv;
        std::condition_variable response_cv;

        // Поток обработки
        std::thread processing_thread;
        std::atomic<bool> running;

        // Карта обработчиков команд
        std::unordered_map<CommandType, std::function<CommandResponse(const json&)>> command_handlers;

        // Зависимости (инжектируются извне)
        class Scanner* scanner;
        class QuarantineManager* quarantine_manager;
        class SignatureDB* signature_db;
        class AuthManager* auth_manager;
        class Logger* logger;

        // Вспомогательные методы
        CommandType parse_command_type(const std::string& command) const;
        std::string generate_request_id() const;
        bool validate_command_structure(const json& command) const;
        void register_command_handlers();
        void process_commands();

        // Обработчики конкретных команд
        CommandResponse handle_scan_file(const json& params);
        CommandResponse handle_scan_directory(const json& params);
        CommandResponse handle_quarantine_file(const json& params);
        CommandResponse handle_restore_file(const json& params);
        CommandResponse handle_delete_quarantined(const json& params);
        CommandResponse handle_update_signatures(const json& params);
        CommandResponse handle_get_scan_status(const json& params);
        CommandResponse handle_get_quarantine_list(const json& params);
        CommandResponse handle_login(const json& params);
        CommandResponse handle_register_device(const json& params);
        CommandResponse handle_logout(const json& params);

    public:
        explicit IPCEventHandler();
        ~IPCEventHandler();

        // Основной метод для обработки команд
        void handle_command(const json& command);

        // Методы для установки зависимостей
        void set_scanner(class Scanner* scanner_instance);
        void set_quarantine_manager(class QuarantineManager* quarantine_instance);
        void set_signature_db(class SignatureDB* signature_instance);
        void set_auth_manager(class AuthManager* auth_instance);
        void set_logger(class Logger* logger_instance);

        // Методы для получения ответов
        bool has_response() const;
        CommandResponse get_response();
        CommandResponse get_response_blocking(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

        // Управление состоянием
        void start();
        void stop();
        bool is_running() const;

        // Информационные методы
        size_t get_queue_size() const;
        void clear_queues();
    };

    // Основной класс обработчика событий IPC
    class IPCEventHandler {
    public:
        IPCEventHandler();
        explicit IPCEventHandler(const EventHandlerConfig& config);
        ~IPCEventHandler();

        // Инициализация
        bool Initialize();
        bool Initialize(const EventHandlerConfig& config);
        void Shutdown();
        bool IsInitialized() const;

        // Конфигурация
        void SetConfig(const EventHandlerConfig& config);
        const EventHandlerConfig& GetConfig() const;

        // Регистрация обработчиков событий
        void RegisterEventHandler(EventType event_type, EventCallback handler);
        void UnregisterEventHandler(EventType event_type);
        void RegisterDefaultHandlers();

        // Callbacks
        void SetProgressCallback(ProgressCallback callback);
        void SetErrorCallback(ErrorCallback callback);
        void SetStatusCallback(StatusCallback callback);

        // Обработка событий
        std::string ProcessEvent(const UIEvent& event);
        std::string ProcessEventAsync(const UIEvent& event);

        // Получение результатов
        std::optional<EventResponse> GetEventResult(const std::string& event_id);
        std::vector<EventResponse> GetPendingResults();

        // Управление выполнением
        bool CancelEvent(const std::string& event_id);
        std::vector<std::string> GetActiveEvents() const;

        // Статистика
        EventStatistics GetStatistics() const;
        void ResetStatistics();

        // Мониторинг
        std::vector<UIEvent> GetRecentEvents(std::size_t count = 100) const;
        std::vector<EventResponse> GetRecentResponses(std::size_t count = 100) const;

        // Утилиты
        std::string GenerateEventId() const;
        bool IsEventTypeSupported(EventType event_type) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер команд для различных операций
    class CommandManager {
    public:
        CommandManager();
        ~CommandManager();

        // Команды сканирования
        EventResponse HandleScanStart(const EventParameters& params);
        EventResponse HandleScanStop(const EventParameters& params);
        EventResponse HandleScanPause(const EventParameters& params);
        EventResponse HandleScanResume(const EventParameters& params);

        // Команды управления файлами
        EventResponse HandleQuarantineFile(const EventParameters& params);
        EventResponse HandleRestoreFile(const EventParameters& params);
        EventResponse HandleDeleteFile(const EventParameters& params);
        EventResponse HandleDeletePermanently(const EventParameters& params);

        // Команды очистки
        EventResponse HandleClearQuarantine(const EventParameters& params);
        EventResponse HandleClearLogs(const EventParameters& params);
        EventResponse HandleClearCache(const EventParameters& params);
        EventResponse HandleClearStatistics(const EventParameters& params);

        // Команды конфигурации
        EventResponse HandleUpdateSettings(const EventParameters& params);
        EventResponse HandleReloadConfig(const EventParameters& params);
        EventResponse HandleSaveConfig(const EventParameters& params);

        // Команды баз данных
        EventResponse HandleUpdateSignatures(const EventParameters& params);
        EventResponse HandleReloadSignatures(const EventParameters& params);
        EventResponse HandleExportSignatures(const EventParameters& params);

        // Команды аутентификации
        EventResponse HandleLoginRequest(const EventParameters& params);
        EventResponse HandleLogoutRequest(const EventParameters& params);
        EventResponse HandleRefreshToken(const EventParameters& params);

        // Команды отчетов
        EventResponse HandleGenerateReport(const EventParameters& params);
        EventResponse HandleExportLogs(const EventParameters& params);
        EventResponse HandleExportData(const EventParameters& params);

        // Сервисные команды
        EventResponse HandleRestartService(const EventParameters& params);
        EventResponse HandleShutdownService(const EventParameters& params);
        EventResponse HandleCheckStatus(const EventParameters& params);

        // Установка зависимостей
        void SetScannerInterface(void* scanner_ptr);
        void SetQuarantineInterface(void* quarantine_ptr);
        void SetAuthInterface(void* auth_ptr);
        void SetLoggerInterface(void* logger_ptr);
        void SetConfigInterface(void* config_ptr);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        std::string EventTypeToString(EventType type);
        EventType StringToEventType(const std::string& type_str);

        std::string EventPriorityToString(EventPriority priority);
        EventPriority StringToEventPriority(const std::string& priority_str);

        std::string CommandStatusToString(CommandStatus status);
        CommandStatus StringToCommandStatus(const std::string& status_str);

        std::string ResponseTypeToString(ResponseType type);
        ResponseType StringToResponseType(const std::string& type_str);

        // Сериализация
        std::string SerializeEvent(const UIEvent& event);
        UIEvent DeserializeEvent(const std::string& serialized_data);

        std::string SerializeResponse(const EventResponse& response);
        EventResponse DeserializeResponse(const std::string& serialized_data);

        // Валидация
        bool ValidateEvent(const UIEvent& event);
        bool ValidateParameters(EventType event_type, const EventParameters& params);

        // Время
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str);

        // ID генерация
        std::string GenerateUniqueId();
        std::string GenerateCorrelationId();

        // Прогресс
        std::string FormatProgress(int percentage, const std::string& operation, const std::string& eta);

        // Ошибки
        EventResponse CreateErrorResponse(const std::string& event_id, const std::string& error_message, const std::string& error_code = "");
        EventResponse CreateSuccessResponse(const std::string& event_id, const std::string& message = "");
        EventResponse CreateProgressResponse(const std::string& event_id, int percentage, const std::string& operation);
    }
}

#endif // IPC_EVENTS_H