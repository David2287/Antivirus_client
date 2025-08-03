//
// Created by WhySkyDie on 21.07.2025.
//

#ifndef LOGGER_H
#define LOGGER_H

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <queue>
#include <thread>
#include <condition_variable>
#include <unordered_map>
#include <sstream>

namespace LoggingSystem {

    // Уровни логирования
    enum class LogLevel {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        FATAL = 5,
        OFF = 6
    };

    // Категории логов
    enum class LogCategory {
        GENERAL,
        SCANNER,
        QUARANTINE,
        SIGNATURES,
        NETWORK,
        UI,
        SERVICE,
        DATABASE,
        SECURITY,
        PERFORMANCE
    };

    // Приоритет логов
    enum class LogPriority {
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        CRITICAL = 4
    };

    // Места назначения логов
    enum class LogDestination {
        CONSOLE,
        FILE,
        ROTATING_FILE,
        SYSLOG,
        NETWORK,
        DATABASE,
        MEMORY_BUFFER,
        EVENT_LOG, // Windows Event Log
        CUSTOM
    };

    // Формат логов
    enum class LogFormat {
        PLAIN_TEXT,
        JSON,
        XML,
        CSV,
        STRUCTURED,
        CUSTOM
    };

    enum class LogLevel {
        INFO,
        WARNING,
        ERROR,
        DEBUG
    };

    // Запись лога
    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        LogLevel level;
        LogCategory category;
        LogPriority priority;
        std::string logger_name;
        std::string message;
        std::string thread_id;
        std::string process_id;
        std::string module_name;
        std::string function_name;
        std::string file_name;
        int line_number;

        // Дополнительные поля
        std::unordered_map<std::string, std::string> fields;
        std::string session_id;
        std::string user_id;
        std::string correlation_id;

        // Контекстная информация
        std::string component;
        std::string operation;
        std::string error_code;
        std::string stack_trace;

        std::chrono::system_clock::time_point timestamp;
        LogLevel level;
        std::string message;
        std::string thread_id;

        LogEntry(LogLevel lvl, const std::string& msg);

        LogEntry() : level(LogLevel::INFO), category(LogCategory::GENERAL),
                    priority(LogPriority::NORMAL), line_number(0) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    // Конфигурация логгера
    struct LoggerConfig {
        std::string name;
        LogLevel min_level = LogLevel::INFO;
        LogLevel max_level = LogLevel::FATAL;
        std::vector<LogDestination> destinations;
        LogFormat format = LogFormat::STRUCTURED;

        // Файловые настройки
        std::filesystem::path log_directory;
        std::string file_name_pattern = "%Y%m%d_%H%M%S.log";
        std::size_t max_file_size = 10 * 1024 * 1024; // 10MB
        int max_files = 10;
        bool auto_flush = true;

        // Буферизация
        std::size_t buffer_size = 1000;
        std::chrono::milliseconds flush_interval{1000};

        // Сетевые настройки
        std::string server_url;
        std::string api_key;
        int connection_timeout_ms = 5000;
        int retry_attempts = 3;
        std::chrono::seconds retry_delay{5};

        // Фильтрация
        std::vector<LogCategory> enabled_categories;
        std::vector<std::string> excluded_modules;
        std::vector<std::string> included_components;

        // Безопасность
        bool encrypt_logs = false;
        std::string encryption_key;
        bool sanitize_sensitive_data = true;

        // Производительность
        bool async_logging = true;
        int worker_threads = 2;
        std::size_t queue_size = 10000;

        LoggerConfig() {
            log_directory = std::filesystem::temp_directory_path() / "logs";
            destinations = {LogDestination::FILE, LogDestination::CONSOLE};
            enabled_categories = {LogCategory::GENERAL, LogCategory::ERROR};
        }
    };

    // Статистика логирования
    struct LogStatistics {
        std::atomic<std::uint64_t> total_messages{0};
        std::atomic<std::uint64_t> messages_by_level[7]{}; // По количеству LogLevel
        std::atomic<std::uint64_t> dropped_messages{0};
        std::atomic<std::uint64_t> network_failures{0};
        std::atomic<std::uint64_t> disk_write_failures{0};

        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_message_time;

        std::unordered_map<LogCategory, std::uint64_t> category_counts;
        std::unordered_map<std::string, std::uint64_t> module_counts;

        double average_processing_time_ms = 0.0;
        std::uint64_t total_bytes_written = 0;

        void Reset() {
            total_messages = 0;
            for (auto& count : messages_by_level) count = 0;
            dropped_messages = 0;
            network_failures = 0;
            disk_write_failures = 0;
            category_counts.clear();
            module_counts.clear();
            average_processing_time_ms = 0.0;
            total_bytes_written = 0;
            start_time = std::chrono::system_clock::now();
        }
    };

    class Logger {
    private:
        std::filesystem::path log_file_path;
        std::filesystem::path error_log_path;
        std::vector<LogEntry> log_buffer;
        std::vector<LogEntry> error_buffer;
        std::mutex log_mutex;
        std::mutex error_mutex;

        size_t max_buffer_size;
        bool auto_flush;

        // Вспомогательные методы
        std::string format_timestamp(const std::chrono::system_clock::time_point& time) const;
        std::string format_log_entry(const LogEntry& entry) const;
        std::string get_current_thread_id() const;
        bool write_buffer_to_file(const std::vector<LogEntry>& buffer, const std::filesystem::path& file_path);
        void ensure_log_directory_exists();

    public:
        explicit Logger(const std::filesystem::path& log_directory = "./logs",
                       size_t buffer_size = 100,
                       bool enable_auto_flush = true);
        ~Logger();

        // Основные методы с исправленными сигнатурами
        void log_event(const std::string& event_str);
        void log_error(const std::string& error_str);
        void flush_to_disk();

        // Дополнительные методы
        void log_info(const std::string& message);
        void log_warning(const std::string& message);
        void log_debug(const std::string& message);

        void set_max_buffer_size(size_t size);
        void set_auto_flush(bool enabled);
        void clear_logs();
        size_t get_buffer_size() const;
        bool rotate_logs(size_t max_file_size_mb = 10);

    private:
        void check_and_flush_if_needed();
    };

    // Интерфейс для пользовательских назначений
    class LogDestinationInterface {
    public:
        virtual ~LogDestinationInterface() = default;
        virtual bool Initialize(const LoggerConfig& config) = 0;
        virtual bool WriteLog(const LogEntry& entry, const std::string& formatted_message) = 0;
        virtual void Flush() = 0;
        virtual void Shutdown() = 0;
        virtual std::string GetName() const = 0;
    };

    // Интерфейс для пользовательских форматтеров
    class LogFormatterInterface {
    public:
        virtual ~LogFormatterInterface() = default;
        virtual std::string Format(const LogEntry& entry) = 0;
        virtual std::string GetName() const = 0;
    };

    // Callback типы
    using LogCallback = std::function<void(const LogEntry& entry)>;
    using ErrorCallback = std::function<void(const std::string& error_message)>;
    using FlushCallback = std::function<void()>;

    // Основной класс логгера
    class Logger {
    public:
        Logger();
        explicit Logger(const std::string& name);
        explicit Logger(const LoggerConfig& config);
        ~Logger();

        // Инициализация
        bool Initialize();
        bool Initialize(const LoggerConfig& config);
        void Shutdown();
        bool IsInitialized() const;

        // Конфигурация
        void SetConfig(const LoggerConfig& config);
        const LoggerConfig& GetConfig() const;
        void SetLevel(LogLevel level);
        LogLevel GetLevel() const;

        // Основные методы логирования
        void Log(LogLevel level, const std::string& message);
        void Log(LogLevel level, LogCategory category, const std::string& message);
        void Log(const LogEntry& entry);

        // Удобные методы
        void Trace(const std::string& message);
        void Debug(const std::string& message);
        void Info(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Fatal(const std::string& message);

        // Логирование с категориями
        void LogScanner(LogLevel level, const std::string& message);
        void LogQuarantine(LogLevel level, const std::string& message);
        void LogSignatures(LogLevel level, const std::string& message);
        void LogNetwork(LogLevel level, const std::string& message);
        void LogUI(LogLevel level, const std::string& message);
        void LogService(LogLevel level, const std::string& message);
        void LogSecurity(LogLevel level, const std::string& message);

        // Структурированное логирование
        template<typename... Args>
        void LogFormatted(LogLevel level, const std::string& format, Args&&... args);

        void LogWithFields(LogLevel level, const std::string& message,
                          const std::unordered_map<std::string, std::string>& fields);

        // Контекстное логирование
        void SetSessionId(const std::string& session_id);
        void SetUserId(const std::string& user_id);
        void SetCorrelationId(const std::string& correlation_id);
        void SetComponent(const std::string& component);

        // Управление назначениями
        bool AddDestination(LogDestination destination);
        bool RemoveDestination(LogDestination destination);
        bool AddCustomDestination(std::shared_ptr<LogDestinationInterface> destination);
        void SetCustomFormatter(std::shared_ptr<LogFormatterInterface> formatter);

        // Callbacks
        void SetLogCallback(LogCallback callback);
        void SetErrorCallback(ErrorCallback callback);
        void SetFlushCallback(FlushCallback callback);

        // Управление
        void Flush();
        void FlushAsync();
        bool IsAsyncMode() const;
        void SetAsyncMode(bool enabled);

        // Получение логов
        std::vector<LogEntry> GetRecentLogs(std::size_t count = 100) const;
        std::vector<LogEntry> GetLogsByLevel(LogLevel level, std::size_t count = 100) const;
        std::vector<LogEntry> GetLogsByCategory(LogCategory category, std::size_t count = 100) const;
        std::vector<LogEntry> GetLogsByTimeRange(
            const std::chrono::system_clock::time_point& start,
            const std::chrono::system_clock::time_point& end) const;

        // Поиск в логах
        std::vector<LogEntry> SearchLogs(const std::string& search_term, std::size_t max_results = 100) const;
        std::vector<LogEntry> FilterLogs(
            const std::function<bool(const LogEntry&)>& predicate,
            std::size_t max_results = 100) const;

        // Статистика
        LogStatistics GetStatistics() const;
        void ResetStatistics();

        // Экспорт
        bool ExportLogs(const std::filesystem::path& file_path, LogFormat format = LogFormat::JSON) const;
        bool ImportLogs(const std::filesystem::path& file_path);

        // Утилиты
        void SetThreadName(const std::string& name);
        std::string GetThreadName() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер логгеров (Singleton)
    class LoggerManager {
    public:
        static LoggerManager& Instance();

        // Управление логгерами
        std::shared_ptr<Logger> GetLogger(const std::string& name = "default");
        std::shared_ptr<Logger> CreateLogger(const std::string& name, const LoggerConfig& config);
        bool RemoveLogger(const std::string& name);

        // Глобальные настройки
        void SetGlobalLevel(LogLevel level);
        void SetGlobalConfig(const LoggerConfig& config);
        void FlushAll();
        void ShutdownAll();

        // Получение информации
        std::vector<std::string> GetLoggerNames() const;
        LogStatistics GetGlobalStatistics() const;

    private:
        LoggerManager() = default;
        ~LoggerManager() = default;
        LoggerManager(const LoggerManager&) = delete;
        LoggerManager& operator=(const LoggerManager&) = delete;

        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Макросы для удобного логирования с информацией о файле/строке
    #define LOG_TRACE(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::TRACE; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    #define LOG_DEBUG(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::DEBUG; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    #define LOG_INFO(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::INFO; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    #define LOG_WARNING(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::WARNING; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    #define LOG_ERROR(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::ERROR; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    #define LOG_FATAL(logger, message) \
        do { if (logger) { \
            LogEntry entry; \
            entry.level = LogLevel::FATAL; \
            entry.message = message; \
            entry.file_name = __FILE__; \
            entry.line_number = __LINE__; \
            entry.function_name = __FUNCTION__; \
            logger->Log(entry); \
        } } while(0)

    // Утилитарные функции
    namespace Utils {
        std::string LogLevelToString(LogLevel level);
        LogLevel StringToLogLevel(const std::string& level_str);

        std::string LogCategoryToString(LogCategory category);
        LogCategory StringToLogCategory(const std::string& category_str);

        std::string LogPriorityToString(LogPriority priority);
        LogPriority StringToLogPriority(const std::string& priority_str);

        std::string LogDestinationToString(LogDestination destination);
        LogDestination StringToLogDestination(const std::string& destination_str);

        std::string LogFormatToString(LogFormat format);
        LogFormat StringToLogFormat(const std::string& format_str);

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp_str);

        std::string SanitizeSensitiveData(const std::string& message);
        std::string GenerateCorrelationId();

        std::string GetCurrentThreadId();
        std::string GetCurrentProcessId();
        std::string GetModuleName();

        bool IsValidLogLevel(const std::string& level_str);
        bool CreateDirectories(const std::filesystem::path& path);

        std::string EscapeJsonString(const std::string& str);
        std::string EscapeXmlString(const std::string& str);
    }
}

#endif // LOGGER_H