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
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <queue>
#include <condition_variable>
#include <unordered_map>

#ifdef _WIN32
    #include <windows.h>
    #include <evntprov.h>
#else
    #include <syslog.h>
#endif

namespace LoggingSystem {

    // Уровни логирования
    enum class LogLevel {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        CRITICAL = 5,
        FATAL = 6
    };

    // Места назначения логов
    enum class LogDestination {
        CONSOLE = 0x01,
        FILE = 0x02,
        WINDOWS_EVENT_LOG = 0x04,
        SYSLOG = 0x08,
        NETWORK = 0x10,
        CALLBACK = 0x20
    };

    // Форматы логирования
    enum class LogFormat {
        SIMPLE,        // [LEVEL] Message
        DETAILED,      // [YYYY-MM-DD HH:MM:SS] [LEVEL] [Thread] [Function] Message
        JSON,          // {"timestamp":"...","level":"...","message":"..."}
        XML,           // <log><timestamp>...</timestamp><level>...</level><message>...</message></log>
        CUSTOM         // Пользовательский формат
    };

    // Политика ротации логов
    enum class RotationPolicy {
        NONE,
        SIZE_BASED,
        TIME_BASED,
        DAILY,
        WEEKLY,
        MONTHLY
    };

    // Структура записи лога
    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        LogLevel level;
        std::string message;
        std::string logger_name;
        std::string thread_id;
        std::string function_name;
        std::string file_name;
        int line_number;
        std::unordered_map<std::string, std::string> context_data;

        LogEntry() : level(LogLevel::INFO), line_number(0) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    // Конфигурация логгера
    struct LoggerConfig {
        std::string name = "DefaultLogger";
        LogLevel min_level = LogLevel::INFO;
        int destinations = static_cast<int>(LogDestination::FILE);
        LogFormat format = LogFormat::DETAILED;

        // Файловые настройки
        std::filesystem::path log_directory;
        std::string log_filename_pattern = "{name}_{date}.log";
        std::size_t max_file_size = 10 * 1024 * 1024; // 10MB
        int max_backup_files = 10;
        RotationPolicy rotation_policy = RotationPolicy::SIZE_BASED;

        // Буферизация
        bool async_logging = true;
        std::size_t buffer_size = 1000;
        std::chrono::milliseconds flush_interval{1000};

        // Windows Event Log
        std::string event_source_name = "AntivirusLogger";
        DWORD event_category = 0;

        // Сеть
        std::string network_host;
        int network_port = 514; // Syslog default

        // Производительность
        bool include_stack_trace = false;
        bool include_process_info = true;
        bool thread_safe = true;

        LoggerConfig() {
            log_directory = std::filesystem::temp_directory_path() / "logs";
        }
    };

    // Статистика логгера
    struct LoggerStatistics {
        std::atomic<std::uint64_t> total_messages{0};
        std::atomic<std::uint64_t> messages_by_level[7] = {};
        std::atomic<std::uint64_t> dropped_messages{0};
        std::atomic<std::uint64_t> bytes_written{0};

        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_message_time;

        double average_message_size = 0.0;
        std::size_t current_buffer_size = 0;

        void Reset() {
            total_messages = 0;
            for (int i = 0; i < 7; ++i) {
                messages_by_level[i] = 0;
            }
            dropped_messages = 0;
            bytes_written = 0;
            start_time = std::chrono::system_clock::now();
            average_message_size = 0.0;
            current_buffer_size = 0;
        }
    };

    // Forward declarations
    class Logger;
    class FileAppender;
    class EventLogAppender;
    class ConsoleAppender;

    // Callback типы
    using LogCallback = std::function<void(const LogEntry& entry)>;
    using LogFormatter = std::function<std::string(const LogEntry& entry)>;
    using LogFilter = std::function<bool(const LogEntry& entry)>;

    // Основной класс логгера
    class Logger {
    public:
        explicit Logger(const std::string& name = "Logger");
        explicit Logger(const LoggerConfig& config);
        ~Logger();

        // Конфигурирование
        void SetConfig(const LoggerConfig& config);
        const LoggerConfig& GetConfig() const;
        void SetLevel(LogLevel level);
        LogLevel GetLevel() const;

        // Основные методы логирования
        void Log(LogLevel level, const std::string& message);
        void Log(LogLevel level, const std::string& message, const std::string& function,
                const std::string& file, int line);

        void Trace(const std::string& message);
        void Debug(const std::string& message);
        void Info(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Critical(const std::string& message);
        void Fatal(const std::string& message);

        // Логирование с форматированием
        template<typename... Args>
        void LogF(LogLevel level, const std::string& format, Args&&... args);

        template<typename... Args>
        void InfoF(const std::string& format, Args&&... args);

        template<typename... Args>
        void ErrorF(const std::string& format, Args&&... args);

        // Контекстное логирование
        void LogWithContext(LogLevel level, const std::string& message,
                           const std::unordered_map<std::string, std::string>& context);

        void SetGlobalContext(const std::string& key, const std::string& value);
        void RemoveGlobalContext(const std::string& key);
        void ClearGlobalContext();

        // Управление appender'ами
        void AddDestination(LogDestination destination);
        void RemoveDestination(LogDestination destination);
        bool HasDestination(LogDestination destination) const;

        // Callbacks и фильтры
        void SetLogCallback(LogCallback callback);
        void SetCustomFormatter(LogFormatter formatter);
        void AddLogFilter(LogFilter filter);
        void ClearLogFilters();

        // Управление
        void Flush();
        void Close();
        bool IsEnabled(LogLevel level) const;

        // Статистика
        LoggerStatistics GetStatistics() const;
        void ResetStatistics();

        // Ротация логов
        void RotateLogs();
        void SetRotationCallback(std::function<void(const std::filesystem::path&)> callback);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Менеджер логгеров
    class LoggerManager {
    public:
        static LoggerManager& Instance();

        std::shared_ptr<Logger> GetLogger(const std::string& name);
        std::shared_ptr<Logger> CreateLogger(const std::string& name, const LoggerConfig& config);
        void RemoveLogger(const std::string& name);

        void SetGlobalLevel(LogLevel level);
        void SetGlobalConfig(const LoggerConfig& config);

        void FlushAll();
        void CloseAll();
        void Shutdown();

        std::vector<std::string> GetLoggerNames() const;

    private:
        LoggerManager() = default;
        ~LoggerManager() = default;
        LoggerManager(const LoggerManager&) = delete;
        LoggerManager& operator=(const LoggerManager&) = delete;

        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Appender'ы для различных назначений
    class LogAppender {
    public:
        virtual ~LogAppender() = default;
        virtual void Write(const LogEntry& entry) = 0;
        virtual void Flush() = 0;
        virtual void Close() = 0;
    };

    class FileAppender : public LogAppender {
    public:
        explicit FileAppender(const LoggerConfig& config);
        ~FileAppender() override;

        void Write(const LogEntry& entry) override;
        void Flush() override;
        void Close() override;

        void Rotate();
        std::filesystem::path GetCurrentLogFile() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    class ConsoleAppender : public LogAppender {
    public:
        explicit ConsoleAppender(const LoggerConfig& config);
        ~ConsoleAppender() override;

        void Write(const LogEntry& entry) override;
        void Flush() override;
        void Close() override;

        void SetColorEnabled(bool enabled);

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    class EventLogAppender : public LogAppender {
    public:
        explicit EventLogAppender(const LoggerConfig& config);
        ~EventLogAppender() override;

        void Write(const LogEntry& entry) override;
        void Flush() override;
        void Close() override;

        bool RegisterEventSource();
        void UnregisterEventSource();

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Форматтеры
    class LogFormatters {
    public:
        static std::string SimpleFormat(const LogEntry& entry);
        static std::string DetailedFormat(const LogEntry& entry);
        static std::string JsonFormat(const LogEntry& entry);
        static std::string XmlFormat(const LogEntry& entry);

        static LogFormatter CreateCustomFormatter(const std::string& pattern);
    };

    // Утилитарные функции
    namespace Utils {
        // Конвертация уровней
        std::string LogLevelToString(LogLevel level);
        LogLevel StringToLogLevel(const std::string& level_str);

        std::string LogDestinationToString(LogDestination destination);
        LogDestination StringToLogDestination(const std::string& destination_str);

        // Время
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp);
        std::string GetCurrentDateString();
        std::string GetCurrentTimeString();

        // Система
        std::string GetThreadId();
        std::string GetProcessId();
        std::string GetProcessName();
        std::string GetHostname();

        // Файлы
        std::string ExpandLogFileName(const std::string& pattern, const std::string& logger_name);
        std::vector<std::filesystem::path> FindLogFiles(const std::filesystem::path& directory,
                                                        const std::string& pattern);
        bool CreateDirectoryIfNotExists(const std::filesystem::path& path);

        // Windows Event Log
        WORD LogLevelToEventType(LogLevel level);
        DWORD LogLevelToEventId(LogLevel level);

        // Цвета для консоли
        void SetConsoleColor(LogLevel level);
        void ResetConsoleColor();
    }

    // Макросы для удобного логирования
    #define LOG_TRACE(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::TRACE)) \
            (logger)->Log(LoggingSystem::LogLevel::TRACE, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_DEBUG(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::DEBUG)) \
            (logger)->Log(LoggingSystem::LogLevel::DEBUG, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_INFO(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::INFO)) \
            (logger)->Log(LoggingSystem::LogLevel::INFO, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_WARNING(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::WARNING)) \
            (logger)->Log(LoggingSystem::LogLevel::WARNING, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_ERROR(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::ERROR)) \
            (logger)->Log(LoggingSystem::LogLevel::ERROR, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_CRITICAL(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::CRITICAL)) \
            (logger)->Log(LoggingSystem::LogLevel::CRITICAL, (message), __FUNCTION__, __FILE__, __LINE__)

    #define LOG_FATAL(logger, message) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::FATAL)) \
            (logger)->Log(LoggingSystem::LogLevel::FATAL, (message), __FUNCTION__, __FILE__, __LINE__)

    // Форматированное логирование
    #define LOG_INFO_F(logger, format, ...) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::INFO)) \
            (logger)->InfoF((format), __VA_ARGS__)

    #define LOG_ERROR_F(logger, format, ...) \
        if ((logger)->IsEnabled(LoggingSystem::LogLevel::ERROR)) \
            (logger)->ErrorF((format), __VA_ARGS__)

    // Глобальный логгер
    extern std::shared_ptr<Logger> g_default_logger;

    #define GLOBAL_LOG_INFO(message) \
        if (LoggingSystem::g_default_logger) \
            LoggingSystem::g_default_logger->Info(message)

    #define GLOBAL_LOG_ERROR(message) \
        if (LoggingSystem::g_default_logger) \
            LoggingSystem::g_default_logger->Error(message)

    #define GLOBAL_LOG_WARNING(message) \
        if (LoggingSystem::g_default_logger) \
            LoggingSystem::g_default_logger->Warning(message)
}
