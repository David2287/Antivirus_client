//
// Created by WhySkyDie on 21.07.2025.
//

#include "logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>
#include <regex>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
    #include <processthreadsapi.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
#endif

namespace LoggingSystem {

    // Глобальный логгер
    std::shared_ptr<Logger> g_default_logger;

    // ============================================================================
    // Logger::Impl
    // ============================================================================

    class Logger::Impl {
    public:
        LoggerConfig config;
        std::atomic<LogLevel> current_level{LogLevel::INFO};

        // Appender'ы
        std::vector<std::unique_ptr<LogAppender>> appenders;

        // Асинхронная обработка
        std::queue<LogEntry> message_queue;
        std::mutex queue_mutex;
        std::condition_variable queue_cv;
        std::thread worker_thread;
        std::atomic<bool> should_stop{false};

        // Callbacks и фильтры
        LogCallback log_callback;
        LogFormatter custom_formatter;
        std::vector<LogFilter> filters;

        // Глобальный контекст
        std::unordered_map<std::string, std::string> global_context;
        std::mutex context_mutex;

        // Статистика
        mutable std::mutex stats_mutex;
        LoggerStatistics statistics;

        // Ротация
        std::function<void(const std::filesystem::path&)> rotation_callback;

        Impl() {
            statistics.start_time = std::chrono::system_clock::now();
        }

        ~Impl() {
            Shutdown();
        }

        void Initialize() {
            // Создание директорий
            if (!config.log_directory.empty()) {
                Utils::CreateDirectoryIfNotExists(config.log_directory);
            }

            // Создание appender'ов
            CreateAppenders();

            // Запуск асинхронного потока если нужен
            if (config.async_logging) {
                StartWorkerThread();
            }
        }

        void CreateAppenders() {
            appenders.clear();

            if (config.destinations & static_cast<int>(LogDestination::CONSOLE)) {
                appenders.push_back(std::make_unique<ConsoleAppender>(config));
            }

            if (config.destinations & static_cast<int>(LogDestination::FILE)) {
                appenders.push_back(std::make_unique<FileAppender>(config));
            }

            if (config.destinations & static_cast<int>(LogDestination::WINDOWS_EVENT_LOG)) {
                appenders.push_back(std::make_unique<EventLogAppender>(config));
            }
        }

        void StartWorkerThread() {
            should_stop = false;
            worker_thread = std::thread([this]() {
                WorkerThreadLoop();
            });
        }

        void WorkerThreadLoop() {
            auto last_flush = std::chrono::steady_clock::now();

            while (!should_stop.load()) {
                std::unique_lock<std::mutex> lock(queue_mutex);

                // Ждем сообщения или таймаута
                queue_cv.wait_for(lock, config.flush_interval, [this]() {
                    return !message_queue.empty() || should_stop.load();
                });

                // Обработка всех сообщений в очереди
                std::vector<LogEntry> entries_to_process;
                while (!message_queue.empty()) {
                    entries_to_process.push_back(std::move(message_queue.front()));
                    message_queue.pop();
                }
                lock.unlock();

                // Запись сообщений
                for (const auto& entry : entries_to_process) {
                    ProcessLogEntry(entry);
                }

                // Периодический flush
                auto now = std::chrono::steady_clock::now();
                if (now - last_flush >= config.flush_interval) {
                    FlushAllAppenders();
                    last_flush = now;
                }
            }

            // Финальная обработка оставшихся сообщений
            std::unique_lock<std::mutex> lock(queue_mutex);
            while (!message_queue.empty()) {
                ProcessLogEntry(message_queue.front());
                message_queue.pop();
            }
            lock.unlock();

            FlushAllAppenders();
        }

        void LogImpl(LogLevel level, const std::string& message, const std::string& function = "",
                    const std::string& file = "", int line = 0) {

            if (level < current_level.load()) {
                return;
            }

            // Создание записи лога
            LogEntry entry;
            entry.timestamp = std::chrono::system_clock::now();
            entry.level = level;
            entry.message = message;
            entry.logger_name = config.name;
            entry.thread_id = Utils::GetThreadId();
            entry.function_name = function;
            entry.file_name = file;
            entry.line_number = line;

            // Добавление глобального контекста
            {
                std::lock_guard<std::mutex> lock(context_mutex);
                entry.context_data = global_context;
            }

            // Применение фильтров
            for (const auto& filter : filters) {
                if (!filter(entry)) {
                    return; // Сообщение отфильтровано
                }
            }

            // Обновление статистики
            UpdateStatistics(entry);

            if (config.async_logging) {
                // Асинхронная обработка
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (message_queue.size() < config.buffer_size) {
                        message_queue.push(std::move(entry));
                    } else {
                        // Буфер переполнен - отбрасываем сообщение
                        statistics.dropped_messages++;
                    }
                }
                queue_cv.notify_one();
            } else {
                // Синхронная обработка
                ProcessLogEntry(entry);
            }
        }

        void ProcessLogEntry(const LogEntry& entry) {
            try {
                // Callback
                if (log_callback) {
                    log_callback(entry);
                }

                // Запись через все appender'ы
                for (auto& appender : appenders) {
                    appender->Write(entry);
                }

            } catch (const std::exception& e) {
                // Ошибка записи - пытаемся записать в stderr
                std::cerr << "Logger error: " << e.what() << std::endl;
            }
        }

        void UpdateStatistics(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(stats_mutex);

            statistics.total_messages++;
            statistics.messages_by_level[static_cast<int>(entry.level)]++;
            statistics.last_message_time = entry.timestamp;

            // Обновление среднего размера сообщения
            double message_size = entry.message.size();
            if (statistics.total_messages > 0) {
                statistics.average_message_size =
                    (statistics.average_message_size * (statistics.total_messages - 1) + message_size)
                    / statistics.total_messages;
            }

            statistics.current_buffer_size = message_queue.size();
        }

        void FlushAllAppenders() {
            for (auto& appender : appenders) {
                appender->Flush();
            }
        }

        void Shutdown() {
            if (config.async_logging && worker_thread.joinable()) {
                should_stop = true;
                queue_cv.notify_all();
                worker_thread.join();
            }

            // Закрытие всех appender'ов
            for (auto& appender : appenders) {
                appender->Close();
            }
            appenders.clear();
        }

        std::string FormatMessage(const LogEntry& entry) {
            if (custom_formatter) {
                return custom_formatter(entry);
            }

            switch (config.format) {
                case LogFormat::SIMPLE:
                    return LogFormatters::SimpleFormat(entry);
                case LogFormat::DETAILED:
                    return LogFormatters::DetailedFormat(entry);
                case LogFormat::JSON:
                    return LogFormatters::JsonFormat(entry);
                case LogFormat::XML:
                    return LogFormatters::XmlFormat(entry);
                default:
                    return LogFormatters::DetailedFormat(entry);
            }
        }
    };

    // ============================================================================
    // FileAppender::Impl
    // ============================================================================

    class FileAppender::Impl {
    public:
        LoggerConfig config;
        std::filesystem::path current_log_file;
        std::ofstream file_stream;
        std::mutex file_mutex;
        std::size_t current_file_size = 0;

        Impl(const LoggerConfig& cfg) : config(cfg) {
            CreateLogFile();
        }

        ~Impl() {
            Close();
        }

        void CreateLogFile() {
            current_log_file = config.log_directory /
                Utils::ExpandLogFileName(config.log_filename_pattern, config.name);

            file_stream.open(current_log_file, std::ios::out | std::ios::app);
            if (!file_stream.is_open()) {
                throw std::runtime_error("Cannot open log file: " + current_log_file.string());
            }

            current_file_size = std::filesystem::exists(current_log_file) ?
                std::filesystem::file_size(current_log_file) : 0;
        }

        void Write(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(file_mutex);

            if (!file_stream.is_open()) {
                return;
            }

            std::string formatted_message = FormatEntry(entry);
            file_stream << formatted_message << std::endl;

            current_file_size += formatted_message.size() + 1; // +1 для \n

            // Проверка необходимости ротации
            if (ShouldRotate()) {
                Rotate();
            }
        }

        void Flush() {
            std::lock_guard<std::mutex> lock(file_mutex);
            if (file_stream.is_open()) {
                file_stream.flush();
            }
        }

        void Close() {
            std::lock_guard<std::mutex> lock(file_mutex);
            if (file_stream.is_open()) {
                file_stream.close();
            }
        }

        void Rotate() {
            if (!file_stream.is_open()) {
                return;
            }

            file_stream.close();

            // Переименование текущего файла
            std::string backup_name = current_log_file.stem().string() + "_" +
                Utils::GetCurrentDateString() + "_" +
                std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()) +
                current_log_file.extension().string();

            std::filesystem::path backup_path = current_log_file.parent_path() / backup_name;

            try {
                std::filesystem::rename(current_log_file, backup_path);
            } catch (const std::exception& e) {
                // Ошибка переименования - продолжаем с новым файлом
            }

            // Создание нового файла
            CreateLogFile();

            // Очистка старых файлов
            CleanupOldFiles();
        }

        bool ShouldRotate() const {
            switch (config.rotation_policy) {
                case RotationPolicy::SIZE_BASED:
                    return current_file_size >= config.max_file_size;
                case RotationPolicy::DAILY:
                    // Упрощенная проверка - в реальности нужна более точная логика
                    return false;
                default:
                    return false;
            }
        }

        void CleanupOldFiles() {
            try {
                auto log_files = Utils::FindLogFiles(config.log_directory, config.name + "_*");

                if (log_files.size() > static_cast<size_t>(config.max_backup_files)) {
                    // Сортировка по времени модификации
                    std::sort(log_files.begin(), log_files.end(), [](const auto& a, const auto& b) {
                        return std::filesystem::last_write_time(a) < std::filesystem::last_write_time(b);
                    });

                    // Удаление самых старых файлов
                    for (size_t i = 0; i < log_files.size() - config.max_backup_files; ++i) {
                        std::filesystem::remove(log_files[i]);
                    }
                }
            } catch (const std::exception& e) {
                // Ошибка очистки - игнорируем
            }
        }

        std::string FormatEntry(const LogEntry& entry) {
            switch (config.format) {
                case LogFormat::SIMPLE:
                    return LogFormatters::SimpleFormat(entry);
                case LogFormat::DETAILED:
                    return LogFormatters::DetailedFormat(entry);
                case LogFormat::JSON:
                    return LogFormatters::JsonFormat(entry);
                case LogFormat::XML:
                    return LogFormatters::XmlFormat(entry);
                default:
                    return LogFormatters::DetailedFormat(entry);
            }
        }
    };

    // ============================================================================
    // ConsoleAppender::Impl
    // ============================================================================

    class ConsoleAppender::Impl {
    public:
        LoggerConfig config;
        bool color_enabled = true;
        std::mutex console_mutex;

        Impl(const LoggerConfig& cfg) : config(cfg) {}

        void Write(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(console_mutex);

            if (color_enabled) {
                Utils::SetConsoleColor(entry.level);
            }

            std::string formatted = FormatEntry(entry);
            std::cout << formatted << std::endl;

            if (color_enabled) {
                Utils::ResetConsoleColor();
            }
        }

        void Flush() {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout.flush();
        }

        void Close() {
            // Консоль не нужно закрывать
        }

        std::string FormatEntry(const LogEntry& entry) {
            return LogFormatters::SimpleFormat(entry);
        }
    };

    // ============================================================================
    // EventLogAppender::Impl (Windows)
    // ============================================================================

    class EventLogAppender::Impl {
    public:
        LoggerConfig config;

#ifdef _WIN32
        HANDLE event_log_handle = nullptr;

        Impl(const LoggerConfig& cfg) : config(cfg) {
            RegisterEventSource();
        }

        ~Impl() {
            Close();
        }

        bool RegisterEventSource() {
            event_log_handle = RegisterEventSourceA(nullptr, config.event_source_name.c_str());
            return event_log_handle != nullptr;
        }

        void Write(const LogEntry& entry) {
            if (!event_log_handle) {
                return;
            }

            WORD event_type = Utils::LogLevelToEventType(entry.level);
            DWORD event_id = Utils::LogLevelToEventId(entry.level);

            std::string formatted = FormatEntry(entry);
            const char* messages[] = {formatted.c_str()};

            ReportEventA(
                event_log_handle,
                event_type,
                static_cast<WORD>(config.event_category),
                event_id,
                nullptr,
                1,
                0,
                messages,
                nullptr
            );
        }

        void Flush() {
            // Event Log не требует flush
        }

        void Close() {
            if (event_log_handle) {
                DeregisterEventSource(event_log_handle);
                event_log_handle = nullptr;
            }
        }

#else
        Impl(const LoggerConfig& cfg) : config(cfg) {
            openlog(config.event_source_name.c_str(), LOG_PID | LOG_CONS, LOG_USER);
        }

        ~Impl() {
            closelog();
        }

        void Write(const LogEntry& entry) {
            int priority = ConvertLogLevel(entry.level);
            std::string formatted = FormatEntry(entry);
            syslog(priority, "%s", formatted.c_str());
        }

        void Flush() {
            // Syslog не требует flush
        }

        void Close() {
            closelog();
        }

        int ConvertLogLevel(LogLevel level) {
            switch (level) {
                case LogLevel::TRACE:
                case LogLevel::DEBUG: return LOG_DEBUG;
                case LogLevel::INFO: return LOG_INFO;
                case LogLevel::WARNING: return LOG_WARNING;
                case LogLevel::ERROR: return LOG_ERR;
                case LogLevel::CRITICAL:
                case LogLevel::FATAL: return LOG_CRIT;
                default: return LOG_INFO;
            }
        }
#endif

        std::string FormatEntry(const LogEntry& entry) {
            return LogFormatters::SimpleFormat(entry);
        }
    };

    // ============================================================================
    // LoggerManager::Impl
    // ============================================================================

    class LoggerManager::Impl {
    public:
        std::unordered_map<std::string, std::shared_ptr<Logger>> loggers;
        mutable std::mutex loggers_mutex;
        LoggerConfig global_config;
        LogLevel global_level = LogLevel::INFO;

        std::shared_ptr<Logger> GetLogger(const std::string& name) {
            std::lock_guard<std::mutex> lock(loggers_mutex);

            auto it = loggers.find(name);
            if (it != loggers.end()) {
                return it->second;
            }

            // Создание нового логгера с глобальной конфигурацией
            LoggerConfig config = global_config;
            config.name = name;
            config.min_level = global_level;

            auto logger = std::make_shared<Logger>(config);
            loggers[name] = logger;
            return logger;
        }

        std::shared_ptr<Logger> CreateLogger(const std::string& name, const LoggerConfig& config) {
            std::lock_guard<std::mutex> lock(loggers_mutex);

            auto logger = std::make_shared<Logger>(config);
            loggers[name] = logger;
            return logger;
        }

        void RemoveLogger(const std::string& name) {
            std::lock_guard<std::mutex> lock(loggers_mutex);

            auto it = loggers.find(name);
            if (it != loggers.end()) {
                it->second->Close();
                loggers.erase(it);
            }
        }

        void SetGlobalLevel(LogLevel level) {
            std::lock_guard<std::mutex> lock(loggers_mutex);
            global_level = level;

            for (auto& [name, logger] : loggers) {
                logger->SetLevel(level);
            }
        }

        void FlushAll() {
            std::lock_guard<std::mutex> lock(loggers_mutex);
            for (auto& [name, logger] : loggers) {
                logger->Flush();
            }
        }

        void CloseAll() {
            std::lock_guard<std::mutex> lock(loggers_mutex);
            for (auto& [name, logger] : loggers) {
                logger->Close();
            }
            loggers.clear();
        }

        std::vector<std::string> GetLoggerNames() const {
            std::lock_guard<std::mutex> lock(loggers_mutex);
            std::vector<std::string> names;
            names.reserve(loggers.size());

            for (const auto& [name, logger] : loggers) {
                names.push_back(name);
            }

            return names;
        }
    };

    // ============================================================================
    // Реализация основных классов
    // ============================================================================

    // Logger
    Logger::Logger(const std::string& name) : pImpl(std::make_unique<Impl>()) {
        pImpl->config.name = name;
        pImpl->Initialize();
    }

    Logger::Logger(const LoggerConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
        pImpl->current_level = config.min_level;
        pImpl->Initialize();
    }

    Logger::~Logger() = default;

    void Logger::SetConfig(const LoggerConfig& config) {
        pImpl->config = config;
        pImpl->current_level = config.min_level;
        pImpl->Initialize();
    }

    const LoggerConfig& Logger::GetConfig() const {
        return pImpl->config;
    }

    void Logger::SetLevel(LogLevel level) {
        pImpl->current_level = level;
    }

    LogLevel Logger::GetLevel() const {
        return pImpl->current_level.load();
    }

    void Logger::Log(LogLevel level, const std::string& message) {
        pImpl->LogImpl(level, message);
    }

    void Logger::Log(LogLevel level, const std::string& message, const std::string& function,
                     const std::string& file, int line) {
        pImpl->LogImpl(level, message, function, file, line);
    }

    void Logger::Trace(const std::string& message) {
        Log(LogLevel::TRACE, message);
    }

    void Logger::Debug(const std::string& message) {
        Log(LogLevel::DEBUG, message);
    }

    void Logger::Info(const std::string& message) {
        Log(LogLevel::INFO, message);
    }

    void Logger::Warning(const std::string& message) {
        Log(LogLevel::WARNING, message);
    }

    void Logger::Error(const std::string& message) {
        Log(LogLevel::ERROR, message);
    }

    void Logger::Critical(const std::string& message) {
        Log(LogLevel::CRITICAL, message);
    }

    void Logger::Fatal(const std::string& message) {
        Log(LogLevel::FATAL, message);
    }

    template<typename... Args>
    void Logger::LogF(LogLevel level, const std::string& format, Args&&... args) {
        if (IsEnabled(level)) {
            std::ostringstream oss;
            FormatImpl(oss, format, std::forward<Args>(args)...);
            Log(level, oss.str());
        }
    }

    template<typename... Args>
    void Logger::InfoF(const std::string& format, Args&&... args) {
        LogF(LogLevel::INFO, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void Logger::ErrorF(const std::string& format, Args&&... args) {
        LogF(LogLevel::ERROR, format, std::forward<Args>(args)...);
    }

    void Logger::SetGlobalContext(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(pImpl->context_mutex);
        pImpl->global_context[key] = value;
    }

    void Logger::SetLogCallback(LogCallback callback) {
        pImpl->log_callback = std::move(callback);
    }

    void Logger::SetCustomFormatter(LogFormatter formatter) {
        pImpl->custom_formatter = std::move(formatter);
    }

    void Logger::AddLogFilter(LogFilter filter) {
        pImpl->filters.push_back(std::move(filter));
    }

    void Logger::Flush() {
        pImpl->FlushAllAppenders();
    }

    void Logger::Close() {
        pImpl->Shutdown();
    }

    bool Logger::IsEnabled(LogLevel level) const {
        return level >= pImpl->current_level.load();
    }

    LoggerStatistics Logger::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    void Logger::RotateLogs() {
        for (auto& appender : pImpl->appenders) {
            auto* file_appender = dynamic_cast<FileAppender*>(appender.get());
            if (file_appender) {
                file_appender->Rotate();
            }
        }
    }

    // LoggerManager
    LoggerManager& LoggerManager::Instance() {
        static LoggerManager instance;
        if (!instance.pImpl) {
            instance.pImpl = std::make_unique<Impl>();
        }
        return instance;
    }

    std::shared_ptr<Logger> LoggerManager::GetLogger(const std::string& name) {
        return pImpl->GetLogger(name);
    }

    std::shared_ptr<Logger> LoggerManager::CreateLogger(const std::string& name, const LoggerConfig& config) {
        return pImpl->CreateLogger(name, config);
    }

    void LoggerManager::SetGlobalLevel(LogLevel level) {
        pImpl->SetGlobalLevel(level);
    }

    void LoggerManager::FlushAll() {
        pImpl->FlushAll();
    }

    void LoggerManager::Shutdown() {
        pImpl->CloseAll();
    }

    // FileAppender
    FileAppender::FileAppender(const LoggerConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    FileAppender::~FileAppender() = default;

    void FileAppender::Write(const LogEntry& entry) {
        pImpl->Write(entry);
    }

    void FileAppender::Flush() {
        pImpl->Flush();
    }

    void FileAppender::Close() {
        pImpl->Close();
    }

    void FileAppender::Rotate() {
        pImpl->Rotate();
    }

    // ConsoleAppender
    ConsoleAppender::ConsoleAppender(const LoggerConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    ConsoleAppender::~ConsoleAppender() = default;

    void ConsoleAppender::Write(const LogEntry& entry) {
        pImpl->Write(entry);
    }

    void ConsoleAppender::Flush() {
        pImpl->Flush();
    }

    void ConsoleAppender::Close() {
        pImpl->Close();
    }

    void ConsoleAppender::SetColorEnabled(bool enabled) {
        pImpl->color_enabled = enabled;
    }

    // EventLogAppender
    EventLogAppender::EventLogAppender(const LoggerConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    EventLogAppender::~EventLogAppender() = default;

    void EventLogAppender::Write(const LogEntry& entry) {
        pImpl->Write(entry);
    }

    void EventLogAppender::Flush() {
        pImpl->Flush();
    }

    void EventLogAppender::Close() {
        pImpl->Close();
    }

    // ============================================================================
    // LogFormatters
    // ============================================================================

    std::string LogFormatters::SimpleFormat(const LogEntry& entry) {
        return "[" + Utils::LogLevelToString(entry.level) + "] " + entry.message;
    }

    std::string LogFormatters::DetailedFormat(const LogEntry& entry) {
        std::ostringstream oss;
        oss << "[" << Utils::FormatTimestamp(entry.timestamp) << "] "
            << "[" << Utils::LogLevelToString(entry.level) << "] "
            << "[" << entry.thread_id << "] ";

        if (!entry.function_name.empty()) {
            oss << "[" << entry.function_name << "] ";
        }

        oss << entry.message;

        return oss.str();
    }

    std::string LogFormatters::JsonFormat(const LogEntry& entry) {
        std::ostringstream oss;
        oss << "{"
            << "\"timestamp\":\"" << Utils::FormatTimestamp(entry.timestamp) << "\","
            << "\"level\":\"" << Utils::LogLevelToString(entry.level) << "\","
            << "\"logger\":\"" << entry.logger_name << "\","
            << "\"thread\":\"" << entry.thread_id << "\","
            << "\"message\":\"" << entry.message << "\"";

        if (!entry.function_name.empty()) {
            oss << ",\"function\":\"" << entry.function_name << "\"";
        }

        if (!entry.context_data.empty()) {
            oss << ",\"context\":{";
            bool first = true;
            for (const auto& [key, value] : entry.context_data) {
                if (!first) oss << ",";
                oss << "\"" << key << "\":\"" << value << "\"";
                first = false;
            }
            oss << "}";
        }

        oss << "}";
        return oss.str();
    }

    std::string LogFormatters::XmlFormat(const LogEntry& entry) {
        std::ostringstream oss;
        oss << "<log>"
            << "<timestamp>" << Utils::FormatTimestamp(entry.timestamp) << "</timestamp>"
            << "<level>" << Utils::LogLevelToString(entry.level) << "</level>"
            << "<logger>" << entry.logger_name << "</logger>"
            << "<thread>" << entry.thread_id << "</thread>"
            << "<message>" << entry.message << "</message>";

        if (!entry.function_name.empty()) {
            oss << "<function>" << entry.function_name << "</function>";
        }

        oss << "</log>";
        return oss.str();
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string LogLevelToString(LogLevel level) {
            switch (level) {
                case LogLevel::TRACE: return "TRACE";
                case LogLevel::DEBUG: return "DEBUG";
                case LogLevel::INFO: return "INFO";
                case LogLevel::WARNING: return "WARNING";
                case LogLevel::ERROR: return "ERROR";
                case LogLevel::CRITICAL: return "CRITICAL";
                case LogLevel::FATAL: return "FATAL";
                default: return "UNKNOWN";
            }
        }

        LogLevel StringToLogLevel(const std::string& level_str) {
            if (level_str == "TRACE") return LogLevel::TRACE;
            if (level_str == "DEBUG") return LogLevel::DEBUG;
            if (level_str == "INFO") return LogLevel::INFO;
            if (level_str == "WARNING") return LogLevel::WARNING;
            if (level_str == "ERROR") return LogLevel::ERROR;
            if (level_str == "CRITICAL") return LogLevel::CRITICAL;
            if (level_str == "FATAL") return LogLevel::FATAL;
            return LogLevel::INFO;
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()) % 1000;

            std::tm* tm = std::localtime(&time_t);
            std::ostringstream oss;
            oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
            oss << "." << std::setfill('0') << std::setw(3) << ms.count();

            return oss.str();
        }

        std::string GetCurrentDateString() {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            std::tm* tm = std::localtime(&time_t);

            std::ostringstream oss;
            oss << std::put_time(tm, "%Y%m%d");
            return oss.str();
        }

        std::string GetThreadId() {
            std::ostringstream oss;
            oss << std::this_thread::get_id();
            return oss.str();
        }

        std::string GetProcessId() {
#ifdef _WIN32
            return std::to_string(GetCurrentProcessId());
#else
            return std::to_string(getpid());
#endif
        }

        std::string ExpandLogFileName(const std::string& pattern, const std::string& logger_name) {
            std::string result = pattern;

            // Замена переменных
            std::regex name_regex(R"(\{name\})");
            result = std::regex_replace(result, name_regex, logger_name);

            std::regex date_regex(R"(\{date\})");
            result = std::regex_replace(result, date_regex, GetCurrentDateString());

            std::regex pid_regex(R"(\{pid\})");
            result = std::regex_replace(result, pid_regex, GetProcessId());

            return result;
        }

        bool CreateDirectoryIfNotExists(const std::filesystem::path& path) {
            try {
                return std::filesystem::create_directories(path);
            } catch (const std::exception& e) {
                return false;
            }
        }

        std::vector<std::filesystem::path> FindLogFiles(const std::filesystem::path& directory,
                                                       const std::string& pattern) {
            std::vector<std::filesystem::path> files;

            try {
                for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                    if (entry.is_regular_file()) {
                        std::string filename = entry.path().filename().string();
                        if (filename.find(pattern) != std::string::npos) {
                            files.push_back(entry.path());
                        }
                    }
                }
            } catch (const std::exception& e) {
                // Ошибка чтения директории
            }

            return files;
        }

#ifdef _WIN32
        WORD LogLevelToEventType(LogLevel level) {
            switch (level) {
                case LogLevel::ERROR:
                case LogLevel::CRITICAL:
                case LogLevel::FATAL:
                    return EVENTLOG_ERROR_TYPE;
                case LogLevel::WARNING:
                    return EVENTLOG_WARNING_TYPE;
                default:
                    return EVENTLOG_INFORMATION_TYPE;
            }
        }

        DWORD LogLevelToEventId(LogLevel level) {
            return static_cast<DWORD>(level) + 1000;
        }

        void SetConsoleColor(LogLevel level) {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // Белый по умолчанию

            switch (level) {
                case LogLevel::ERROR:
                case LogLevel::CRITICAL:
                case LogLevel::FATAL:
                    color = FOREGROUND_RED | FOREGROUND_INTENSITY;
                    break;
                case LogLevel::WARNING:
                    color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                    break;
                case LogLevel::INFO:
                    color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                    break;
                case LogLevel::DEBUG:
                    color = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                    break;
                default:
                    break;
            }

            SetConsoleTextAttribute(hConsole, color);
        }

        void ResetConsoleColor() {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
#else
        void SetConsoleColor(LogLevel level) {
            switch (level) {
                case LogLevel::ERROR:
                case LogLevel::CRITICAL:
                case LogLevel::FATAL:
                    std::cout << "\033[31m"; // Красный
                    break;
                case LogLevel::WARNING:
                    std::cout << "\033[33m"; // Желтый
                    break;
                case LogLevel::INFO:
                    std::cout << "\033[32m"; // Зеленый
                    break;
                case LogLevel::DEBUG:
                    std::cout << "\033[36m"; // Голубой
                    break;
                default:
                    break;
            }
        }

        void ResetConsoleColor() {
            std::cout << "\033[0m";
        }
#endif
    }

    // Инициализация глобального логгера при загрузке модуля
    static struct GlobalLoggerInitializer {
        GlobalLoggerInitializer() {
            LoggerConfig config;
            config.name = "Global";
            config.destinations = static_cast<int>(LogDestination::CONSOLE) |
                                 static_cast<int>(LogDestination::FILE);

            g_default_logger = std::make_shared<Logger>(config);
        }
    } g_initializer;
}