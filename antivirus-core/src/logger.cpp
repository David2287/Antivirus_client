//
// Created by WhySkyDie on 21.07.2025.
//


#include "logger.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <random>
#include <ctime>
#include <json/json.h>

#ifdef _WIN32
    #include <windows.h>
    #include <evntprov.h>
    #include <process.h>
#else
    #include <unistd.h>
    #include <pthread.h>
    #include <syslog.h>
#endif

#include <curl/curl.h> // Для отправки логов на сервер

namespace LoggingSystem {

    // Реализация Logger::Impl
    class Logger::Impl {
    public:
        LoggerConfig config;
        std::atomic<bool> initialized{false};
        std::atomic<bool> shutdown_requested{false};

        // Буферизация и асинхронность
        std::queue<LogEntry> log_queue;
        std::mutex queue_mutex;
        std::condition_variable queue_cv;
        std::vector<std::thread> worker_threads;

        // Статистика
        mutable std::mutex stats_mutex;
        LogStatistics statistics;

        // Callbacks
        LogCallback log_callback;
        ErrorCallback error_callback;
        FlushCallback flush_callback;

        // Назначения
        std::vector<std::shared_ptr<LogDestinationInterface>> custom_destinations;
        std::shared_ptr<LogFormatterInterface> custom_formatter;

        // Контекст
        thread_local std::string thread_session_id;
        thread_local std::string thread_user_id;
        thread_local std::string thread_correlation_id;
        thread_local std::string thread_component;
        thread_local std::string thread_name;

        // Буфер для быстрого доступа к логам
        mutable std::mutex buffer_mutex;
        std::vector<LogEntry> recent_logs_buffer;
        std::size_t buffer_index = 0;

        // Файловые дескрипторы
        std::unordered_map<LogDestination, std::unique_ptr<std::ofstream>> file_streams;
        std::unordered_map<LogDestination, std::filesystem::path> current_files;

        Impl() {
            statistics.start_time = std::chrono::system_clock::now();
            recent_logs_buffer.resize(1000); // Кольцевой буфер на 1000 записей
        }

        ~Impl() {
            Shutdown();
        }

        bool InitializeImpl() {
            if (initialized.load()) {
                return true;
            }

            try {
                // Создание директорий
                if (!Utils::CreateDirectories(config.log_directory)) {
                    if (error_callback) {
                        error_callback("Failed to create log directory: " + config.log_directory.string());
                    }
                    return false;
                }

                // Инициализация назначений
                for (auto destination : config.destinations) {
                    if (!InitializeDestination(destination)) {
                        if (error_callback) {
                            error_callback("Failed to initialize destination: " +
                                         Utils::LogDestinationToString(destination));
                        }
                    }
                }

                // Запуск рабочих потоков для асинхронного режима
                if (config.async_logging) {
                    StartWorkerThreads();
                }

                initialized = true;
                return true;

            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Logger initialization failed: " + std::string(e.what()));
                }
                return false;
            }
        }

        void Shutdown() {
            if (!initialized.load()) {
                return;
            }

            shutdown_requested = true;

            // Сигнал всем рабочим потокам о завершении
            queue_cv.notify_all();

            // Ожидание завершения потоков
            for (auto& thread : worker_threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            worker_threads.clear();

            // Финальный flush
            FlushAll();

            // Закрытие файлов
            for (auto& stream_pair : file_streams) {
                if (stream_pair.second && stream_pair.second->is_open()) {
                    stream_pair.second->close();
                }
            }
            file_streams.clear();

            // Shutdown пользовательских назначений
            for (auto& destination : custom_destinations) {
                destination->Shutdown();
            }

            initialized = false;
        }

        bool InitializeDestination(LogDestination destination) {
            switch (destination) {
                case LogDestination::FILE:
                case LogDestination::ROTATING_FILE:
                    return InitializeFileDestination(destination);

                case LogDestination::CONSOLE:
                    return true; // Консоль не требует инициализации

                case LogDestination::SYSLOG:
#ifndef _WIN32
                    openlog(config.name.c_str(), LOG_CONS | LOG_PID, LOG_USER);
                    return true;
#else
                    return false; // Syslog не поддерживается на Windows
#endif

                case LogDestination::EVENT_LOG:
#ifdef _WIN32
                    return InitializeEventLogDestination();
#else
                    return false; // Event Log только на Windows
#endif

                default:
                    return true;
            }
        }

        bool InitializeFileDestination(LogDestination destination) {
            try {
                std::string filename = GenerateFileName();
                std::filesystem::path file_path = config.log_directory / filename;

                auto file_stream = std::make_unique<std::ofstream>(file_path, std::ios::app);
                if (!file_stream->is_open()) {
                    return false;
                }

                file_streams[destination] = std::move(file_stream);
                current_files[destination] = file_path;

                return true;

            } catch (const std::exception&) {
                return false;
            }
        }

#ifdef _WIN32
        bool InitializeEventLogDestination() {
            // Инициализация Windows Event Log
            // Для полной реализации потребуется регистрация источника событий
            return true;
        }
#endif

        void StartWorkerThreads() {
            for (int i = 0; i < config.worker_threads; ++i) {
                worker_threads.emplace_back([this]() {
                    WorkerThreadLoop();
                });
            }
        }

        void WorkerThreadLoop() {
            while (!shutdown_requested.load()) {
                std::unique_lock<std::mutex> lock(queue_mutex);

                // Ожидание логов или сигнала завершения
                queue_cv.wait(lock, [this]() {
                    return !log_queue.empty() || shutdown_requested.load();
                });

                // Обработка всех доступных логов
                while (!log_queue.empty()) {
                    LogEntry entry = log_queue.front();
                    log_queue.pop();
                    lock.unlock();

                    ProcessLogEntry(entry);

                    lock.lock();
                }
            }

            // Обработка оставшихся логов при завершении
            std::lock_guard<std::mutex> lock(queue_mutex);
            while (!log_queue.empty()) {
                ProcessLogEntry(log_queue.front());
                log_queue.pop();
            }
        }

        void ProcessLogEntry(const LogEntry& entry) {
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                // Форматирование сообщения
                std::string formatted_message = FormatLogEntry(entry);

                // Отправка во все назначения
                for (auto destination : config.destinations) {
                    WriteToDestination(destination, entry, formatted_message);
                }

                // Пользовательские назначения
                for (auto& custom_dest : custom_destinations) {
                    try {
                        custom_dest->WriteLog(entry, formatted_message);
                    } catch (const std::exception& e) {
                        if (error_callback) {
                            error_callback("Custom destination error: " + std::string(e.what()));
                        }
                    }
                }

                // Сохранение в буфер
                SaveToBuffer(entry);

                // Callback
                if (log_callback) {
                    log_callback(entry);
                }

                // Обновление статистики
                UpdateStatistics(entry, start_time);

            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Error processing log entry: " + std::string(e.what()));
                }

                std::lock_guard<std::mutex> lock(stats_mutex);
                statistics.dropped_messages++;
            }
        }

        std::string FormatLogEntry(const LogEntry& entry) {
            if (custom_formatter) {
                return custom_formatter->Format(entry);
            }

            switch (config.format) {
                case LogFormat::JSON:
                    return FormatAsJson(entry);
                case LogFormat::XML:
                    return FormatAsXml(entry);
                case LogFormat::CSV:
                    return FormatAsCsv(entry);
                case LogFormat::STRUCTURED:
                    return FormatAsStructured(entry);
                default:
                    return FormatAsPlainText(entry);
            }
        }

        std::string FormatAsJson(const LogEntry& entry) {
            Json::Value root;

            root["timestamp"] = Utils::FormatTimestamp(entry.timestamp);
            root["level"] = Utils::LogLevelToString(entry.level);
            root["category"] = Utils::LogCategoryToString(entry.category);
            root["priority"] = Utils::LogPriorityToString(entry.priority);
            root["logger"] = entry.logger_name;
            root["message"] = entry.message;
            root["thread_id"] = entry.thread_id;
            root["process_id"] = entry.process_id;
            root["module"] = entry.module_name;
            root["function"] = entry.function_name;
            root["file"] = entry.file_name;
            root["line"] = entry.line_number;

            if (!entry.session_id.empty()) root["session_id"] = entry.session_id;
            if (!entry.user_id.empty()) root["user_id"] = entry.user_id;
            if (!entry.correlation_id.empty()) root["correlation_id"] = entry.correlation_id;
            if (!entry.component.empty()) root["component"] = entry.component;
            if (!entry.operation.empty()) root["operation"] = entry.operation;
            if (!entry.error_code.empty()) root["error_code"] = entry.error_code;

            if (!entry.fields.empty()) {
                Json::Value fields;
                for (const auto& field : entry.fields) {
                    fields[field.first] = field.second;
                }
                root["fields"] = fields;
            }

            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";
            return Json::writeString(builder, root);
        }

        std::string FormatAsStructured(const LogEntry& entry) {
            std::ostringstream oss;

            oss << "[" << Utils::FormatTimestamp(entry.timestamp) << "] "
                << "[" << Utils::LogLevelToString(entry.level) << "] "
                << "[" << Utils::LogCategoryToString(entry.category) << "] "
                << "[" << entry.thread_id << "] ";

            if (!entry.component.empty()) {
                oss << "[" << entry.component << "] ";
            }

            oss << entry.message;

            if (!entry.fields.empty()) {
                oss << " {";
                bool first = true;
                for (const auto& field : entry.fields) {
                    if (!first) oss << ", ";
                    oss << field.first << "=" << field.second;
                    first = false;
                }
                oss << "}";
            }

            if (!entry.file_name.empty() && entry.line_number > 0) {
                oss << " (" << std::filesystem::path(entry.file_name).filename().string()
                    << ":" << entry.line_number << ")";
            }

            return oss.str();
        }

        std::string FormatAsPlainText(const LogEntry& entry) {
            std::ostringstream oss;

            oss << Utils::FormatTimestamp(entry.timestamp) << " "
                << Utils::LogLevelToString(entry.level) << " "
                << entry.message;

            return oss.str();
        }

        std::string FormatAsCsv(const LogEntry& entry) {
            std::ostringstream oss;

            oss << "\"" << Utils::FormatTimestamp(entry.timestamp) << "\","
                << "\"" << Utils::LogLevelToString(entry.level) << "\","
                << "\"" << Utils::LogCategoryToString(entry.category) << "\","
                << "\"" << entry.logger_name << "\","
                << "\"" << Utils::EscapeJsonString(entry.message) << "\","
                << "\"" << entry.thread_id << "\","
                << "\"" << entry.process_id << "\","
                << "\"" << entry.module_name << "\","
                << "\"" << entry.function_name << "\","
                << "\"" << entry.file_name << "\","
                << entry.line_number;

            return oss.str();
        }

        std::string FormatAsXml(const LogEntry& entry) {
            std::ostringstream oss;

            oss << "<log>"
                << "<timestamp>" << Utils::FormatTimestamp(entry.timestamp) << "</timestamp>"
                << "<level>" << Utils::LogLevelToString(entry.level) << "</level>"
                << "<category>" << Utils::LogCategoryToString(entry.category) << "</category>"
                << "<logger>" << Utils::EscapeXmlString(entry.logger_name) << "</logger>"
                << "<message>" << Utils::EscapeXmlString(entry.message) << "</message>"
                << "<thread_id>" << entry.thread_id << "</thread_id>"
                << "<process_id>" << entry.process_id << "</process_id>";

            if (!entry.fields.empty()) {
                oss << "<fields>";
                for (const auto& field : entry.fields) {
                    oss << "<" << field.first << ">" << Utils::EscapeXmlString(field.second)
                        << "</" << field.first << ">";
                }
                oss << "</fields>";
            }

            oss << "</log>";

            return oss.str();
        }

        void WriteToDestination(LogDestination destination, const LogEntry& entry,
                               const std::string& formatted_message) {
            try {
                switch (destination) {
                    case LogDestination::CONSOLE:
                        WriteToConsole(entry, formatted_message);
                        break;

                    case LogDestination::FILE:
                    case LogDestination::ROTATING_FILE:
                        WriteToFile(destination, entry, formatted_message);
                        break;

                    case LogDestination::NETWORK:
                        WriteToNetwork(entry, formatted_message);
                        break;

                    case LogDestination::SYSLOG:
                        WriteToSyslog(entry, formatted_message);
                        break;

                    case LogDestination::EVENT_LOG:
                        WriteToEventLog(entry, formatted_message);
                        break;

                    default:
                        break;
                }
            } catch (const std::exception& e) {
                if (error_callback) {
                    error_callback("Error writing to destination: " + std::string(e.what()));
                }
            }
        }

        void WriteToConsole(const LogEntry& entry, const std::string& formatted_message) {
            // Цветной вывод в зависимости от уровня
            const char* color_code = "";
            const char* reset_code = "\033[0m";

            switch (entry.level) {
                case LogLevel::ERROR:
                case LogLevel::FATAL:
                    color_code = "\033[1;31m"; // Красный
                    break;
                case LogLevel::WARNING:
                    color_code = "\033[1;33m"; // Желтый
                    break;
                case LogLevel::INFO:
                    color_code = "\033[1;32m"; // Зеленый
                    break;
                case LogLevel::DEBUG:
                    color_code = "\033[1;34m"; // Синий
                    break;
                default:
                    reset_code = "";
                    break;
            }

            if (entry.level >= LogLevel::ERROR) {
                std::cerr << color_code << formatted_message << reset_code << std::endl;
            } else {
                std::cout << color_code << formatted_message << reset_code << std::endl;
            }
        }

        void WriteToFile(LogDestination destination, const LogEntry& entry,
                        const std::string& formatted_message) {
            auto it = file_streams.find(destination);
            if (it == file_streams.end() || !it->second->is_open()) {
                if (!InitializeFileDestination(destination)) {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    statistics.disk_write_failures++;
                    return;
                }
                it = file_streams.find(destination);
            }

            auto& stream = *it->second;
            stream << formatted_message << std::endl;

            if (config.auto_flush) {
                stream.flush();
            }

            // Проверка ротации файлов
            if (destination == LogDestination::ROTATING_FILE) {
                CheckFileRotation(destination);
            }

            // Обновление статистики
            std::lock_guard<std::mutex> lock(stats_mutex);
            statistics.total_bytes_written += formatted_message.length() + 1; // +1 for newline
        }

        void WriteToNetwork(const LogEntry& entry, const std::string& formatted_message) {
            if (config.server_url.empty()) {
                return;
            }

            // Отправка в отдельном потоке для неблокирующего выполнения
            std::thread([this, formatted_message]() {
                try {
                    SendLogToServer(formatted_message);
                } catch (const std::exception& e) {
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    statistics.network_failures++;

                    if (error_callback) {
                        error_callback("Network log send failed: " + std::string(e.what()));
                    }
                }
            }).detach();
        }

        void WriteToSyslog(const LogEntry& entry, const std::string& formatted_message) {
#ifndef _WIN32
            int priority = LOG_INFO;

            switch (entry.level) {
                case LogLevel::FATAL:
                    priority = LOG_CRIT;
                    break;
                case LogLevel::ERROR:
                    priority = LOG_ERR;
                    break;
                case LogLevel::WARNING:
                    priority = LOG_WARNING;
                    break;
                case LogLevel::INFO:
                    priority = LOG_INFO;
                    break;
                case LogLevel::DEBUG:
                case LogLevel::TRACE:
                    priority = LOG_DEBUG;
                    break;
                default:
                    break;
            }

            syslog(priority, "%s", formatted_message.c_str());
#endif
        }

        void WriteToEventLog(const LogEntry& entry, const std::string& formatted_message) {
#ifdef _WIN32
            WORD event_type = EVENTLOG_INFORMATION_TYPE;

            switch (entry.level) {
                case LogLevel::FATAL:
                case LogLevel::ERROR:
                    event_type = EVENTLOG_ERROR_TYPE;
                    break;
                case LogLevel::WARNING:
                    event_type = EVENTLOG_WARNING_TYPE;
                    break;
                default:
                    break;
            }

            HANDLE h_event_log = RegisterEventSourceA(nullptr, config.name.c_str());
            if (h_event_log) {
                const char* messages[] = {formatted_message.c_str()};
                ReportEventA(h_event_log, event_type, 0, 0, nullptr, 1, 0, messages, nullptr);
                DeregisterEventSource(h_event_log);
            }
#endif
        }

        void SendLogToServer(const std::string& log_data) {
            CURL* curl = curl_easy_init();
            if (!curl) {
                throw std::runtime_error("Failed to initialize CURL");
            }

            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            if (!config.api_key.empty()) {
                std::string auth_header = "Authorization: Bearer " + config.api_key;
                headers = curl_slist_append(headers, auth_header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_URL, config.server_url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, log_data.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.connection_timeout_ms / 1000);

            CURLcode res = curl_easy_perform(curl);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK) {
                throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
            }
        }

        void CheckFileRotation(LogDestination destination) {
            auto it = current_files.find(destination);
            if (it == current_files.end()) {
                return;
            }

            try {
                std::uintmax_t file_size = std::filesystem::file_size(it->second);
                if (file_size >= config.max_file_size) {
                    RotateFile(destination);
                }
            } catch (const std::exception&) {
                // Игнорируем ошибки получения размера файла
            }
        }

        void RotateFile(LogDestination destination) {
            // Закрываем текущий файл
            auto stream_it = file_streams.find(destination);
            if (stream_it != file_streams.end()) {
                stream_it->second->close();
            }

            // Переименовываем старые файлы
            auto file_it = current_files.find(destination);
            if (file_it != current_files.end()) {
                std::filesystem::path base_path = file_it->second;

                // Удаляем самый старый файл если достигнут лимит
                std::filesystem::path oldest_file = base_path;
                oldest_file += "." + std::to_string(config.max_files - 1);
                if (std::filesystem::exists(oldest_file)) {
                    std::filesystem::remove(oldest_file);
                }

                // Переименовываем файлы
                for (int i = config.max_files - 2; i >= 0; --i) {
                    std::filesystem::path old_file = base_path;
                    std::filesystem::path new_file = base_path;

                    if (i == 0) {
                        old_file = base_path;
                    } else {
                        old_file += "." + std::to_string(i);
                    }

                    new_file += "." + std::to_string(i + 1);

                    if (std::filesystem::exists(old_file)) {
                        std::filesystem::rename(old_file, new_file);
                    }
                }
            }

            // Создаем новый файл
            InitializeFileDestination(destination);
        }

        void SaveToBuffer(const LogEntry& entry) {
            std::lock_guard<std::mutex> lock(buffer_mutex);
            recent_logs_buffer[buffer_index] = entry;
            buffer_index = (buffer_index + 1) % recent_logs_buffer.size();
        }

        void UpdateStatistics(const LogEntry& entry,
                             const std::chrono::high_resolution_clock::time_point& start_time) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto processing_time = std::chrono::duration<double, std::milli>(end_time - start_time).count();

            std::lock_guard<std::mutex> lock(stats_mutex);

            statistics.total_messages++;
            statistics.messages_by_level[static_cast<int>(entry.level)]++;
            statistics.last_message_time = entry.timestamp;
            statistics.category_counts[entry.category]++;

            if (!entry.module_name.empty()) {
                statistics.module_counts[entry.module_name]++;
            }

            // Обновление среднего времени обработки
            double total_processing_time = statistics.average_processing_time_ms *
                                         (statistics.total_messages - 1) + processing_time;
            statistics.average_processing_time_ms = total_processing_time / statistics.total_messages;
        }

        std::string GenerateFileName() {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto tm = *std::localtime(&time_t);

            std::string pattern = config.file_name_pattern;

            // Замена паттернов на реальные значения
            std::ostringstream oss;
            for (std::size_t i = 0; i < pattern.length(); ++i) {
                if (pattern[i] == '%' && i + 1 < pattern.length()) {
                    char format_char = pattern[i + 1];
                    switch (format_char) {
                        case 'Y':
                            oss << std::setfill('0') << std::setw(4) << (tm.tm_year + 1900);
                            break;
                        case 'm':
                            oss << std::setfill('0') << std::setw(2) << (tm.tm_mon + 1);
                            break;
                        case 'd':
                            oss << std::setfill('0') << std::setw(2) << tm.tm_mday;
                            break;
                        case 'H':
                            oss << std::setfill('0') << std::setw(2) << tm.tm_hour;
                            break;
                        case 'M':
                            oss << std::setfill('0') << std::setw(2) << tm.tm_min;
                            break;
                        case 'S':
                            oss << std::setfill('0') << std::setw(2) << tm.tm_sec;
                            break;
                        default:
                            oss << '%' << format_char;
                            break;
                    }
                    ++i; // Пропускаем символ форматирования
                } else {
                    oss << pattern[i];
                }
            }

            return oss.str();
        }

        void FlushAll() {
            for (auto& stream_pair : file_streams) {
                if (stream_pair.second && stream_pair.second->is_open()) {
                    stream_pair.second->flush();
                }
            }

            for (auto& destination : custom_destinations) {
                destination->Flush();
            }

            if (flush_callback) {
                flush_callback();
            }
        }

        bool ShouldLog(const LogEntry& entry) {
            // Проверка уровня
            if (entry.level < config.min_level || entry.level > config.max_level) {
                return false;
            }

            // Проверка категории
            if (!config.enabled_categories.empty()) {
                auto it = std::find(config.enabled_categories.begin(),
                                  config.enabled_categories.end(), entry.category);
                if (it == config.enabled_categories.end()) {
                    return false;
                }
            }

            // Проверка исключенных модулей
            if (!config.excluded_modules.empty() && !entry.module_name.empty()) {
                auto it = std::find(config.excluded_modules.begin(),
                                  config.excluded_modules.end(), entry.module_name);
                if (it != config.excluded_modules.end()) {
                    return false;
                }
            }

            // Проверка включенных компонентов
            if (!config.included_components.empty() && !entry.component.empty()) {
                auto it = std::find(config.included_components.begin(),
                                  config.included_components.end(), entry.component);
                if (it == config.included_components.end()) {
                    return false;
                }
            }

            return true;
        }
    };

    // Реализация LoggerManager::Impl
    class LoggerManager::Impl {
    public:
        std::unordered_map<std::string, std::shared_ptr<Logger>> loggers;
        mutable std::mutex loggers_mutex;
        LoggerConfig global_config;

        std::shared_ptr<Logger> GetOrCreateLogger(const std::string& name) {
            std::lock_guard<std::mutex> lock(loggers_mutex);

            auto it = loggers.find(name);
            if (it != loggers.end()) {
                return it->second;
            }

            auto logger = std::make_shared<Logger>(name);
            logger->SetConfig(global_config);
            logger->Initialize();

            loggers[name] = logger;
            return logger;
        }
    };

    // Реализация основных классов

    // Logger
    Logger::Logger() : pImpl(std::make_unique<Impl>()) {
        pImpl->config.name = "default";
    }

    Logger::Logger(const std::string& name) : pImpl(std::make_unique<Impl>()) {
        pImpl->config.name = name;
    }

    Logger::Logger(const LoggerConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    Logger::~Logger() = default;

    bool Logger::Initialize() {
        return pImpl->InitializeImpl();
    }

    bool Logger::Initialize(const LoggerConfig& config) {
        pImpl->config = config;
        return pImpl->InitializeImpl();
    }

    void Logger::Shutdown() {
        pImpl->Shutdown();
    }

    bool Logger::IsInitialized() const {
        return pImpl->initialized.load();
    }

    void Logger::Log(LogLevel level, const std::string& message) {
        LogEntry entry;
        entry.level = level;
        entry.message = message;
        entry.logger_name = pImpl->config.name;
        entry.thread_id = Utils::GetCurrentThreadId();
        entry.process_id = Utils::GetCurrentProcessId();
        entry.module_name = Utils::GetModuleName();

        Log(entry);
    }

    void Logger::Log(LogLevel level, LogCategory category, const std::string& message) {
        LogEntry entry;
        entry.level = level;
        entry.category = category;
        entry.message = message;
        entry.logger_name = pImpl->config.name;
        entry.thread_id = Utils::GetCurrentThreadId();
        entry.process_id = Utils::GetCurrentProcessId();
        entry.module_name = Utils::GetModuleName();

        Log(entry);
    }

    void Logger::Log(const LogEntry& entry) {
        if (!pImpl->initialized.load() || !pImpl->ShouldLog(entry)) {
            return;
        }

        LogEntry processed_entry = entry;

        // Дополнение контекстной информации
        if (processed_entry.session_id.empty()) {
            processed_entry.session_id = pImpl->thread_session_id;
        }
        if (processed_entry.user_id.empty()) {
            processed_entry.user_id = pImpl->thread_user_id;
        }
        if (processed_entry.correlation_id.empty()) {
            processed_entry.correlation_id = pImpl->thread_correlation_id;
        }
        if (processed_entry.component.empty()) {
            processed_entry.component = pImpl->thread_component;
        }

        // Санитизация чувствительных данных
        if (pImpl->config.sanitize_sensitive_data) {
            processed_entry.message = Utils::SanitizeSensitiveData(processed_entry.message);
        }

        if (pImpl->config.async_logging) {
            // Асинхронный режим
            std::lock_guard<std::mutex> lock(pImpl->queue_mutex);
            if (pImpl->log_queue.size() < pImpl->config.queue_size) {
                pImpl->log_queue.push(processed_entry);
                pImpl->queue_cv.notify_one();
            } else {
                // Очередь переполнена
                std::lock_guard<std::mutex> stats_lock(pImpl->stats_mutex);
                pImpl->statistics.dropped_messages++;
            }
        } else {
            // Синхронный режим
            pImpl->ProcessLogEntry(processed_entry);
        }
    }

    void Logger::Info(const std::string& message) {
        Log(LogLevel::INFO, message);
    }

    void Logger::Error(const std::string& message) {
        Log(LogLevel::ERROR, message);
    }

    void Logger::Warning(const std::string& message) {
        Log(LogLevel::WARNING, message);
    }

    void Logger::Debug(const std::string& message) {
        Log(LogLevel::DEBUG, message);
    }

    void Logger::Trace(const std::string& message) {
        Log(LogLevel::TRACE, message);
    }

    void Logger::Fatal(const std::string& message) {
        Log(LogLevel::FATAL, message);
    }

    void Logger::LogScanner(LogLevel level, const std::string& message) {
        Log(level, LogCategory::SCANNER, message);
    }

    void Logger::LogQuarantine(LogLevel level, const std::string& message) {
        Log(level, LogCategory::QUARANTINE, message);
    }

    void Logger::LogSignatures(LogLevel level, const std::string& message) {
        Log(level, LogCategory::SIGNATURES, message);
    }

    void Logger::LogNetwork(LogLevel level, const std::string& message) {
        Log(level, LogCategory::NETWORK, message);
    }

    void Logger::LogUI(LogLevel level, const std::string& message) {
        Log(level, LogCategory::UI, message);
    }

    void Logger::LogService(LogLevel level, const std::string& message) {
        Log(level, LogCategory::SERVICE, message);
    }

    void Logger::LogSecurity(LogLevel level, const std::string& message) {
        Log(level, LogCategory::SECURITY, message);
    }

    void Logger::SetSessionId(const std::string& session_id) {
        pImpl->thread_session_id = session_id;
    }

    void Logger::SetUserId(const std::string& user_id) {
        pImpl->thread_user_id = user_id;
    }

    void Logger::SetCorrelationId(const std::string& correlation_id) {
        pImpl->thread_correlation_id = correlation_id;
    }

    void Logger::SetComponent(const std::string& component) {
        pImpl->thread_component = component;
    }

    void Logger::Flush() {
        pImpl->FlushAll();
    }

    LogStatistics Logger::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    std::vector<LogEntry> Logger::GetRecentLogs(std::size_t count) const {
        std::lock_guard<std::mutex> lock(pImpl->buffer_mutex);

        std::vector<LogEntry> result;
        std::size_t available = std::min(count, pImpl->recent_logs_buffer.size());

        for (std::size_t i = 0; i < available; ++i) {
            std::size_t index = (pImpl->buffer_index - available + i) % pImpl->recent_logs_buffer.size();
            const auto& entry = pImpl->recent_logs_buffer[index];
            if (entry.timestamp != std::chrono::system_clock::time_point{}) {
                result.push_back(entry);
            }
        }

        return result;
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
        return pImpl->GetOrCreateLogger(name);
    }

    std::shared_ptr<Logger> LoggerManager::CreateLogger(const std::string& name, const LoggerConfig& config) {
        std::lock_guard<std::mutex> lock(pImpl->loggers_mutex);

        auto logger = std::make_shared<Logger>(config);
        logger->Initialize();

        pImpl->loggers[name] = logger;
        return logger;
    }

    void LoggerManager::FlushAll() {
        std::lock_guard<std::mutex> lock(pImpl->loggers_mutex);
        for (auto& pair : pImpl->loggers) {
            pair.second->Flush();
        }
    }

    void LoggerManager::ShutdownAll() {
        std::lock_guard<std::mutex> lock(pImpl->loggers_mutex);
        for (auto& pair : pImpl->loggers) {
            pair.second->Shutdown();
        }
        pImpl->loggers.clear();
    }

    // Утилитарные функции
    namespace Utils {

        std::string LogLevelToString(LogLevel level) {
            switch (level) {
                case LogLevel::TRACE: return "TRACE";
                case LogLevel::DEBUG: return "DEBUG";
                case LogLevel::INFO: return "INFO";
                case LogLevel::WARNING: return "WARNING";
                case LogLevel::ERROR: return "ERROR";
                case LogLevel::FATAL: return "FATAL";
                case LogLevel::OFF: return "OFF";
                default: return "UNKNOWN";
            }
        }

        LogLevel StringToLogLevel(const std::string& level_str) {
            if (level_str == "TRACE") return LogLevel::TRACE;
            if (level_str == "DEBUG") return LogLevel::DEBUG;
            if (level_str == "INFO") return LogLevel::INFO;
            if (level_str == "WARNING" || level_str == "WARN") return LogLevel::WARNING;
            if (level_str == "ERROR") return LogLevel::ERROR;
            if (level_str == "FATAL") return LogLevel::FATAL;
            if (level_str == "OFF") return LogLevel::OFF;
            return LogLevel::INFO; // default
        }

        std::string LogCategoryToString(LogCategory category) {
            switch (category) {
                case LogCategory::GENERAL: return "GENERAL";
                case LogCategory::SCANNER: return "SCANNER";
                case LogCategory::QUARANTINE: return "QUARANTINE";
                case LogCategory::SIGNATURES: return "SIGNATURES";
                case LogCategory::NETWORK: return "NETWORK";
                case LogCategory::UI: return "UI";
                case LogCategory::SERVICE: return "SERVICE";
                case LogCategory::DATABASE: return "DATABASE";
                case LogCategory::SECURITY: return "SECURITY";
                case LogCategory::PERFORMANCE: return "PERFORMANCE";
                default: return "UNKNOWN";
            }
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()) % 1000;

            std::tm* tm = std::gmtime(&time_t);

            std::ostringstream oss;
            oss << std::put_time(tm, "%Y-%m-%dT%H:%M:%S");
            oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";

            return oss.str();
        }

        std::string SanitizeSensitiveData(const std::string& message) {
            std::string sanitized = message;

            // Маскирование паролей
            std::regex password_regex(R"(password[=:\s]*['\"]?([^'\"\s]+)['\"]?)",
                                    std::regex_constants::icase);
            sanitized = std::regex_replace(sanitized, password_regex, "password=***");

            // Маскирование токенов
            std::regex token_regex(R"(token[=:\s]*['\"]?([^'\"\s]+)['\"]?)",
                                 std::regex_constants::icase);
            sanitized = std::regex_replace(sanitized, token_regex, "token=***");

            // Маскирование ключей
            std::regex key_regex(R"(key[=:\s]*['\"]?([^'\"\s]+)['\"]?)",
                               std::regex_constants::icase);
            sanitized = std::regex_replace(sanitized, key_regex, "key=***");

            return sanitized;
        }

        std::string GenerateCorrelationId() {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::ostringstream oss;
            for (int i = 0; i < 32; ++i) {
                oss << std::hex << dis(gen);
                if (i == 7 || i == 11 || i == 15 || i == 19) {
                    oss << "-";
                }
            }

            return oss.str();
        }

        std::string GetCurrentThreadId() {
            std::ostringstream oss;
            oss << std::this_thread::get_id();
            return oss.str();
        }

        std::string GetCurrentProcessId() {
#ifdef _WIN32
            return std::to_string(GetCurrentProcessId());
#else
            return std::to_string(getpid());
#endif
        }

        std::string GetModuleName() {
#ifdef _WIN32
            char module_name[MAX_PATH];
            GetModuleFileNameA(nullptr, module_name, MAX_PATH);
            return std::filesystem::path(module_name).filename().string();
#else
            return "unknown";
#endif
        }

        bool CreateDirectories(const std::filesystem::path& path) {
            try {
                return std::filesystem::create_directories(path);
            } catch (const std::exception&) {
                return false;
            }
        }

        std::string EscapeJsonString(const std::string& str) {
            std::string escaped;
            escaped.reserve(str.length() * 2);

            for (char c : str) {
                switch (c) {
                    case '"': escaped += "\\\""; break;
                    case '\\': escaped += "\\\\"; break;
                    case '\b': escaped += "\\b"; break;
                    case '\f': escaped += "\\f"; break;
                    case '\n': escaped += "\\n"; break;
                    case '\r': escaped += "\\r"; break;
                    case '\t': escaped += "\\t"; break;
                    default:
                        if (c < 0x20) {
                            escaped += "\\u00";
                            escaped += "0123456789abcdef"[c >> 4];
                            escaped += "0123456789abcdef"[c & 0xf];
                        } else {
                            escaped += c;
                        }
                        break;
                }
            }

            return escaped;
        }

        std::string EscapeXmlString(const std::string& str) {
            std::string escaped;
            escaped.reserve(str.length() * 2);

            for (char c : str) {
                switch (c) {
                    case '<': escaped += "&lt;"; break;
                    case '>': escaped += "&gt;"; break;
                    case '&': escaped += "&amp;"; break;
                    case '"': escaped += "&quot;"; break;
                    case '\'': escaped += "&apos;"; break;
                    default: escaped += c; break;
                }
            }

            return escaped;
        }
    }
}