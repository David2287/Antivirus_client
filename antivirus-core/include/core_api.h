//
// Created by WhySkyDie on 21.07.2025.
//

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <thread>

#ifdef _WIN32
    #ifdef CORE_API_EXPORTS
        #define CORE_API __declspec(dllexport)
    #else
        #define CORE_API __declspec(dllimport)
    #endif
#else
    #define CORE_API
#endif

extern "C" {

// Базовые типы данных
struct ApiResult {
    bool success;
    int error_code;
    char* message;
    char* data;
};

struct ConfigData {
    char* app_name;
    char* version;
    char* log_level;
    bool auto_start;
    int port;
};

// Callback типы
typedef void(*LogCallback)(int level, const char* message);
typedef void(*StatusCallback)(const char* status, const char* details);
typedef void(*DataCallback)(const char* event_type, const char* data);

// Основные API функции
CORE_API bool initialize_core(const ConfigData* config);
CORE_API void shutdown_core();
CORE_API bool is_core_running();

// Конфигурация
CORE_API ApiResult* get_config();
CORE_API ApiResult* set_config(const ConfigData* config);
CORE_API ApiResult* save_config();
CORE_API ApiResult* load_config();

// Логирование
CORE_API void set_log_callback(LogCallback callback);
CORE_API ApiResult* get_logs(int count, int level);
CORE_API void clear_logs();

// Статус и мониторинг
CORE_API void set_status_callback(StatusCallback callback);
CORE_API ApiResult* get_system_status();
CORE_API ApiResult* get_performance_metrics();

// События и данные
CORE_API void set_data_callback(DataCallback callback);
CORE_API ApiResult* send_command(const char* command, const char* parameters);
CORE_API ApiResult* query_data(const char* query_type, const char* filters);

// Служебные функции
CORE_API void free_api_result(ApiResult* result);
CORE_API const char* get_version();
CORE_API const char* get_build_info();

// Windows Service специфичные функции
#ifdef _WIN32
CORE_API bool install_service();
CORE_API bool uninstall_service();
CORE_API bool start_service();
CORE_API bool stop_service();
CORE_API ApiResult* get_service_status();
#endif

} // extern "C"

// C++ интерфейс для более удобного использования
namespace CoreAPI {

    enum class LogLevel {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        FATAL = 5
    };

    enum class SystemStatus {
        STOPPED = 0,
        STARTING = 1,
        RUNNING = 2,
        STOPPING = 3,
        ERROR_STATE = 4
    };

    struct Config {
        std::string app_name;
        std::string version;
        std::string log_level;
        bool auto_start;
        int port;

        Config() : auto_start(false), port(8080) {}
    };

    struct PerformanceMetrics {
        double cpu_usage;
        size_t memory_usage;
        size_t uptime_seconds;
        int active_connections;
    };

    class CoreInterface {
    public:
        CoreInterface();
        ~CoreInterface();

        // Основные операции
        bool Initialize(const Config& config);
        void Shutdown();
        bool IsRunning() const;

        // Конфигурация
        bool GetConfig(Config& config);
        bool SetConfig(const Config& config);
        bool SaveConfig();
        bool LoadConfig();

        // Callbacks
        void SetLogCallback(std::function<void(LogLevel, const std::string&)> callback);
        void SetStatusCallback(std::function<void(const std::string&, const std::string&)> callback);
        void SetDataCallback(std::function<void(const std::string&, const std::string&)> callback);

        // Операции
        std::string SendCommand(const std::string& command, const std::string& parameters = "");
        std::string QueryData(const std::string& query_type, const std::string& filters = "");

        // Статус
        SystemStatus GetSystemStatus();
        bool GetPerformanceMetrics(PerformanceMetrics& metrics);

        // Служебные
        std::string GetVersion() const;
        std::string GetBuildInfo() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };
}