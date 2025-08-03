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
#include <future>
#include <optional>

namespace TaskRouter {

    // Типы задач
    enum class TaskType {
        SCAN_FILE,
        SCAN_DIRECTORY,
        SCAN_FULL_SYSTEM,
        SCAN_QUICK,
        SCAN_CUSTOM,

        UPDATE_SIGNATURES,
        UPDATE_ENGINE,
        UPDATE_CONFIG,
        UPDATE_ALL,

        LOGIN,
        LOGOUT,
        REGISTER,
        REFRESH_TOKEN,

        QUARANTINE_FILE,
        RESTORE_FILE,
        DELETE_FILE,

        GENERATE_REPORT,
        EXPORT_LOGS,

        SYSTEM_SHUTDOWN,
        SYSTEM_RESTART,
        SYSTEM_STATUS,

        CUSTOM_TASK
    };

    // Приоритет задачи
    enum class TaskPriority {
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        CRITICAL = 4,
        EMERGENCY = 5
    };

    // Статус выполнения задачи
    enum class TaskStatus {
        PENDING,
        QUEUED,
        PROCESSING,
        COMPLETED,
        FAILED,
        CANCELLED,
        TIMEOUT
    };

    // Категория задачи для группировки
    enum class TaskCategory {
        SCAN_OPERATIONS,
        UPDATE_OPERATIONS,
        AUTH_OPERATIONS,
        FILE_OPERATIONS,
        SYSTEM_OPERATIONS,
        REPORTING_OPERATIONS
    };

    // Параметры задачи
    struct TaskParameters {
        std::unordered_map<std::string, std::string> string_params;
        std::unordered_map<std::string, int> int_params;
        std::unordered_map<std::string, bool> bool_params;
        std::unordered_map<std::string, double> double_params;
        std::vector<std::string> file_paths;
        std::vector<std::string> string_list;
        std::string json_data;

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

    // Контекст выполнения задачи
    struct TaskContext {
        std::string user_id;
        std::string session_id;
        std::string client_ip;
        std::string user_agent;
        std::chrono::system_clock::time_point request_time;
        std::unordered_map<std::string, std::string> headers;
        std::string correlation_id;

        TaskContext() {
            request_time = std::chrono::system_clock::now();
        }
    };

    // Результат выполнения задачи
    struct TaskResult {
        bool success = false;
        std::string error_message;
        std::string error_code;
        std::string result_data;
        std::unordered_map<std::string, std::string> result_metadata;
        std::chrono::milliseconds execution_time{0};
        int progress_percentage = 100;

        TaskResult() = default;
    };

    // Задача
    struct Task {
        std::string task_id;
        TaskType type;
        TaskPriority priority;
        TaskCategory category;
        TaskParameters parameters;
        TaskContext context;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point scheduled_at;
        std::chrono::milliseconds timeout{300000}; // 5 минут по умолчанию

        std::atomic<TaskStatus> status{TaskStatus::PENDING};
        std::chrono::system_clock::time_point started_at;
        std::chrono::system_clock::time_point completed_at;

        std::string assigned_worker;
        TaskResult result;

        Task() {
            created_at = std::chrono::system_clock::now();
            scheduled_at = created_at;
        }

        explicit Task(TaskType t, TaskPriority p = TaskPriority::NORMAL)
            : type(t), priority(p) {
            created_at = std::chrono::system_clock::now();
            scheduled_at = created_at;
            category = GetTaskCategory(t);
        }

        bool IsExpired() const {
            auto now = std::chrono::system_clock::now();
            return now > (started_at + timeout);
        }

    private:
        TaskCategory GetTaskCategory(TaskType type) const;
    };

    // Конфигурация роутера
    struct RouterConfig {
        // Пулы потоков
        int scan_worker_threads = 2;
        int update_worker_threads = 1;
        int auth_worker_threads = 2;
        int file_worker_threads = 2;
        int system_worker_threads = 1;
        int reporting_worker_threads = 1;

        // Очереди
        std::size_t max_queue_size = 10000;
        std::size_t priority_queue_size = 1000;

        // Таймауты
        std::chrono::milliseconds default_task_timeout{300000}; // 5 минут
        std::chrono::milliseconds queue_wait_timeout{60000};    // 1 минута

        // Производительность
        bool enable_task_batching = true;
        std::size_t max_batch_size = 10;
        std::chrono::milliseconds batch_timeout{1000};

        // Мониторинг
        bool enable_metrics = true;
        std::chrono::seconds metrics_interval{30};
        bool enable_task_logging = true;

        // Ограничения ресурсов
        std::size_t max_concurrent_scans = 5;
        std::size_t max_concurrent_updates = 1;
        std::size_t max_memory_usage_mb = 2048; // 2GB

        // Retry политика
        int max_retries = 3;
        std::chrono::milliseconds retry_delay{5000};
        bool exponential_backoff = true;
    };

    // Статистика роутера
    struct RouterStatistics {
        std::atomic<std::uint64_t> total_tasks{0};
        std::atomic<std::uint64_t> completed_tasks{0};
        std::atomic<std::uint64_t> failed_tasks{0};
        std::atomic<std::uint64_t> cancelled_tasks{0};
        std::atomic<std::uint64_t> timeout_tasks{0};

        std::unordered_map<TaskType, std::uint64_t> task_type_counts;
        std::unordered_map<TaskCategory, std::uint64_t> category_counts;

        double average_execution_time_ms = 0.0;
        std::size_t current_queue_size = 0;
        std::size_t active_worker_count = 0;

        std::chrono::system_clock::time_point start_time;
        std::chrono::system_clock::time_point last_task_time;

        void Reset() {
            total_tasks = 0;
            completed_tasks = 0;
            failed_tasks = 0;
            cancelled_tasks = 0;
            timeout_tasks = 0;
            task_type_counts.clear();
            category_counts.clear();
            average_execution_time_ms = 0.0;
            start_time = std::chrono::system_clock::now();
        }
    };

    // Forward declarations
    class TaskWorker;
    class TaskQueue;

    // Callback типы
    using TaskHandler = std::function<TaskResult(const Task& task)>;
    using TaskProgressCallback = std::function<void(const std::string& task_id, int percentage, const std::string& status)>;
    using TaskCompletedCallback = std::function<void(const Task& task, const TaskResult& result)>;
    using TaskFailedCallback = std::function<void(const Task& task, const std::string& error)>;
    using TaskTimeoutCallback = std::function<void(const Task& task)>;

    // Основной класс роутера задач
    class TaskRouter {
    public:
        explicit TaskRouter(const RouterConfig& config = RouterConfig{});
        ~TaskRouter();

        // Инициализация и управление
        bool Initialize();
        void Shutdown();
        bool IsRunning() const;

        // Конфигурация
        void SetConfig(const RouterConfig& config);
        const RouterConfig& GetConfig() const;

        // Регистрация обработчиков
        void RegisterTaskHandler(TaskType type, TaskHandler handler);
        void UnregisterTaskHandler(TaskType type);
        void RegisterDefaultHandlers();

        // Регистрация callbacks
        void SetTaskProgressCallback(TaskProgressCallback callback);
        void SetTaskCompletedCallback(TaskCompletedCallback callback);
        void SetTaskFailedCallback(TaskFailedCallback callback);
        void SetTaskTimeoutCallback(TaskTimeoutCallback callback);

        // Отправка задач
        std::string SubmitTask(const Task& task);
        std::string SubmitTask(TaskType type, const TaskParameters& params,
                              TaskPriority priority = TaskPriority::NORMAL);
        std::string SubmitTask(TaskType type, const TaskParameters& params,
                              const TaskContext& context,
                              TaskPriority priority = TaskPriority::NORMAL);

        // Асинхронное выполнение
        std::future<TaskResult> SubmitTaskAsync(const Task& task);
        std::future<TaskResult> SubmitTaskAsync(TaskType type, const TaskParameters& params);

        // Управление задачами
        bool CancelTask(const std::string& task_id);
        bool RescheduleTask(const std::string& task_id, std::chrono::system_clock::time_point new_time);
        std::optional<Task> GetTask(const std::string& task_id) const;
        std::vector<Task> GetTasksByUser(const std::string& user_id) const;
        std::vector<Task> GetTasksByStatus(TaskStatus status) const;

        // Получение результатов
        std::optional<TaskResult> GetTaskResult(const std::string& task_id) const;
        std::vector<std::string> GetPendingTasks() const;
        std::vector<std::string> GetActiveTasks() const;

        // Управление очередями
        void PauseCategory(TaskCategory category);
        void ResumeCategory(TaskCategory category);
        void ClearQueue(TaskCategory category);
        std::size_t GetQueueSize(TaskCategory category) const;

        // Статистика и мониторинг
        RouterStatistics GetStatistics() const;
        void ResetStatistics();
        std::vector<Task> GetRecentTasks(std::size_t count = 100) const;

        // Утилиты
        std::string GenerateTaskId() const;
        TaskCategory GetTaskCategory(TaskType type) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Обработчик задач по умолчанию
    class DefaultTaskHandlers {
    public:
        // Обработчики сканирования
        static TaskResult HandleScanFile(const Task& task);
        static TaskResult HandleScanDirectory(const Task& task);
        static TaskResult HandleScanFullSystem(const Task& task);
        static TaskResult HandleScanQuick(const Task& task);

        // Обработчики обновлений
        static TaskResult HandleUpdateSignatures(const Task& task);
        static TaskResult HandleUpdateEngine(const Task& task);
        static TaskResult HandleUpdateConfig(const Task& task);

        // Обработчики аутентификации
        static TaskResult HandleLogin(const Task& task);
        static TaskResult HandleLogout(const Task& task);
        static TaskResult HandleRegister(const Task& task);
        static TaskResult HandleRefreshToken(const Task& task);

        // Обработчики файловых операций
        static TaskResult HandleQuarantineFile(const Task& task);
        static TaskResult HandleRestoreFile(const Task& task);
        static TaskResult HandleDeleteFile(const Task& task);

        // Обработчики отчетов
        static TaskResult HandleGenerateReport(const Task& task);
        static TaskResult HandleExportLogs(const Task& task);

        // Системные обработчики
        static TaskResult HandleSystemStatus(const Task& task);
        static TaskResult HandleSystemShutdown(const Task& task);
        static TaskResult HandleSystemRestart(const Task& task);

    private:
        static void UpdateProgress(const std::string& task_id, int percentage, const std::string& status);
        static bool ValidateParameters(const Task& task);
    };

    // Утилитарные функции
    namespace Utils {
        // Конвертация типов
        std::string TaskTypeToString(TaskType type);
        TaskType StringToTaskType(const std::string& type_str);

        std::string TaskPriorityToString(TaskPriority priority);
        TaskPriority StringToTaskPriority(const std::string& priority_str);

        std::string TaskStatusToString(TaskStatus status);
        TaskStatus StringToTaskStatus(const std::string& status_str);

        std::string TaskCategoryToString(TaskCategory category);
        TaskCategory StringToTaskCategory(const std::string& category_str);

        // Валидация
        bool ValidateTaskType(TaskType type);
        bool ValidateTaskParameters(TaskType type, const TaskParameters& params);
        bool ValidateTaskContext(const TaskContext& context);

        // Сериализация
        std::string SerializeTask(const Task& task);
        std::optional<Task> DeserializeTask(const std::string& serialized_data);

        std::string SerializeTaskResult(const TaskResult& result);
        std::optional<TaskResult> DeserializeTaskResult(const std::string& serialized_data);

        // Время
        std::string FormatDuration(std::chrono::milliseconds duration);
        std::chrono::milliseconds ParseDuration(const std::string& duration_str);

        // ID генерация
        std::string GenerateUniqueTaskId();
        std::string GenerateCorrelationId();

        // Приоритезация
        bool ShouldTaskTakePriority(const Task& task1, const Task& task2);
        int CalculateTaskScore(const Task& task);

        // Ресурсы
        std::size_t EstimateTaskMemoryUsage(const Task& task);
        std::chrono::milliseconds EstimateTaskDuration(const Task& task);
    }
}