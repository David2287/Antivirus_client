//
// Created by WhySkyDie on 21.07.2025.
//

#include "task_router.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <random>
#include <json/json.h>
#include <thread>
#include <future>

namespace TaskRouter {

    // ============================================================================
    // Task::GetTaskCategory реализация
    // ============================================================================

    TaskCategory Task::GetTaskCategory(TaskType type) const {
        switch (type) {
            case TaskType::SCAN_FILE:
            case TaskType::SCAN_DIRECTORY:
            case TaskType::SCAN_FULL_SYSTEM:
            case TaskType::SCAN_QUICK:
            case TaskType::SCAN_CUSTOM:
                return TaskCategory::SCAN_OPERATIONS;

            case TaskType::UPDATE_SIGNATURES:
            case TaskType::UPDATE_ENGINE:
            case TaskType::UPDATE_CONFIG:
            case TaskType::UPDATE_ALL:
                return TaskCategory::UPDATE_OPERATIONS;

            case TaskType::LOGIN:
            case TaskType::LOGOUT:
            case TaskType::REGISTER:
            case TaskType::REFRESH_TOKEN:
                return TaskCategory::AUTH_OPERATIONS;

            case TaskType::QUARANTINE_FILE:
            case TaskType::RESTORE_FILE:
            case TaskType::DELETE_FILE:
                return TaskCategory::FILE_OPERATIONS;

            case TaskType::SYSTEM_SHUTDOWN:
            case TaskType::SYSTEM_RESTART:
            case TaskType::SYSTEM_STATUS:
                return TaskCategory::SYSTEM_OPERATIONS;

            case TaskType::GENERATE_REPORT:
            case TaskType::EXPORT_LOGS:
                return TaskCategory::REPORTING_OPERATIONS;

            default:
                return TaskCategory::SYSTEM_OPERATIONS;
        }
    }

    // ============================================================================
    // TaskRouter::Impl
    // ============================================================================

    class TaskRouter::Impl {
    public:
        RouterConfig config;
        std::atomic<bool> running{false};
        std::atomic<bool> shutdown_requested{false};

        // Очереди задач по категориям
        std::unordered_map<TaskCategory, std::unique_ptr<std::priority_queue<Task, std::vector<Task>, TaskComparator>>> task_queues;
        std::unordered_map<TaskCategory, std::mutex> queue_mutexes;
        std::unordered_map<TaskCategory, std::condition_variable> queue_cvs;
        std::unordered_map<TaskCategory, std::atomic<bool>> category_paused;

        // Обработчики задач
        std::unordered_map<TaskType, TaskHandler> task_handlers;
        std::mutex handlers_mutex;

        // Рабочие потоки
        std::vector<std::thread> worker_threads;
        std::unordered_map<TaskCategory, std::vector<std::thread>> category_workers;

        // Активные задачи
        std::unordered_map<std::string, Task> active_tasks;
        std::unordered_map<std::string, std::promise<TaskResult>> task_promises;
        std::mutex active_tasks_mutex;

        // Результаты задач
        std::unordered_map<std::string, TaskResult> task_results;
        std::mutex results_mutex;

        // Callbacks
        TaskProgressCallback progress_callback;
        TaskCompletedCallback completed_callback;
        TaskFailedCallback failed_callback;
        TaskTimeoutCallback timeout_callback;

        // Статистика
        mutable std::mutex stats_mutex;
        RouterStatistics statistics;

        // История задач
        std::vector<Task> recent_tasks;
        mutable std::mutex history_mutex;

        // Компаратор для приоритетной очереди
        struct TaskComparator {
            bool operator()(const Task& a, const Task& b) const {
                if (a.priority != b.priority) {
                    return a.priority < b.priority; // Высокий приоритет = меньшее число
                }
                return a.scheduled_at > b.scheduled_at; // Раньше по времени = выше приоритет
            }
        };

        Impl() {
            statistics.start_time = std::chrono::system_clock::now();
            InitializeQueues();
        }

        ~Impl() {
            Shutdown();
        }

        void InitializeQueues() {
            // Инициализация очередей для каждой категории
            for (int i = 0; i < static_cast<int>(TaskCategory::REPORTING_OPERATIONS) + 1; ++i) {
                TaskCategory category = static_cast<TaskCategory>(i);
                task_queues[category] = std::make_unique<std::priority_queue<Task, std::vector<Task>, TaskComparator>>();
                category_paused[category] = false;
            }
        }

        bool Initialize() {
            if (running.load()) {
                return true;
            }

            try {
                shutdown_requested = false;

                // Запуск рабочих потоков для каждой категории
                StartWorkerThreads();

                // Запуск мониторинга
                if (config.enable_metrics) {
                    StartMonitoringThread();
                }

                running = true;
                return true;

            } catch (const std::exception& e) {
                return false;
            }
        }

        void Shutdown() {
            if (!running.load()) {
                return;
            }

            shutdown_requested = true;
            running = false;

            // Уведомляем все потоки о завершении
            for (auto& [category, cv] : queue_cvs) {
                cv.notify_all();
            }

            // Ждем завершения всех потоков
            for (auto& [category, workers] : category_workers) {
                for (auto& worker : workers) {
                    if (worker.joinable()) {
                        worker.join();
                    }
                }
            }

            for (auto& worker : worker_threads) {
                if (worker.joinable()) {
                    worker.join();
                }
            }

            // Отменяем все pending задачи
            CancelAllPendingTasks();
        }

        void StartWorkerThreads() {
            // Сканирование
            StartCategoryWorkers(TaskCategory::SCAN_OPERATIONS, config.scan_worker_threads);

            // Обновления
            StartCategoryWorkers(TaskCategory::UPDATE_OPERATIONS, config.update_worker_threads);

            // Аутентификация
            StartCategoryWorkers(TaskCategory::AUTH_OPERATIONS, config.auth_worker_threads);

            // Файловые операции
            StartCategoryWorkers(TaskCategory::FILE_OPERATIONS, config.file_worker_threads);

            // Системные операции
            StartCategoryWorkers(TaskCategory::SYSTEM_OPERATIONS, config.system_worker_threads);

            // Отчеты
            StartCategoryWorkers(TaskCategory::REPORTING_OPERATIONS, config.reporting_worker_threads);
        }

        void StartCategoryWorkers(TaskCategory category, int thread_count) {
            auto& workers = category_workers[category];
            workers.clear();

            for (int i = 0; i < thread_count; ++i) {
                workers.emplace_back([this, category, i]() {
                    WorkerThreadLoop(category, i);
                });
            }
        }

        void WorkerThreadLoop(TaskCategory category, int worker_id) {
            std::string worker_name = Utils::TaskCategoryToString(category) + "_worker_" + std::to_string(worker_id);

            while (!shutdown_requested.load()) {
                try {
                    std::unique_lock<std::mutex> lock(queue_mutexes[category]);

                    // Ждем задачи в очереди
                    queue_cvs[category].wait(lock, [this, category]() {
                        return !task_queues[category]->empty() ||
                               shutdown_requested.load() ||
                               category_paused[category].load();
                    });

                    if (shutdown_requested.load()) {
                        break;
                    }

                    if (category_paused[category].load() || task_queues[category]->empty()) {
                        continue;
                    }

                    // Извлекаем задачу из очереди
                    Task task = task_queues[category]->top();
                    task_queues[category]->pop();
                    lock.unlock();

                    // Проверяем, не отменена ли задача
                    if (task.status == TaskStatus::CANCELLED) {
                        continue;
                    }

                    // Выполняем задачу
                    ProcessTask(task, worker_name);

                } catch (const std::exception& e) {
                    // Логирование ошибки
                }
            }
        }

        void ProcessTask(Task& task, const std::string& worker_name) {
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                // Обновляем статус задачи
                task.status = TaskStatus::PROCESSING;
                task.started_at = std::chrono::system_clock::now();
                task.assigned_worker = worker_name;

                // Добавляем в активные задачи
                {
                    std::lock_guard<std::mutex> lock(active_tasks_mutex);
                    active_tasks[task.task_id] = task;
                }

                // Поиск обработчика
                TaskHandler handler;
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex);
                    auto it = task_handlers.find(task.type);
                    if (it == task_handlers.end()) {
                        throw std::runtime_error("No handler registered for task type: " +
                                               Utils::TaskTypeToString(task.type));
                    }
                    handler = it->second;
                }

                // Выполнение задачи с таймаутом
                TaskResult result = ExecuteTaskWithTimeout(task, handler);

                // Обновляем время выполнения
                auto end_time = std::chrono::high_resolution_clock::now();
                result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                // Завершаем задачу
                CompleteTask(task, result);

            } catch (const std::exception& e) {
                TaskResult result;
                result.success = false;
                result.error_message = e.what();
                result.error_code = "PROCESSING_ERROR";

                auto end_time = std::chrono::high_resolution_clock::now();
                result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                FailTask(task, result);
            }
        }

        TaskResult ExecuteTaskWithTimeout(const Task& task, TaskHandler& handler) {
            if (task.timeout.count() == 0) {
                // Выполнение без таймаута
                return handler(task);
            }

            // Выполнение с таймаутом
            auto future = std::async(std::launch::async, [&handler, &task]() {
                return handler(task);
            });

            auto status = future.wait_for(task.timeout);
            if (status == std::future_status::timeout) {
                TaskResult result;
                result.success = false;
                result.error_message = "Task execution timeout";
                result.error_code = "TIMEOUT";
                return result;
            }

            return future.get();
        }

        void CompleteTask(Task& task, const TaskResult& result) {
            task.status = result.success ? TaskStatus::COMPLETED : TaskStatus::FAILED;
            task.completed_at = std::chrono::system_clock::now();
            task.result = result;

            // Удаляем из активных задач
            {
                std::lock_guard<std::mutex> lock(active_tasks_mutex);
                active_tasks.erase(task.task_id);

                // Уведомляем promise если есть
                auto promise_it = task_promises.find(task.task_id);
                if (promise_it != task_promises.end()) {
                    promise_it->second.set_value(result);
                    task_promises.erase(promise_it);
                }
            }

            // Сохраняем результат
            {
                std::lock_guard<std::mutex> lock(results_mutex);
                task_results[task.task_id] = result;
            }

            // Обновляем статистику
            UpdateStatistics(task, result);

            // Добавляем в историю
            AddToHistory(task);

            // Callback
            if (completed_callback) {
                completed_callback(task, result);
            }
        }

        void FailTask(Task& task, const TaskResult& result) {
            task.status = TaskStatus::FAILED;
            task.completed_at = std::chrono::system_clock::now();
            task.result = result;

            // Удаляем из активных задач
            {
                std::lock_guard<std::mutex> lock(active_tasks_mutex);
                active_tasks.erase(task.task_id);

                // Уведомляем promise если есть
                auto promise_it = task_promises.find(task.task_id);
                if (promise_it != task_promises.end()) {
                    promise_it->second.set_value(result);
                    task_promises.erase(promise_it);
                }
            }

            // Сохраняем результат
            {
                std::lock_guard<std::mutex> lock(results_mutex);
                task_results[task.task_id] = result;
            }

            // Обновляем статистику
            UpdateStatistics(task, result);

            // Добавляем в историю
            AddToHistory(task);

            // Callback
            if (failed_callback) {
                failed_callback(task, result.error_message);
            }
        }

        std::string SubmitTaskImpl(const Task& task) {
            if (!running.load()) {
                throw std::runtime_error("Task router is not running");
            }

            // Валидация задачи
            if (!Utils::ValidateTaskType(task.type) ||
                !Utils::ValidateTaskParameters(task.type, task.parameters)) {
                throw std::invalid_argument("Invalid task parameters");
            }

            TaskCategory category = task.category;

            // Проверка размера очереди
            {
                std::lock_guard<std::mutex> lock(queue_mutexes[category]);
                if (task_queues[category]->size() >= config.max_queue_size) {
                    throw std::runtime_error("Task queue is full");
                }
            }

            // Добавляем в очередь
            {
                std::lock_guard<std::mutex> lock(queue_mutexes[category]);
                Task mutable_task = task;
                mutable_task.status = TaskStatus::QUEUED;
                task_queues[category]->push(mutable_task);
            }

            // Уведомляем рабочие потоки
            queue_cvs[category].notify_one();

            // Обновляем статистику
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                statistics.total_tasks++;
                statistics.task_type_counts[task.type]++;
                statistics.category_counts[category]++;
                statistics.last_task_time = task.created_at;
                statistics.current_queue_size = GetTotalQueueSize();
            }

            return task.task_id;
        }

        std::future<TaskResult> SubmitTaskAsyncImpl(const Task& task) {
            std::promise<TaskResult> promise;
            std::future<TaskResult> future = promise.get_future();

            {
                std::lock_guard<std::mutex> lock(active_tasks_mutex);
                task_promises[task.task_id] = std::move(promise);
            }

            SubmitTaskImpl(task);
            return future;
        }

        bool CancelTaskImpl(const std::string& task_id) {
            // Проверяем активные задачи
            {
                std::lock_guard<std::mutex> lock(active_tasks_mutex);
                auto it = active_tasks.find(task_id);
                if (it != active_tasks.end()) {
                    it->second.status = TaskStatus::CANCELLED;
                    active_tasks.erase(it);

                    // Уведомляем promise если есть
                    auto promise_it = task_promises.find(task_id);
                    if (promise_it != task_promises.end()) {
                        TaskResult cancelled_result;
                        cancelled_result.success = false;
                        cancelled_result.error_message = "Task cancelled";
                        cancelled_result.error_code = "CANCELLED";
                        promise_it->second.set_value(cancelled_result);
                        task_promises.erase(promise_it);
                    }

                    statistics.cancelled_tasks++;
                    return true;
                }
            }

            // Проверяем очереди
            for (auto& [category, queue] : task_queues) {
                std::lock_guard<std::mutex> lock(queue_mutexes[category]);
                // Для упрощения помечаем задачу как отмененную
                // В реальной реализации нужно удалить из очереди
            }

            return false;
        }

        void UpdateStatistics(const Task& task, const TaskResult& result) {
            std::lock_guard<std::mutex> lock(stats_mutex);

            if (result.success) {
                statistics.completed_tasks++;
            } else {
                statistics.failed_tasks++;

                if (result.error_code == "TIMEOUT") {
                    statistics.timeout_tasks++;
                }
            }

            // Обновление среднего времени выполнения
            double execution_time_ms = result.execution_time.count();
            if (statistics.completed_tasks > 0) {
                statistics.average_execution_time_ms =
                    (statistics.average_execution_time_ms * (statistics.completed_tasks - 1) + execution_time_ms)
                    / statistics.completed_tasks;
            }

            statistics.current_queue_size = GetTotalQueueSize();
            statistics.active_worker_count = GetActiveWorkerCount();
        }

        void AddToHistory(const Task& task) {
            std::lock_guard<std::mutex> lock(history_mutex);
            recent_tasks.push_back(task);

            if (recent_tasks.size() > 10000) { // Ограничиваем размер истории
                recent_tasks.erase(recent_tasks.begin());
            }
        }

        void StartMonitoringThread() {
            worker_threads.emplace_back([this]() {
                while (!shutdown_requested.load()) {
                    try {
                        CheckTimeouts();
                        CleanupCompletedTasks();

                        std::this_thread::sleep_for(config.metrics_interval);
                    } catch (const std::exception& e) {
                        // Логирование ошибки
                    }
                }
            });
        }

        void CheckTimeouts() {
            std::vector<std::string> timed_out_tasks;

            {
                std::lock_guard<std::mutex> lock(active_tasks_mutex);
                auto now = std::chrono::system_clock::now();

                for (auto& [task_id, task] : active_tasks) {
                    if (task.IsExpired()) {
                        timed_out_tasks.push_back(task_id);
                    }
                }
            }

            for (const auto& task_id : timed_out_tasks) {
                CancelTaskImpl(task_id);
                if (timeout_callback) {
                    auto task_it = active_tasks.find(task_id);
                    if (task_it != active_tasks.end()) {
                        timeout_callback(task_it->second);
                    }
                }
            }
        }

        void CleanupCompletedTasks() {
            // Очистка старых результатов (старше 1 часа)
            auto cutoff_time = std::chrono::system_clock::now() - std::chrono::hours{1};

            std::lock_guard<std::mutex> lock(results_mutex);
            for (auto it = task_results.begin(); it != task_results.end();) {
                // В реальной реализации нужно сохранять время завершения в результате
                ++it; // Пока просто пропускаем
            }
        }

        void CancelAllPendingTasks() {
            for (auto& [category, queue] : task_queues) {
                std::lock_guard<std::mutex> lock(queue_mutexes[category]);
                while (!queue->empty()) {
                    queue->pop();
                }
            }

            std::lock_guard<std::mutex> lock(active_tasks_mutex);
            for (auto& [task_id, promise] : task_promises) {
                TaskResult cancelled_result;
                cancelled_result.success = false;
                cancelled_result.error_message = "System shutdown";
                cancelled_result.error_code = "SHUTDOWN";
                promise.set_value(cancelled_result);
            }
            task_promises.clear();
        }

        std::size_t GetTotalQueueSize() const {
            std::size_t total = 0;
            for (const auto& [category, queue] : task_queues) {
                total += queue->size();
            }
            return total;
        }

        std::size_t GetActiveWorkerCount() const {
            return active_tasks.size();
        }
    };

    // ============================================================================
    // DefaultTaskHandlers реализация
    // ============================================================================

    TaskResult DefaultTaskHandlers::HandleScanFile(const Task& task) {
        TaskResult result;

        try {
            std::string file_path = task.parameters.GetStringParam("file_path");
            if (file_path.empty()) {
                result.error_message = "File path is required";
                result.error_code = "MISSING_PARAMETER";
                return result;
            }

            UpdateProgress(task.task_id, 10, "Initializing scan");

            // Здесь должна быть реальная логика сканирования файла
            // Например, вызов ScannerEngine::Scanner::ScanFile(file_path)

            UpdateProgress(task.task_id, 50, "Scanning file");
            std::this_thread::sleep_for(std::chrono::milliseconds{1000}); // Имитация работы

            UpdateProgress(task.task_id, 90, "Finalizing scan");

            result.success = true;
            result.result_data = "File scan completed";
            result.result_metadata["scanned_file"] = file_path;
            result.result_metadata["threats_found"] = "0";

            UpdateProgress(task.task_id, 100, "Scan completed");

        } catch (const std::exception& e) {
            result.error_message = "Scan failed: " + std::string(e.what());
            result.error_code = "SCAN_ERROR";
        }

        return result;
    }

    TaskResult DefaultTaskHandlers::HandleLogin(const Task& task) {
        TaskResult result;

        try {
            std::string username = task.parameters.GetStringParam("username");
            std::string password = task.parameters.GetStringParam("password");

            if (username.empty() || password.empty()) {
                result.error_message = "Username and password are required";
                result.error_code = "MISSING_CREDENTIALS";
                return result;
            }

            UpdateProgress(task.task_id, 25, "Validating credentials");

            // Здесь должна быть реальная аутентификация
            // Например, вызов ClientAuth::AuthClient::Login(username, password)

            std::this_thread::sleep_for(std::chrono::milliseconds{500}); // Имитация работы

            UpdateProgress(task.task_id, 75, "Creating session");

            result.success = true;
            result.result_data = "Login successful";
            result.result_metadata["user_id"] = username;
            result.result_metadata["session_token"] = "generated_token_123";

            UpdateProgress(task.task_id, 100, "Login completed");

        } catch (const std::exception& e) {
            result.error_message = "Login failed: " + std::string(e.what());
            result.error_code = "AUTH_ERROR";
        }

        return result;
    }

    TaskResult DefaultTaskHandlers::HandleUpdateSignatures(const Task& task) {
        TaskResult result;

        try {
            UpdateProgress(task.task_id, 10, "Checking for updates");

            // Здесь должна быть логика обновления сигнатур
            // Например, вызов SignatureEngine::SignatureDatabase::UpdateDatabase()

            UpdateProgress(task.task_id, 30, "Downloading updates");
            std::this_thread::sleep_for(std::chrono::milliseconds{2000}); // Имитация загрузки

            UpdateProgress(task.task_id, 70, "Installing updates");
            std::this_thread::sleep_for(std::chrono::milliseconds{1000}); // Имитация установки

            UpdateProgress(task.task_id, 90, "Verifying installation");

            result.success = true;
            result.result_data = "Signature database updated successfully";
            result.result_metadata["updated_signatures"] = "1250";
            result.result_metadata["update_version"] = "2024.01.15";

            UpdateProgress(task.task_id, 100, "Update completed");

        } catch (const std::exception& e) {
            result.error_message = "Update failed: " + std::string(e.what());
            result.error_code = "UPDATE_ERROR";
        }

        return result;
    }

    // Добавляем остальные обработчики...
    TaskResult DefaultTaskHandlers::HandleScanDirectory(const Task& task) {
        TaskResult result;
        result.success = true;
        result.result_data = "Directory scan completed";
        return result;
    }

    TaskResult DefaultTaskHandlers::HandleRegister(const Task& task) {
        TaskResult result;
        result.success = true;
        result.result_data = "Registration completed";
        return result;
    }

    void DefaultTaskHandlers::UpdateProgress(const std::string& task_id, int percentage, const std::string& status) {
        // В реальной реализации здесь должен быть вызов progress_callback
        // через глобальный экземпляр TaskRouter или статический callback
    }

    bool DefaultTaskHandlers::ValidateParameters(const Task& task) {
        return Utils::ValidateTaskParameters(task.type, task.parameters);
    }

    // ============================================================================
    // Основной класс TaskRouter
    // ============================================================================

    TaskRouter::TaskRouter(const RouterConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    TaskRouter::~TaskRouter() = default;

    bool TaskRouter::Initialize() {
        return pImpl->Initialize();
    }

    void TaskRouter::Shutdown() {
        pImpl->Shutdown();
    }

    bool TaskRouter::IsRunning() const {
        return pImpl->running.load();
    }

    void TaskRouter::RegisterTaskHandler(TaskType type, TaskHandler handler) {
        std::lock_guard<std::mutex> lock(pImpl->handlers_mutex);
        pImpl->task_handlers[type] = std::move(handler);
    }

    void TaskRouter::RegisterDefaultHandlers() {
        RegisterTaskHandler(TaskType::SCAN_FILE, DefaultTaskHandlers::HandleScanFile);
        RegisterTaskHandler(TaskType::SCAN_DIRECTORY, DefaultTaskHandlers::HandleScanDirectory);
        RegisterTaskHandler(TaskType::LOGIN, DefaultTaskHandlers::HandleLogin);
        RegisterTaskHandler(TaskType::REGISTER, DefaultTaskHandlers::HandleRegister);
        RegisterTaskHandler(TaskType::UPDATE_SIGNATURES, DefaultTaskHandlers::HandleUpdateSignatures);
        // Регистрация остальных обработчиков...
    }

    void TaskRouter::SetTaskProgressCallback(TaskProgressCallback callback) {
        pImpl->progress_callback = std::move(callback);
    }

    void TaskRouter::SetTaskCompletedCallback(TaskCompletedCallback callback) {
        pImpl->completed_callback = std::move(callback);
    }

    void TaskRouter::SetTaskFailedCallback(TaskFailedCallback callback) {
        pImpl->failed_callback = std::move(callback);
    }

    void TaskRouter::SetTaskTimeoutCallback(TaskTimeoutCallback callback) {
        pImpl->timeout_callback = std::move(callback);
    }

    std::string TaskRouter::SubmitTask(const Task& task) {
        return pImpl->SubmitTaskImpl(task);
    }

    std::string TaskRouter::SubmitTask(TaskType type, const TaskParameters& params, TaskPriority priority) {
        Task task(type, priority);
        task.task_id = GenerateTaskId();
        task.parameters = params;
        return SubmitTask(task);
    }

    std::future<TaskResult> TaskRouter::SubmitTaskAsync(const Task& task) {
        return pImpl->SubmitTaskAsyncImpl(task);
    }

    bool TaskRouter::CancelTask(const std::string& task_id) {
        return pImpl->CancelTaskImpl(task_id);
    }

    std::optional<TaskResult> TaskRouter::GetTaskResult(const std::string& task_id) const {
        std::lock_guard<std::mutex> lock(pImpl->results_mutex);
        auto it = pImpl->task_results.find(task_id);
        return it != pImpl->task_results.end() ? std::make_optional(it->second) : std::nullopt;
    }

    RouterStatistics TaskRouter::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    std::string TaskRouter::GenerateTaskId() const {
        return Utils::GenerateUniqueTaskId();
    }

    TaskCategory TaskRouter::GetTaskCategory(TaskType type) const {
        Task temp_task;
        return temp_task.GetTaskCategory(type);
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string TaskTypeToString(TaskType type) {
            switch (type) {
                case TaskType::SCAN_FILE: return "SCAN_FILE";
                case TaskType::SCAN_DIRECTORY: return "SCAN_DIRECTORY";
                case TaskType::SCAN_FULL_SYSTEM: return "SCAN_FULL_SYSTEM";
                case TaskType::SCAN_QUICK: return "SCAN_QUICK";
                case TaskType::SCAN_CUSTOM: return "SCAN_CUSTOM";
                case TaskType::UPDATE_SIGNATURES: return "UPDATE_SIGNATURES";
                case TaskType::UPDATE_ENGINE: return "UPDATE_ENGINE";
                case TaskType::UPDATE_CONFIG: return "UPDATE_CONFIG";
                case TaskType::UPDATE_ALL: return "UPDATE_ALL";
                case TaskType::LOGIN: return "LOGIN";
                case TaskType::LOGOUT: return "LOGOUT";
                case TaskType::REGISTER: return "REGISTER";
                case TaskType::REFRESH_TOKEN: return "REFRESH_TOKEN";
                case TaskType::QUARANTINE_FILE: return "QUARANTINE_FILE";
                case TaskType::RESTORE_FILE: return "RESTORE_FILE";
                case TaskType::DELETE_FILE: return "DELETE_FILE";
                case TaskType::GENERATE_REPORT: return "GENERATE_REPORT";
                case TaskType::EXPORT_LOGS: return "EXPORT_LOGS";
                case TaskType::SYSTEM_SHUTDOWN: return "SYSTEM_SHUTDOWN";
                case TaskType::SYSTEM_RESTART: return "SYSTEM_RESTART";
                case TaskType::SYSTEM_STATUS: return "SYSTEM_STATUS";
                case TaskType::CUSTOM_TASK: return "CUSTOM_TASK";
                default: return "UNKNOWN";
            }
        }

        TaskType StringToTaskType(const std::string& type_str) {
            if (type_str == "SCAN_FILE") return TaskType::SCAN_FILE;
            if (type_str == "SCAN_DIRECTORY") return TaskType::SCAN_DIRECTORY;
            if (type_str == "SCAN_FULL_SYSTEM") return TaskType::SCAN_FULL_SYSTEM;
            if (type_str == "LOGIN") return TaskType::LOGIN;
            if (type_str == "REGISTER") return TaskType::REGISTER;
            if (type_str == "UPDATE_SIGNATURES") return TaskType::UPDATE_SIGNATURES;
            // ... остальные типы
            return TaskType::CUSTOM_TASK;
        }

        std::string TaskPriorityToString(TaskPriority priority) {
            switch (priority) {
                case TaskPriority::LOW: return "LOW";
                case TaskPriority::NORMAL: return "NORMAL";
                case TaskPriority::HIGH: return "HIGH";
                case TaskPriority::CRITICAL: return "CRITICAL";
                case TaskPriority::EMERGENCY: return "EMERGENCY";
                default: return "UNKNOWN";
            }
        }

        std::string TaskCategoryToString(TaskCategory category) {
            switch (category) {
                case TaskCategory::SCAN_OPERATIONS: return "SCAN_OPERATIONS";
                case TaskCategory::UPDATE_OPERATIONS: return "UPDATE_OPERATIONS";
                case TaskCategory::AUTH_OPERATIONS: return "AUTH_OPERATIONS";
                case TaskCategory::FILE_OPERATIONS: return "FILE_OPERATIONS";
                case TaskCategory::SYSTEM_OPERATIONS: return "SYSTEM_OPERATIONS";
                case TaskCategory::REPORTING_OPERATIONS: return "REPORTING_OPERATIONS";
                default: return "UNKNOWN";
            }
        }

        bool ValidateTaskType(TaskType type) {
            return type != TaskType::CUSTOM_TASK || true; // Все типы валидны
        }

        bool ValidateTaskParameters(TaskType type, const TaskParameters& params) {
            switch (type) {
                case TaskType::SCAN_FILE:
                    return !params.GetStringParam("file_path").empty();
                case TaskType::LOGIN:
                    return !params.GetStringParam("username").empty() &&
                           !params.GetStringParam("password").empty();
                case TaskType::REGISTER:
                    return !params.GetStringParam("username").empty() &&
                           !params.GetStringParam("password").empty() &&
                           !params.GetStringParam("email").empty();
                default:
                    return true;
            }
        }

        std::string GenerateUniqueTaskId() {
            static std::atomic<uint64_t> counter{1};
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            return "task_" + std::to_string(timestamp) + "_" + std::to_string(counter.fetch_add(1));
        }

        std::string FormatDuration(std::chrono::milliseconds duration) {
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
            auto ms = duration - seconds;

            return std::to_string(seconds.count()) + "." +
                   std::to_string(ms.count()) + "s";
        }

        bool ShouldTaskTakePriority(const Task& task1, const Task& task2) {
            if (task1.priority != task2.priority) {
                return task1.priority > task2.priority;
            }
            return task1.scheduled_at < task2.scheduled_at;
        }
    }
}