//
// Created by WhySkyDie on 21.07.2025.
//


#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <thread>
#include <atomic>
#include <memory>
#include <iostream>
#include <fstream>
#include <chrono>
#include <filesystem>

// Подключаем наши модули антивируса
#include "scanner.h"
#include "logger.h"
#include "auth.h"
#include "signatures.h"
#include "quarantine.h"
#include "ipc_events.h"

// Имя службы
#define SERVICE_NAME _T("AntivirusService")
#define SERVICE_DISPLAY_NAME _T("Antivirus Protection Service")
#define SERVICE_DESCRIPTION _T("Provides real-time antivirus protection and malware scanning")

// Глобальные переменные службы
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = NULL;

// Указатель на основной класс службы
std::unique_ptr<class AntivirusServiceCore> g_ServiceCore;

// Атомарные флаги для контроля состояния
std::atomic<bool> g_ServiceStopping{false};
std::atomic<bool> g_ServicePaused{false};

// Логгер
std::shared_ptr<LoggingSystem::Logger> g_Logger;

// ============================================================================
// Основной класс службы антивируса
// ============================================================================

class AntivirusServiceCore {
public:
    AntivirusServiceCore()
        : m_initialized(false), m_running(false) {

        // Инициализация логгера
        LoggingSystem::LoggerConfig logger_config;
        logger_config.name = "AntivirusService";
        logger_config.destinations = {LoggingSystem::LogDestination::FILE,
                                     LoggingSystem::LogDestination::EVENT_LOG};
        logger_config.log_directory = std::filesystem::temp_directory_path() / "antivirus_logs";
        logger_config.min_level = LoggingSystem::LogLevel::INFO;

        m_logger = LoggingSystem::LoggerManager::Instance().CreateLogger("ServiceCore", logger_config);
    }

    ~AntivirusServiceCore() {
        Shutdown();
    }

    bool Initialize() {
        try {
            m_logger->Info("Initializing Antivirus Service Core");

            // Инициализация базы данных сигнатур
            SignatureEngine::DatabaseConfig sig_config;
            sig_config.database_directory = GetServiceDataDirectory() / "signatures";
            m_signature_db = std::make_unique<SignatureEngine::SignatureDatabase>(sig_config);

            if (!m_signature_db->Initialize()) {
                m_logger->Error("Failed to initialize signature database");
                return false;
            }

            // Инициализация карантина
            QuarantineEngine::QuarantineConfig quarantine_config;
            quarantine_config.quarantine_directory = GetServiceDataDirectory() / "quarantine";
            quarantine_config.auto_encrypt = true;
            quarantine_config.auto_compress = true;
            m_quarantine = std::make_unique<QuarantineEngine::QuarantineManager>(quarantine_config);

            if (!m_quarantine->Initialize()) {
                m_logger->Error("Failed to initialize quarantine manager");
                return false;
            }

            // Инициализация сканера
            ScannerEngine::ScanConfig scan_config;
            scan_config.enable_real_time = true;
            scan_config.scan_archives = true;
            scan_config.thread_count = std::thread::hardware_concurrency();
            scan_config.max_file_size = 500 * 1024 * 1024; // 500MB
            m_scanner = std::make_unique<ScannerEngine::Scanner>(scan_config);

            if (!m_scanner->Initialize()) {
                m_logger->Error("Failed to initialize scanner");
                return false;
            }

            // Инициализация аутентификации
            ClientAuth::ClientConfig auth_config;
            auth_config.server_url = "https://antivirus-auth.company.com";
            auth_config.auto_refresh_tokens = true;
            auth_config.cache_tokens = true;
            m_auth_client = std::make_unique<ClientAuth::AuthClient>(auth_config);

            if (!m_auth_client->Initialize()) {
                m_logger->Warning("Authentication client failed to initialize - running in offline mode");
            }

            // Инициализация IPC обработчика событий
            IPCEvents::EventHandlerConfig ipc_config;
            ipc_config.max_worker_threads = 4;
            ipc_config.enable_async_processing = true;
            ipc_config.log_directory = GetServiceDataDirectory() / "ipc_logs";
            m_ipc_handler = std::make_unique<IPCEvents::IPCEventHandler>(ipc_config);

            if (!m_ipc_handler->Initialize()) {
                m_logger->Error("Failed to initialize IPC event handler");
                return false;
            }

            // Настройка callbacks
            SetupCallbacks();

            m_initialized = true;
            m_logger->Info("Antivirus Service Core initialized successfully");
            return true;

        } catch (const std::exception& e) {
            m_logger->Error("Exception during initialization: " + std::string(e.what()));
            return false;
        }
    }

    void Run() {
        if (!m_initialized) {
            m_logger->Error("Service core not initialized");
            return;
        }

        m_running = true;
        m_logger->Info("Antivirus Service started and running");

        // Основной цикл службы
        while (!g_ServiceStopping.load() && m_running) {
            try {
                // Проверка состояния пауза
                if (g_ServicePaused.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }

                // Выполнение периодических задач
                PerformPeriodicTasks();

                // Проверка обновлений
                CheckForUpdates();

                // Мониторинг производительности
                MonitorPerformance();

                // Сон между итерациями
                std::this_thread::sleep_for(std::chrono::seconds(10));

            } catch (const std::exception& e) {
                m_logger->Error("Exception in service main loop: " + std::string(e.what()));
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }

        m_logger->Info("Antivirus Service main loop terminated");
        m_running = false;
    }

    void Shutdown() {
        m_logger->Info("Shutting down Antivirus Service Core");

        m_running = false;

        // Остановка всех компонентов в обратном порядке
        if (m_ipc_handler) {
            m_ipc_handler->Shutdown();
            m_ipc_handler.reset();
        }

        if (m_scanner) {
            m_scanner->StopAllScans();
            m_scanner->Shutdown();
            m_scanner.reset();
        }

        if (m_auth_client) {
            m_auth_client->Shutdown();
            m_auth_client.reset();
        }

        if (m_quarantine) {
            m_quarantine->Shutdown();
            m_quarantine.reset();
        }

        if (m_signature_db) {
            m_signature_db->Shutdown();
            m_signature_db.reset();
        }

        m_initialized = false;
        m_logger->Info("Antivirus Service Core shutdown completed");
    }

    void Pause() {
        m_logger->Info("Pausing Antivirus Service");

        // Приостановка сканирования
        if (m_scanner) {
            m_scanner->PauseRealTimeProtection();
        }

        g_ServicePaused = true;
    }

    void Resume() {
        m_logger->Info("Resuming Antivirus Service");

        g_ServicePaused = false;

        // Возобновление сканирования
        if (m_scanner) {
            m_scanner->ResumeRealTimeProtection();
        }
    }

private:
    void SetupCallbacks() {
        // Настройка callback'ов для сканера
        if (m_scanner) {
            m_scanner->SetThreatDetectedCallback([this](const ScannerEngine::ScanResult& result) {
                if (result.threat_level > ScannerEngine::ThreatLevel::CLEAN) {
                    m_logger->Warning("Threat detected: " + result.scan_info);

                    // Автоматическое помещение в карантин
                    if (m_quarantine && !result.detected_threats.empty()) {
                        auto quarantine_result = m_quarantine->QuarantineFile(
                            result.file_path,
                            QuarantineEngine::QuarantineReason::MALWARE_DETECTED,
                            result.detected_threats[0].signature_name
                        );

                        if (quarantine_result.success) {
                            m_logger->Info("File quarantined: " + quarantine_result.quarantine_id);
                        }
                    }
                }
            });
        }

        // Настройка callback'ов для IPC обработчика
        if (m_ipc_handler) {
            m_ipc_handler->SetErrorCallback([this](const std::string& error, const IPCEvents::UIEvent& event) {
                m_logger->Error("IPC Error: " + error + " for event: " + event.event_id);
            });

            m_ipc_handler->SetStatusCallback([this](const std::string& status) {
                m_logger->Debug("IPC Status: " + status);
            });
        }
    }

    void PerformPeriodicTasks() {
        static auto last_cleanup = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();

        // Очистка каждые 30 минут
        if (now - last_cleanup > std::chrono::minutes(30)) {
            // Очистка временных файлов
            if (m_quarantine) {
                m_quarantine->CleanupExpiredFiles();
            }

            // Очистка логов
            CleanupOldLogs();

            last_cleanup = now;
        }
    }

    void CheckForUpdates() {
        static auto last_update_check = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();

        // Проверка обновлений каждые 4 часа
        if (now - last_update_check > std::chrono::hours(4)) {
            if (m_signature_db) {
                // Асинхронная проверка обновлений базы сигнатур
                std::thread([this]() {
                    try {
                        if (m_signature_db->CheckForUpdates()) {
                            m_logger->Info("Signature database updated successfully");
                        }
                    } catch (const std::exception& e) {
                        m_logger->Error("Failed to update signatures: " + std::string(e.what()));
                    }
                }).detach();
            }

            last_update_check = now;
        }
    }

    void MonitorPerformance() {
        static auto last_monitor = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();

        // Мониторинг каждые 5 минут
        if (now - last_monitor > std::chrono::minutes(5)) {
            // Логирование статистики сканера
            if (m_scanner) {
                auto stats = m_scanner->GetStatistics();
                m_logger->Info("Scanner stats - Files scanned: " + std::to_string(stats.total_files_scanned) +
                              ", Threats detected: " + std::to_string(stats.threats_detected));
            }

            // Логирование статистики карантина
            if (m_quarantine) {
                auto stats = m_quarantine->GetStatistics();
                m_logger->Info("Quarantine stats - Files in quarantine: " + std::to_string(stats.active_files.load()));
            }

            last_monitor = now;
        }
    }

    std::filesystem::path GetServiceDataDirectory() {
        wchar_t programData[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, programData) == S_OK) {
            return std::filesystem::path(programData) / L"AntivirusService";
        }
        return std::filesystem::temp_directory_path() / "AntivirusService";
    }

    void CleanupOldLogs() {
        try {
            auto log_dir = GetServiceDataDirectory() / "logs";
            if (std::filesystem::exists(log_dir)) {
                auto now = std::filesystem::file_time_type::clock::now();
                auto cutoff = now - std::chrono::hours(24 * 30); // 30 дней

                for (const auto& entry : std::filesystem::directory_iterator(log_dir)) {
                    if (entry.is_regular_file()) {
                        auto file_time = entry.last_write_time();
                        if (file_time < cutoff) {
                            std::filesystem::remove(entry.path());
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            m_logger->Warning("Failed to cleanup old logs: " + std::string(e.what()));
        }
    }

private:
    bool m_initialized;
    std::atomic<bool> m_running;

    std::shared_ptr<LoggingSystem::Logger> m_logger;
    std::unique_ptr<ScannerEngine::Scanner> m_scanner;
    std::unique_ptr<SignatureEngine::SignatureDatabase> m_signature_db;
    std::unique_ptr<QuarantineEngine::QuarantineManager> m_quarantine;
    std::unique_ptr<ClientAuth::AuthClient> m_auth_client;
    std::unique_ptr<IPCEvents::IPCEventHandler> m_ipc_handler;
};

// ============================================================================
// Функции службы Windows
// ============================================================================

// Функция обработки управляющих команд службы
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            if (g_Logger) g_Logger->Info("Service stop requested");

            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;

            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
            }

            // Сигнализируем главному потоку о необходимости остановки
            g_ServiceStopping = true;
            if (g_ServiceStopEvent) {
                SetEvent(g_ServiceStopEvent);
            }
            break;

        case SERVICE_CONTROL_PAUSE:
            if (g_Logger) g_Logger->Info("Service pause requested");

            g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
            }

            g_ServicePaused = true;
            if (g_ServiceCore) {
                g_ServiceCore->Pause();
            }
            break;

        case SERVICE_CONTROL_CONTINUE:
            if (g_Logger) g_Logger->Info("Service continue requested");

            g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
            }

            g_ServicePaused = false;
            if (g_ServiceCore) {
                g_ServiceCore->Resume();
            }
            break;

        case SERVICE_CONTROL_INTERROGATE:
            // Возврат текущего статуса
            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
            }
            break;

        case SERVICE_CONTROL_SHUTDOWN:
            if (g_Logger) g_Logger->Info("System shutdown - stopping service");

            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;

            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
            }

            g_ServiceStopping = true;
            if (g_ServiceStopEvent) {
                SetEvent(g_ServiceStopEvent);
            }
            break;

        default:
            if (g_Logger) g_Logger->Debug("Unhandled service control code: " + std::to_string(CtrlCode));
            break;
    }
}

// Главная функция службы
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    DWORD Status = E_FAIL;

    // Инициализация глобального логгера
    try {
        LoggingSystem::LoggerConfig config;
        config.destinations = {LoggingSystem::LogDestination::FILE,
                              LoggingSystem::LogDestination::EVENT_LOG};
        config.log_directory = std::filesystem::temp_directory_path() / "antivirus_service";
        config.min_level = LoggingSystem::LogLevel::INFO;

        g_Logger = LoggingSystem::LoggerManager::Instance().CreateLogger("ServiceMain", config);
        g_Logger->Info("=== Antivirus Service Starting ===");

        // Логирование аргументов запуска
        for (DWORD i = 0; i < argc; i++) {
            g_Logger->Debug("Service argument " + std::to_string(i) + ": " +
#ifdef UNICODE
                           std::string(argv[i], argv[i] + wcslen(argv[i]))
#else
                           std::string(argv[i])
#endif
            );
        }

    } catch (const std::exception& e) {
        // Если не удается инициализировать логгер, записываем в Event Log
        HANDLE hEventSource = RegisterEventSourceA(NULL, "AntivirusService");
        if (hEventSource) {
            const char* messages[] = {"Failed to initialize logger: " + std::string(e.what())};
            ReportEventA(hEventSource, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, messages, NULL);
            DeregisterEventSource(hEventSource);
        }
    }

    // Регистрация обработчика управляющих команд
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) {
        if (g_Logger) g_Logger->Error("RegisterServiceCtrlHandler returned error");
        return;
    }

    // Инициализация структуры статуса службы
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    // Сообщаем SCM что служба запускается
    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
    }

    // Создание события для остановки службы
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        if (g_Logger) g_Logger->Error("CreateEvent(g_ServiceStopEvent) returned error");

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
        }
        return;
    }

    // Инициализация основного класса службы
    try {
        if (g_Logger) g_Logger->Info("Creating service core instance");
        g_ServiceCore = std::make_unique<AntivirusServiceCore>();

        if (g_Logger) g_Logger->Info("Initializing service core");
        if (!g_ServiceCore->Initialize()) {
            if (g_Logger) g_Logger->Error("Failed to initialize service core");
            Status = ERROR_SERVICE_SPECIFIC_ERROR;
            goto EXIT;
        }

    } catch (const std::exception& e) {
        if (g_Logger) g_Logger->Error("Exception creating/initializing service core: " + std::string(e.what()));
        Status = ERROR_SERVICE_SPECIFIC_ERROR;
        goto EXIT;
    }

    // Сообщаем SCM что служба запущена и готова принимать команды
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
    }

    if (g_Logger) g_Logger->Info("Service started successfully, entering main loop");

    // Запуск основного цикла службы в отдельном потоке
    std::thread service_thread([&]() {
        try {
            g_ServiceCore->Run();
        } catch (const std::exception& e) {
            if (g_Logger) g_Logger->Error("Exception in service main loop: " + std::string(e.what()));
        }
    });

    // Ожидание сигнала остановки
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    if (g_Logger) g_Logger->Info("Stop event signaled, shutting down service");

    // Ожидание завершения основного потока службы
    if (service_thread.joinable()) {
        service_thread.join();
    }

    Status = NO_ERROR;

EXIT:
    // Очистка ресурсов
    if (g_ServiceCore) {
        try {
            g_ServiceCore->Shutdown();
            g_ServiceCore.reset();
        } catch (const std::exception& e) {
            if (g_Logger) g_Logger->Error("Exception during service core shutdown: " + std::string(e.what()));
        }
    }

    if (g_ServiceStopEvent) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = NULL;
    }

    // Сообщаем SCM что служба остановлена
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = Status;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        if (g_Logger) g_Logger->Error("SetServiceStatus returned error");
    }

    if (g_Logger) {
        if (Status == NO_ERROR) {
            g_Logger->Info("=== Antivirus Service Stopped Successfully ===");
        } else {
            g_Logger->Error("=== Antivirus Service Stopped With Error: " + std::to_string(Status) + " ===");
        }
    }
}

// ============================================================================
// Функции управления службой
// ============================================================================

// Установка службы
BOOL InstallService() {
    BOOL bResult = FALSE;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    TCHAR szPath[MAX_PATH];

    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        printf("Cannot get module filename (%lu)\n", GetLastError());
        return FALSE;
    }

    // Открываем SCM
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        printf("OpenSCManager failed (%lu)\n", GetLastError());
        return FALSE;
    }

    // Создаем службу
    schService = CreateService(
        schSCManager,              // SCM database
        SERVICE_NAME,              // name of service
        SERVICE_DISPLAY_NAME,      // service name to display
        SERVICE_ALL_ACCESS,        // desired access
        SERVICE_WIN32_OWN_PROCESS, // service type
        SERVICE_AUTO_START,        // start type
        SERVICE_ERROR_NORMAL,      // error control type
        szPath,                    // path to service's binary
        NULL,                      // no load ordering group
        NULL,                      // no tag identifier
        NULL,                      // no dependencies
        NULL,                      // LocalSystem account
        NULL);                     // no password

    if (schService == NULL) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("Service already exists.\n");
        } else {
            printf("CreateService failed (%lu)\n", GetLastError());
        }
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // Установка описания службы
    SERVICE_DESCRIPTION sd;
    sd.lpDescription = SERVICE_DESCRIPTION;
    if (!ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd)) {
        printf("ChangeServiceConfig2 failed for description (%lu)\n", GetLastError());
    }

    // Настройка действий при сбое службы
    SERVICE_FAILURE_ACTIONS sfa;
    SC_ACTION actions[3];

    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 10000; // 10 секунд
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 30000; // 30 секунд
    actions[2].Type = SC_ACTION_NONE;
    actions[2].Delay = 0;

    sfa.dwResetPeriod = 86400; // 24 часа
    sfa.lpRebootMsg = NULL;
    sfa.lpCommand = NULL;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;

    if (!ChangeServiceConfig2(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)) {
        printf("ChangeServiceConfig2 failed for failure actions (%lu)\n", GetLastError());
    }

    printf("Service installed successfully\n");
    bResult = TRUE;

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return bResult;
}

// Удаление службы
BOOL UninstallService() {
    BOOL bResult = FALSE;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS svcStatus;

    // Открываем SCM
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL) {
        printf("OpenSCManager failed (%lu)\n", GetLastError());
        return FALSE;
    }

    // Открываем службу
    schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (schService == NULL) {
        printf("OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    // Останавливаем службу если она запущена
    if (ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus)) {
        printf("Stopping service");
        Sleep(1000);

        while (QueryServiceStatus(schService, &svcStatus)) {
            if (svcStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                printf(".");
                Sleep(1000);
            } else {
                break;
            }
        }

        if (svcStatus.dwCurrentState == SERVICE_STOPPED) {
            printf("\nService stopped successfully\n");
        } else {
            printf("\nService failed to stop\n");
        }
    }

    // Удаляем службу
    if (DeleteService(schService)) {
        printf("Service uninstalled successfully\n");
        bResult = TRUE;
    } else {
        printf("DeleteService failed (%lu)\n", GetLastError());
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return bResult;
}

// ============================================================================
// Главная функция программы
// ============================================================================

int _tmain(int argc, TCHAR* argv[]) {
    // Инициализация COM для использования системных API
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("CoInitializeEx failed with 0x%08lx\n", hr);
        return 1;
    }

    // Обработка аргументов командной строки
    if (argc > 1) {
        if (_tcscmp(argv[1], _T("-install")) == 0 || _tcscmp(argv[1], _T("/install")) == 0) {
            if (InstallService()) {
                return 0;
            } else {
                return 1;
            }
        }
        else if (_tcscmp(argv[1], _T("-uninstall")) == 0 || _tcscmp(argv[1], _T("/uninstall")) == 0) {
            if (UninstallService()) {
                return 0;
            } else {
                return 1;
            }
        }
        else if (_tcscmp(argv[1], _T("-console")) == 0 || _tcscmp(argv[1], _T("/console")) == 0) {
            // Запуск в консольном режиме для отладки
            printf("Running in console mode for debugging...\n");

            try {
                g_ServiceCore = std::make_unique<AntivirusServiceCore>();
                if (g_ServiceCore->Initialize()) {
                    printf("Service initialized successfully\n");
                    printf("Press Ctrl+C to stop...\n");

                    // Установка обработчика Ctrl+C
                    SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
                        if (dwCtrlType == CTRL_C_EVENT) {
                            printf("\nShutting down...\n");
                            g_ServiceStopping = true;
                            return TRUE;
                        }
                        return FALSE;
                    }, TRUE);

                    g_ServiceCore->Run();
                } else {
                    printf("Failed to initialize service\n");
                    return 1;
                }
            } catch (const std::exception& e) {
                printf("Exception: %s\n", e.what());
                return 1;
            }

            return 0;
        }
        else {
            printf("Usage: %s [-install | -uninstall | -console]\n", argv[0]);
            printf("  -install    Install the service\n");
            printf("  -uninstall  Uninstall the service\n");
            printf("  -console    Run in console mode for debugging\n");
            return 1;
        }
    }

    // Если аргументы не переданы, запускаем как службу
    printf("Starting as Windows service...\n");

    // Таблица служб - может содержать несколько служб
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    // Запускаем диспетчер управления службами
    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            printf("This program should be run as a Windows service.\n");
            printf("Use -install to install the service, or -console for debug mode.\n");
        } else {
            printf("StartServiceCtrlDispatcher returned error %lu\n", dwError);
        }

        CoUninitialize();
        return dwError;
    }

    CoUninitialize();
    return 0;
}