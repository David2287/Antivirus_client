//
// Created by WhySkyDie on 21.07.2025.
//

#include "ipc_comm.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <random>
#include <cstring>

#ifdef _WIN32
    #include <process.h>
    #include <psapi.h>
#else
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <signal.h>
#endif

namespace IPCComm {

    // Константы
    constexpr uint32_t IPC_MAGIC = 0x12345678;
    constexpr uint32_t IPC_VERSION = 1;
    constexpr size_t MAX_PIPE_INSTANCES = 10;

    // ============================================================================
    // NamedPipeTransport::Impl
    // ============================================================================

    class NamedPipeTransport::Impl {
    public:
        IPCConfig config;
        bool is_server;
        std::atomic<ConnectionStatus> status{ConnectionStatus::DISCONNECTED};

#ifdef _WIN32
        HANDLE pipe_handle;
        std::string full_pipe_name;
#else
        int pipe_fd;
        std::string pipe_path;
#endif

        mutable std::mutex transport_mutex;

        Impl(const IPCConfig& cfg, bool server)
            : config(cfg), is_server(server)
#ifdef _WIN32
            , pipe_handle(INVALID_HANDLE_VALUE)
#else
            , pipe_fd(-1)
#endif
        {
#ifdef _WIN32
            full_pipe_name = "\\\\.\\pipe\\" + config.pipe_name;
#else
            pipe_path = "/tmp/" + config.pipe_name;
#endif
        }

        ~Impl() {
            Shutdown();
        }

        bool Initialize() {
            std::lock_guard<std::mutex> lock(transport_mutex);

            try {
                status = ConnectionStatus::CONNECTING;

#ifdef _WIN32
                if (is_server) {
                    pipe_handle = CreateNamedPipeA(
                        full_pipe_name.c_str(),
                        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                        MAX_PIPE_INSTANCES,
                        static_cast<DWORD>(config.buffer_size),
                        static_cast<DWORD>(config.buffer_size),
                        0,
                        nullptr
                    );

                    if (pipe_handle == INVALID_HANDLE_VALUE) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }
                } else {
                    // Клиент подключается к существующему pipe
                    if (!WaitNamedPipeA(full_pipe_name.c_str(), static_cast<DWORD>(config.connect_timeout.count()))) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }

                    pipe_handle = CreateFileA(
                        full_pipe_name.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        nullptr,
                        OPEN_EXISTING,
                        0,
                        nullptr
                    );

                    if (pipe_handle == INVALID_HANDLE_VALUE) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }

                    status = ConnectionStatus::CONNECTED;
                }
#else
                // Linux реализация через FIFO/Unix domain sockets
                if (is_server) {
                    unlink(pipe_path.c_str()); // Удаляем существующий

                    if (mkfifo(pipe_path.c_str(), 0666) == -1) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }

                    pipe_fd = open(pipe_path.c_str(), O_RDWR | O_NONBLOCK);
                    if (pipe_fd == -1) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }
                } else {
                    pipe_fd = open(pipe_path.c_str(), O_RDWR);
                    if (pipe_fd == -1) {
                        status = ConnectionStatus::ERROR;
                        return false;
                    }

                    status = ConnectionStatus::CONNECTED;
                }
#endif

                return true;

            } catch (const std::exception& e) {
                status = ConnectionStatus::ERROR;
                return false;
            }
        }

        void Shutdown() {
            std::lock_guard<std::mutex> lock(transport_mutex);

            status = ConnectionStatus::DISCONNECTED;

#ifdef _WIN32
            if (pipe_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(pipe_handle);
                pipe_handle = INVALID_HANDLE_VALUE;
            }
#else
            if (pipe_fd != -1) {
                close(pipe_fd);
                pipe_fd = -1;

                if (is_server) {
                    unlink(pipe_path.c_str());
                }
            }
#endif
        }

        IPCResult SendMessage(const IPCMessage& message) {
            IPCResult result;
            auto start_time = std::chrono::high_resolution_clock::now();

            try {
                std::lock_guard<std::mutex> lock(transport_mutex);

                if (status != ConnectionStatus::CONNECTED) {
                    result.error_message = "Transport not connected";
                    return result;
                }

                // Сериализация сообщения
                auto serialized = IPCManager::Instance().SerializeMessage(message);

#ifdef _WIN32
                DWORD bytes_written;
                if (!WriteFile(pipe_handle, serialized.data(), static_cast<DWORD>(serialized.size()),
                              &bytes_written, nullptr)) {
                    result.error_message = "WriteFile failed: " + std::to_string(GetLastError());
                    return result;
                }

                if (bytes_written != serialized.size()) {
                    result.error_message = "Incomplete write";
                    return result;
                }
#else
                ssize_t bytes_written = write(pipe_fd, serialized.data(), serialized.size());
                if (bytes_written != static_cast<ssize_t>(serialized.size())) {
                    result.error_message = "Write failed or incomplete";
                    return result;
                }
#endif

                result.success = true;

                auto end_time = std::chrono::high_resolution_clock::now();
                result.operation_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Exception in SendMessage: " + std::string(e.what());
                return result;
            }
        }

        std::optional<IPCMessage> ReceiveMessage(std::chrono::milliseconds timeout) {
            try {
                std::lock_guard<std::mutex> lock(transport_mutex);

                if (status != ConnectionStatus::CONNECTED) {
                    return std::nullopt;
                }

                std::vector<uint8_t> buffer(config.buffer_size);

#ifdef _WIN32
                DWORD bytes_read;
                if (!ReadFile(pipe_handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                             &bytes_read, nullptr)) {
                    return std::nullopt;
                }

                if (bytes_read == 0) {
                    return std::nullopt;
                }

                buffer.resize(bytes_read);
#else
                // Установка таймаута для чтения
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(pipe_fd, &read_fds);

                struct timeval tv;
                tv.tv_sec = timeout.count() / 1000;
                tv.tv_usec = (timeout.count() % 1000) * 1000;

                int select_result = select(pipe_fd + 1, &read_fds, nullptr, nullptr, &tv);
                if (select_result <= 0) {
                    return std::nullopt;
                }

                ssize_t bytes_read = read(pipe_fd, buffer.data(), buffer.size());
                if (bytes_read <= 0) {
                    return std::nullopt;
                }

                buffer.resize(bytes_read);
#endif

                // Десериализация сообщения
                return IPCManager::Instance().DeserializeMessage(buffer);

            } catch (const std::exception& e) {
                return std::nullopt;
            }
        }

        bool WaitForConnection() {
            if (!is_server) {
                return false;
            }

            std::lock_guard<std::mutex> lock(transport_mutex);

#ifdef _WIN32
            if (ConnectNamedPipe(pipe_handle, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
                status = ConnectionStatus::CONNECTED;
                return true;
            }
            return false;
#else
            status = ConnectionStatus::CONNECTED;
            return true;
#endif
        }

        void DisconnectClient() {
#ifdef _WIN32
            if (pipe_handle != INVALID_HANDLE_VALUE) {
                DisconnectNamedPipe(pipe_handle);
                status = ConnectionStatus::DISCONNECTED;
            }
#else
            status = ConnectionStatus::DISCONNECTED;
#endif
        }
    };

    // ============================================================================
    // SharedMemoryTransport::Impl
    // ============================================================================

    class SharedMemoryTransport::Impl {
    public:
        IPCConfig config;
        bool is_server;
        std::atomic<ConnectionStatus> status{ConnectionStatus::DISCONNECTED};

#ifdef _WIN32
        HANDLE shm_handle;
        HANDLE mutex_handle;
        HANDLE event_handle;
#else
        int shm_fd;
        sem_t* mutex_sem;
        sem_t* event_sem;
#endif

        void* mapped_memory;
        std::size_t memory_size;
        mutable std::mutex transport_mutex;

        // Структура заголовка shared memory
        struct SHMHeader {
            volatile uint32_t write_offset;
            volatile uint32_t read_offset;
            volatile uint32_t data_size;
            volatile bool has_data;
            char padding[64 - sizeof(uint32_t) * 3 - sizeof(bool)]; // Выравнивание cache line
        };

        Impl(const IPCConfig& cfg, bool server)
            : config(cfg), is_server(server)
#ifdef _WIN32
            , shm_handle(nullptr), mutex_handle(nullptr), event_handle(nullptr)
#else
            , shm_fd(-1), mutex_sem(nullptr), event_sem(nullptr)
#endif
            , mapped_memory(nullptr), memory_size(config.buffer_size + sizeof(SHMHeader))
        {}

        ~Impl() {
            Shutdown();
        }

        bool Initialize() {
            std::lock_guard<std::mutex> lock(transport_mutex);

            try {
                status = ConnectionStatus::CONNECTING;

#ifdef _WIN32
                // Создание или открытие shared memory
                if (is_server) {
                    shm_handle = CreateFileMappingA(
                        INVALID_HANDLE_VALUE,
                        nullptr,
                        PAGE_READWRITE,
                        0,
                        static_cast<DWORD>(memory_size),
                        config.shared_memory_name.c_str()
                    );
                } else {
                    shm_handle = OpenFileMappingA(
                        FILE_MAP_ALL_ACCESS,
                        FALSE,
                        config.shared_memory_name.c_str()
                    );
                }

                if (!shm_handle) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }

                mapped_memory = MapViewOfFile(
                    shm_handle,
                    FILE_MAP_ALL_ACCESS,
                    0, 0,
                    memory_size
                );

                if (!mapped_memory) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }

                // Создание синхронизационных объектов
                std::string mutex_name = config.shared_memory_name + "_mutex";
                std::string event_name = config.shared_memory_name + "_event";

                if (is_server) {
                    mutex_handle = CreateMutexA(nullptr, FALSE, mutex_name.c_str());
                    event_handle = CreateEventA(nullptr, FALSE, FALSE, event_name.c_str());
                } else {
                    mutex_handle = OpenMutexA(SYNCHRONIZE, FALSE, mutex_name.c_str());
                    event_handle = OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, event_name.c_str());
                }

                if (!mutex_handle || !event_handle) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }

#else
                // Linux реализация
                std::string shm_name = "/" + config.shared_memory_name;

                if (is_server) {
                    shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR, 0666);
                    if (shm_fd != -1) {
                        ftruncate(shm_fd, memory_size);
                    }
                } else {
                    shm_fd = shm_open(shm_name.c_str(), O_RDWR, 0666);
                }

                if (shm_fd == -1) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }

                mapped_memory = mmap(nullptr, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
                if (mapped_memory == MAP_FAILED) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }

                // Создание семафоров
                std::string mutex_name = "/" + config.shared_memory_name + "_mutex";
                std::string event_name = "/" + config.shared_memory_name + "_event";

                if (is_server) {
                    mutex_sem = sem_open(mutex_name.c_str(), O_CREAT, 0666, 1);
                    event_sem = sem_open(event_name.c_str(), O_CREAT, 0666, 0);
                } else {
                    mutex_sem = sem_open(mutex_name.c_str(), 0);
                    event_sem = sem_open(event_name.c_str(), 0);
                }

                if (mutex_sem == SEM_FAILED || event_sem == SEM_FAILED) {
                    status = ConnectionStatus::ERROR;
                    return false;
                }
#endif

                // Инициализация заголовка (только для сервера)
                if (is_server) {
                    auto* header = static_cast<SHMHeader*>(mapped_memory);
                    header->write_offset = 0;
                    header->read_offset = 0;
                    header->data_size = 0;
                    header->has_data = false;
                }

                status = ConnectionStatus::CONNECTED;
                return true;

            } catch (const std::exception& e) {
                status = ConnectionStatus::ERROR;
                return false;
            }
        }

        void Shutdown() {
            std::lock_guard<std::mutex> lock(transport_mutex);

            status = ConnectionStatus::DISCONNECTED;

#ifdef _WIN32
            if (mapped_memory) {
                UnmapViewOfFile(mapped_memory);
                mapped_memory = nullptr;
            }

            if (shm_handle) {
                CloseHandle(shm_handle);
                shm_handle = nullptr;
            }

            if (mutex_handle) {
                CloseHandle(mutex_handle);
                mutex_handle = nullptr;
            }

            if (event_handle) {
                CloseHandle(event_handle);
                event_handle = nullptr;
            }
#else
            if (mapped_memory && mapped_memory != MAP_FAILED) {
                munmap(mapped_memory, memory_size);
                mapped_memory = nullptr;
            }

            if (shm_fd != -1) {
                close(shm_fd);
                if (is_server) {
                    std::string shm_name = "/" + config.shared_memory_name;
                    shm_unlink(shm_name.c_str());
                }
                shm_fd = -1;
            }

            if (mutex_sem && mutex_sem != SEM_FAILED) {
                sem_close(mutex_sem);
                if (is_server) {
                    std::string mutex_name = "/" + config.shared_memory_name + "_mutex";
                    sem_unlink(mutex_name.c_str());
                }
                mutex_sem = nullptr;
            }

            if (event_sem && event_sem != SEM_FAILED) {
                sem_close(event_sem);
                if (is_server) {
                    std::string event_name = "/" + config.shared_memory_name + "_event";
                    sem_unlink(event_name.c_str());
                }
                event_sem = nullptr;
            }
#endif
        }

        IPCResult SendMessage(const IPCMessage& message) {
            IPCResult result;

            try {
                if (status != ConnectionStatus::CONNECTED) {
                    result.error_message = "Transport not connected";
                    return result;
                }

                auto serialized = IPCManager::Instance().SerializeMessage(message);

                if (serialized.size() > config.buffer_size) {
                    result.error_message = "Message too large";
                    return result;
                }

                // Захват мьютекса
#ifdef _WIN32
                DWORD wait_result = WaitForSingleObject(mutex_handle, static_cast<DWORD>(config.write_timeout.count()));
                if (wait_result != WAIT_OBJECT_0) {
                    result.error_message = "Mutex wait failed";
                    return result;
                }
#else
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += config.write_timeout.count() / 1000;

                if (sem_timedwait(mutex_sem, &timeout) != 0) {
                    result.error_message = "Semaphore wait failed";
                    return result;
                }
#endif

                auto* header = static_cast<SHMHeader*>(mapped_memory);
                auto* data_area = static_cast<uint8_t*>(mapped_memory) + sizeof(SHMHeader);

                // Запись данных
                std::memcpy(data_area, serialized.data(), serialized.size());
                header->data_size = static_cast<uint32_t>(serialized.size());
                header->has_data = true;

                // Освобождение мьютекса
#ifdef _WIN32
                ReleaseMutex(mutex_handle);
                // Сигнал о готовности данных
                SetEvent(event_handle);
#else
                sem_post(mutex_sem);
                // Сигнал о готовности данных
                sem_post(event_sem);
#endif

                result.success = true;
                return result;

            } catch (const std::exception& e) {
                result.error_message = "Exception in SendMessage: " + std::string(e.what());
                return result;
            }
        }

        std::optional<IPCMessage> ReceiveMessage(std::chrono::milliseconds timeout) {
            try {
                if (status != ConnectionStatus::CONNECTED) {
                    return std::nullopt;
                }

                // Ожидание события о готовности данных
#ifdef _WIN32
                DWORD wait_result = WaitForSingleObject(event_handle, static_cast<DWORD>(timeout.count()));
                if (wait_result != WAIT_OBJECT_0) {
                    return std::nullopt;
                }
#else
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += timeout.count() / 1000;
                ts.tv_nsec += (timeout.count() % 1000) * 1000000;

                if (sem_timedwait(event_sem, &ts) != 0) {
                    return std::nullopt;
                }
#endif

                // Захват мьютекса для чтения
#ifdef _WIN32
                WaitForSingleObject(mutex_handle, INFINITE);
#else
                sem_wait(mutex_sem);
#endif

                auto* header = static_cast<SHMHeader*>(mapped_memory);
                auto* data_area = static_cast<uint8_t*>(mapped_memory) + sizeof(SHMHeader);

                std::optional<IPCMessage> result;

                if (header->has_data && header->data_size > 0) {
                    std::vector<uint8_t> buffer(data_area, data_area + header->data_size);
                    result = IPCManager::Instance().DeserializeMessage(buffer);

                    // Сброс флага
                    header->has_data = false;
                    header->data_size = 0;
                }

                // Освобождение мьютекса
#ifdef _WIN32
                ReleaseMutex(mutex_handle);
#else
                sem_post(mutex_sem);
#endif

                return result;

            } catch (const std::exception& e) {
                return std::nullopt;
            }
        }
    };

    // ============================================================================
    // IPCServer::Impl
    // ============================================================================

    class IPCServer::Impl {
    public:
        IPCConfig config;
        std::atomic<bool> is_running{false};

        std::vector<std::thread> worker_threads;
        std::vector<std::unique_ptr<IPCTransport>> transports;

        // Управление клиентами
        struct ClientInfo {
            uint32_t client_id;
            ClientType client_type;
            std::unique_ptr<IPCTransport> transport;
            std::atomic<bool> is_connected{true};
            std::chrono::system_clock::time_point connect_time;
        };

        std::unordered_map<uint32_t, std::unique_ptr<ClientInfo>> clients;
        mutable std::mutex clients_mutex;

        // Очереди сообщений
        std::queue<std::pair<uint32_t, IPCMessage>> incoming_messages;
        std::mutex messages_mutex;
        std::condition_variable messages_cv;

        // Обработчики событий
        MessageHandler message_handler;
        ClientConnectedHandler client_connected_handler;
        ClientDisconnectedHandler client_disconnected_handler;
        ErrorHandler error_handler;

        // Статистика
        std::atomic<std::size_t> total_messages_received{0};
        std::atomic<std::size_t> total_messages_sent{0};

        Impl(const IPCConfig& cfg) : config(cfg) {}

        ~Impl() {
            Stop();
        }

        bool Start() {
            if (is_running.load()) {
                return true;
            }

            try {
                // Создание основного транспорта для прослушивания
                auto transport = IPCManager::Instance().CreateTransport(config.transport, config, true);
                if (!transport || !transport->Initialize()) {
                    if (error_handler) {
                        error_handler("Failed to initialize main transport");
                    }
                    return false;
                }

                is_running = true;

                // Запуск рабочих потоков
                for (int i = 0; i < config.worker_thread_count; ++i) {
                    worker_threads.emplace_back([this]() {
                        WorkerThreadLoop();
                    });
                }

                // Поток для принятия новых соединений
                worker_threads.emplace_back([this, transport = std::move(transport)]() mutable {
                    AcceptorThreadLoop(std::move(transport));
                });

                return true;

            } catch (const std::exception& e) {
                if (error_handler) {
                    error_handler("Exception in Start: " + std::string(e.what()));
                }
                return false;
            }
        }

        void Stop() {
            is_running = false;
            messages_cv.notify_all();

            // Отключение всех клиентов
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                for (auto& [client_id, client_info] : clients) {
                    client_info->is_connected = false;
                    if (client_info->transport) {
                        client_info->transport->Shutdown();
                    }
                }
                clients.clear();
            }

            // Ожидание завершения потоков
            for (auto& thread : worker_threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            worker_threads.clear();
        }

        void WorkerThreadLoop() {
            while (is_running.load()) {
                std::unique_lock<std::mutex> lock(messages_mutex);

                messages_cv.wait(lock, [this]() {
                    return !incoming_messages.empty() || !is_running.load();
                });

                if (!is_running.load()) {
                    break;
                }

                if (incoming_messages.empty()) {
                    continue;
                }

                auto [client_id, message] = incoming_messages.front();
                incoming_messages.pop();
                lock.unlock();

                // Обработка сообщения
                ProcessMessage(client_id, message);
            }
        }

        void AcceptorThreadLoop(std::unique_ptr<IPCTransport> main_transport) {
            while (is_running.load()) {
                try {
                    if (config.transport == TransportType::NAMED_PIPES) {
                        auto* pipe_transport = dynamic_cast<NamedPipeTransport*>(main_transport.get());
                        if (pipe_transport && pipe_transport->WaitForConnection()) {
                            // Создание нового клиента
                            HandleNewConnection(std::move(main_transport));

                            // Создание нового транспорта для следующего клиента
                            main_transport = IPCManager::Instance().CreateTransport(config.transport, config, true);
                            if (main_transport) {
                                main_transport->Initialize();
                            }
                        }
                    } else {
                        // Для shared memory просто ждем
                        std::this_thread::sleep_for(std::chrono::milliseconds{100});

                        // Проверяем входящие сообщения
                        auto message = main_transport->ReceiveMessage(std::chrono::milliseconds{100});
                        if (message) {
                            QueueMessage(0, *message); // ID = 0 для shared memory
                        }
                    }

                } catch (const std::exception& e) {
                    if (error_handler) {
                        error_handler("Exception in AcceptorThreadLoop: " + std::string(e.what()));
                    }
                    std::this_thread::sleep_for(std::chrono::seconds{1});
                }
            }
        }

        void HandleNewConnection(std::unique_ptr<IPCTransport> transport) {
            try {
                // Ожидание первого сообщения с информацией о клиенте
                auto first_message = transport->ReceiveMessage(std::chrono::seconds{5});
                if (!first_message) {
                    return;
                }

                uint32_t client_id = Utils::GenerateClientId();
                ClientType client_type = first_message->header.client_type;

                // Создание информации о клиенте
                auto client_info = std::make_unique<ClientInfo>();
                client_info->client_id = client_id;
                client_info->client_type = client_type;
                client_info->transport = std::move(transport);
                client_info->connect_time = std::chrono::system_clock::now();

                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    clients[client_id] = std::move(client_info);
                }

                // Уведомление о новом клиенте
                if (client_connected_handler) {
                    client_connected_handler(client_id, client_type);
                }

                // Запуск потока для чтения от этого клиента
                worker_threads.emplace_back([this, client_id]() {
                    ClientReaderLoop(client_id);
                });

            } catch (const std::exception& e) {
                if (error_handler) {
                    error_handler("Exception in HandleNewConnection: " + std::string(e.what()));
                }
            }
        }

        void ClientReaderLoop(uint32_t client_id) {
            while (is_running.load()) {
                try {
                    std::unique_ptr<ClientInfo>* client_info_ptr = nullptr;

                    {
                        std::lock_guard<std::mutex> lock(clients_mutex);
                        auto it = clients.find(client_id);
                        if (it == clients.end() || !it->second->is_connected.load()) {
                            break;
                        }
                        client_info_ptr = &(it->second);
                    }

                    if (!client_info_ptr || !(*client_info_ptr)->transport) {
                        break;
                    }

                    auto message = (*client_info_ptr)->transport->ReceiveMessage(std::chrono::milliseconds{1000});
                    if (message) {
                        QueueMessage(client_id, *message);
                    }

                } catch (const std::exception& e) {
                    if (error_handler) {
                        error_handler("Exception in ClientReaderLoop: " + std::string(e.what()));
                    }
                    break;
                }
            }

            // Отключение клиента
            DisconnectClientImpl(client_id);
        }

        void QueueMessage(uint32_t client_id, const IPCMessage& message) {
            {
                std::lock_guard<std::mutex> lock(messages_mutex);
                if (incoming_messages.size() < config.message_queue_size) {
                    incoming_messages.emplace(client_id, message);
                    total_messages_received++;
                }
            }
            messages_cv.notify_one();
        }

        void ProcessMessage(uint32_t client_id, const IPCMessage& message) {
            try {
                if (message_handler) {
                    ClientType client_type = ClientType::UNKNOWN_CLIENT;

                    {
                        std::lock_guard<std::mutex> lock(clients_mutex);
                        auto it = clients.find(client_id);
                        if (it != clients.end()) {
                            client_type = it->second->client_type;
                        }
                    }

                    auto result = message_handler(message, client_type);

                    // Отправка ответа клиенту если необходимо
                    if (!result.response_data.empty()) {
                        IPCMessage response;
                        response.header.command_type = CommandType::CUSTOM_COMMAND;
                        response.header.message_id = message.header.message_id; // Сохраняем ID для корреляции
                        response.data.assign(result.response_data.begin(), result.response_data.end());
                        response.header.data_size = static_cast<uint32_t>(response.data.size());

                        SendToClientImpl(client_id, response);
                    }
                }

            } catch (const std::exception& e) {
                if (error_handler) {
                    error_handler("Exception in ProcessMessage: " + std::string(e.what()));
                }
            }
        }

        IPCResult SendToClientImpl(uint32_t client_id, const IPCMessage& message) {
            IPCResult result;

            try {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = clients.find(client_id);

                if (it == clients.end() || !it->second->is_connected.load()) {
                    result.error_message = "Client not connected";
                    return result;
                }

                result = it->second->transport->SendMessage(message);
                if (result.success) {
                    total_messages_sent++;
                }

                return result;

            } catch (const std::exception& e) {
                result.error_message = "Exception in SendToClientImpl: " + std::string(e.what());
                return result;
            }
        }

        void DisconnectClientImpl(uint32_t client_id) {
            std::unique_ptr<ClientInfo> client_info;

            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = clients.find(client_id);
                if (it != clients.end()) {
                    client_info = std::move(it->second);
                    clients.erase(it);
                }
            }

            if (client_info) {
                client_info->is_connected = false;
                if (client_info->transport) {
                    client_info->transport->Shutdown();
                }

                if (client_disconnected_handler) {
                    client_disconnected_handler(client_id, client_info->client_type);
                }
            }
        }
    };

    // ============================================================================
    // IPCClient::Impl
    // ============================================================================

    class IPCClient::Impl {
    public:
        IPCConfig config;
        std::unique_ptr<IPCTransport> transport;
        std::atomic<bool> is_connected{false};

        ErrorHandler error_handler;

        std::atomic<std::size_t> messages_sent{0};
        std::atomic<std::size_t> messages_received{0};

        std::mutex transport_mutex;

        Impl(const IPCConfig& cfg) : config(cfg) {}

        ~Impl() {
            Disconnect();
        }

        bool Connect(ClientType client_type) {
            std::lock_guard<std::mutex> lock(transport_mutex);

            try {
                if (is_connected.load()) {
                    return true;
                }

                transport = IPCManager::Instance().CreateTransport(config.transport, config, false);
                if (!transport || !transport->Initialize()) {
                    if (error_handler) {
                        error_handler("Failed to initialize transport");
                    }
                    return false;
                }

                // Отправка первого сообщения с информацией о клиенте
                IPCMessage hello_message;
                hello_message.header.client_type = client_type;
                hello_message.header.command_type = CommandType::CUSTOM_COMMAND;
                hello_message.data.assign({'H', 'E', 'L', 'L', 'O'});
                hello_message.header.data_size = static_cast<uint32_t>(hello_message.data.size());

                auto result = transport->SendMessage(hello_message);
                if (!result.success) {
                    if (error_handler) {
                        error_handler("Failed to send hello message: " + result.error_message);
                    }
                    transport->Shutdown();
                    transport.reset();
                    return false;
                }

                is_connected = true;
                return true;

            } catch (const std::exception& e) {
                if (error_handler) {
                    error_handler("Exception in Connect: " + std::string(e.what()));
                }
                return false;
            }
        }

        void Disconnect() {
            std::lock_guard<std::mutex> lock(transport_mutex);

            if (transport) {
                transport->Shutdown();
                transport.reset();
            }

            is_connected = false;
        }

        IPCResult SendMessage(const IPCMessage& message) {
            std::lock_guard<std::mutex> lock(transport_mutex);

            IPCResult result;

            if (!is_connected.load() || !transport) {
                result.error_message = "Client not connected";
                return result;
            }

            result = transport->SendMessage(message);
            if (result.success) {
                messages_sent++;
            }

            return result;
        }

        std::optional<IPCMessage> ReceiveResponse(std::chrono::milliseconds timeout) {
            std::lock_guard<std::mutex> lock(transport_mutex);

            if (!is_connected.load() || !transport) {
                return std::nullopt;
            }

            auto message = transport->ReceiveMessage(timeout);
            if (message) {
                messages_received++;
            }

            return message;
        }
    };

    // ============================================================================
    // Реализация основных классов
    // ============================================================================

    // NamedPipeTransport
    NamedPipeTransport::NamedPipeTransport(const IPCConfig& config, bool is_server)
        : pImpl(std::make_unique<Impl>(config, is_server)) {}

    NamedPipeTransport::~NamedPipeTransport() = default;

    bool NamedPipeTransport::Initialize() {
        return pImpl->Initialize();
    }

    void NamedPipeTransport::Shutdown() {
        pImpl->Shutdown();
    }

    bool NamedPipeTransport::IsConnected() const {
        return pImpl->status == ConnectionStatus::CONNECTED;
    }

    IPCResult NamedPipeTransport::SendMessage(const IPCMessage& message) {
        return pImpl->SendMessage(message);
    }

    std::optional<IPCMessage> NamedPipeTransport::ReceiveMessage(std::chrono::milliseconds timeout) {
        return pImpl->ReceiveMessage(timeout);
    }

    ConnectionStatus NamedPipeTransport::GetStatus() const {
        return pImpl->status;
    }

    bool NamedPipeTransport::WaitForConnection() {
        return pImpl->WaitForConnection();
    }

    void NamedPipeTransport::DisconnectClient() {
        pImpl->DisconnectClient();
    }

    // SharedMemoryTransport
    SharedMemoryTransport::SharedMemoryTransport(const IPCConfig& config, bool is_server)
        : pImpl(std::make_unique<Impl>(config, is_server)) {}

    SharedMemoryTransport::~SharedMemoryTransport() = default;

    bool SharedMemoryTransport::Initialize() {
        return pImpl->Initialize();
    }

    void SharedMemoryTransport::Shutdown() {
        pImpl->Shutdown();
    }

    bool SharedMemoryTransport::IsConnected() const {
        return pImpl->status == ConnectionStatus::CONNECTED;
    }

    IPCResult SharedMemoryTransport::SendMessage(const IPCMessage& message) {
        return pImpl->SendMessage(message);
    }

    std::optional<IPCMessage> SharedMemoryTransport::ReceiveMessage(std::chrono::milliseconds timeout) {
        return pImpl->ReceiveMessage(timeout);
    }

    ConnectionStatus SharedMemoryTransport::GetStatus() const {
        return pImpl->status;
    }

    // IPCServer
    IPCServer::IPCServer(const IPCConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    IPCServer::~IPCServer() = default;

    bool IPCServer::Start() {
        return pImpl->Start();
    }

    void IPCServer::Stop() {
        pImpl->Stop();
    }

    bool IPCServer::IsRunning() const {
        return pImpl->is_running.load();
    }

    void IPCServer::SetMessageHandler(MessageHandler handler) {
        pImpl->message_handler = std::move(handler);
    }

    void IPCServer::SetClientConnectedHandler(ClientConnectedHandler handler) {
        pImpl->client_connected_handler = std::move(handler);
    }

    void IPCServer::SetClientDisconnectedHandler(ClientDisconnectedHandler handler) {
        pImpl->client_disconnected_handler = std::move(handler);
    }

    void IPCServer::SetErrorHandler(ErrorHandler handler) {
        pImpl->error_handler = std::move(handler);
    }

    IPCResult IPCServer::SendToClient(uint32_t client_id, const IPCMessage& message) {
        return pImpl->SendToClientImpl(client_id, message);
    }

    IPCResult IPCServer::BroadcastMessage(const IPCMessage& message, ClientType client_type) {
        IPCResult result;
        result.success = true;

        std::vector<uint32_t> client_ids;

        {
            std::lock_guard<std::mutex> lock(pImpl->clients_mutex);
            for (const auto& [id, client_info] : pImpl->clients) {
                if (client_type == ClientType::UNKNOWN_CLIENT || client_info->client_type == client_type) {
                    client_ids.push_back(id);
                }
            }
        }

        for (uint32_t client_id : client_ids) {
            auto send_result = SendToClient(client_id, message);
            if (!send_result.success) {
                result.success = false;
                result.error_message += "Failed to send to client " + std::to_string(client_id) + ": " + send_result.error_message + "; ";
            }
        }

        return result;
    }

    std::vector<uint32_t> IPCServer::GetConnectedClients() const {
        std::vector<uint32_t> client_ids;

        std::lock_guard<std::mutex> lock(pImpl->clients_mutex);
        for (const auto& [id, client_info] : pImpl->clients) {
            if (client_info->is_connected.load()) {
                client_ids.push_back(id);
            }
        }

        return client_ids;
    }

    ClientType IPCServer::GetClientType(uint32_t client_id) const {
        std::lock_guard<std::mutex> lock(pImpl->clients_mutex);
        auto it = pImpl->clients.find(client_id);
        return it != pImpl->clients.end() ? it->second->client_type : ClientType::UNKNOWN_CLIENT;
    }

    void IPCServer::DisconnectClient(uint32_t client_id) {
        pImpl->DisconnectClientImpl(client_id);
    }

    std::size_t IPCServer::GetClientCount() const {
        std::lock_guard<std::mutex> lock(pImpl->clients_mutex);
        return pImpl->clients.size();
    }

    std::size_t IPCServer::GetTotalMessagesReceived() const {
        return pImpl->total_messages_received.load();
    }

    std::size_t IPCServer::GetTotalMessagesSent() const {
        return pImpl->total_messages_sent.load();
    }

    // IPCClient
    IPCClient::IPCClient(const IPCConfig& config) : pImpl(std::make_unique<Impl>(config)) {}
    IPCClient::~IPCClient() = default;

    bool IPCClient::Connect(ClientType client_type) {
        return pImpl->Connect(client_type);
    }

    void IPCClient::Disconnect() {
        pImpl->Disconnect();
    }

    bool IPCClient::IsConnected() const {
        return pImpl->is_connected.load();
    }

    IPCResult IPCClient::SendCommand(CommandType command, const std::string& data) {
        IPCMessage message(command, data);
        message.header.message_id = Utils::GenerateMessageId();
        return pImpl->SendMessage(message);
    }

    IPCResult IPCClient::SendMessage(const IPCMessage& message) {
        return pImpl->SendMessage(message);
    }

    std::optional<IPCMessage> IPCClient::ReceiveResponse(std::chrono::milliseconds timeout) {
        return pImpl->ReceiveResponse(timeout);
    }

    IPCResult IPCClient::ExecuteCommand(CommandType command, const std::string& data, std::chrono::milliseconds timeout) {
        auto send_result = SendCommand(command, data);
        if (!send_result.success) {
            return send_result;
        }

        auto response = ReceiveResponse(timeout);
        IPCResult result;

        if (response) {
            result.success = true;
            result.response_data = std::string(response->data.begin(), response->data.end());
        } else {
            result.error_message = "No response received within timeout";
        }

        return result;
    }

    void IPCClient::SetErrorHandler(ErrorHandler handler) {
        pImpl->error_handler = std::move(handler);
    }

    std::size_t IPCClient::GetMessagesSent() const {
        return pImpl->messages_sent.load();
    }

    std::size_t IPCClient::GetMessagesReceived() const {
        return pImpl->messages_received.load();
    }

    // ============================================================================
    // IPCManager
    // ============================================================================

    IPCManager& IPCManager::Instance() {
        static IPCManager instance;
        return instance;
    }

    TransportType IPCManager::SelectBestTransport() {
#ifdef _WIN32
        // На Windows предпочитаем Named Pipes
        return TransportType::NAMED_PIPES;
#else
        // На Linux можем использовать оба варианта, выбираем Shared Memory для производительности
        return TransportType::SHARED_MEMORY;
#endif
    }

    std::unique_ptr<IPCTransport> IPCManager::CreateTransport(TransportType type, const IPCConfig& config, bool is_server) {
        TransportType actual_type = type;
        if (type == TransportType::AUTO_SELECT) {
            actual_type = SelectBestTransport();
        }

        switch (actual_type) {
            case TransportType::NAMED_PIPES:
                return std::make_unique<NamedPipeTransport>(config, is_server);
            case TransportType::SHARED_MEMORY:
                return std::make_unique<SharedMemoryTransport>(config, is_server);
            default:
                return nullptr;
        }
    }

    bool IPCManager::ValidateConfig(const IPCConfig& config) const {
        if (config.pipe_name.empty() || config.shared_memory_name.empty()) {
            return false;
        }

        if (config.buffer_size == 0 || config.max_message_size == 0) {
            return false;
        }

        if (config.buffer_size > config.max_message_size) {
            return false;
        }

        return true;
    }

    std::vector<uint8_t> IPCManager::SerializeMessage(const IPCMessage& message) const {
        std::vector<uint8_t> result;

        // Вычисление контрольной суммы
        MessageHeader header = message.header;
        header.checksum = CalculateChecksum(message);

        // Сериализация заголовка
        result.resize(sizeof(MessageHeader));
        std::memcpy(result.data(), &header, sizeof(MessageHeader));

        // Добавление данных
        if (!message.data.empty()) {
            size_t old_size = result.size();
            result.resize(old_size + message.data.size());
            std::memcpy(result.data() + old_size, message.data.data(), message.data.size());
        }

        return result;
    }

    std::optional<IPCMessage> IPCManager::DeserializeMessage(const std::vector<uint8_t>& data) const {
        if (data.size() < sizeof(MessageHeader)) {
            return std::nullopt;
        }

        IPCMessage message;
        std::memcpy(&message.header, data.data(), sizeof(MessageHeader));

        // Проверка магического числа и версии
        if (message.header.magic != IPC_MAGIC || message.header.version != IPC_VERSION) {
            return std::nullopt;
        }

        // Извлечение данных
        if (message.header.data_size > 0) {
            if (data.size() < sizeof(MessageHeader) + message.header.data_size) {
                return std::nullopt;
            }

            message.data.resize(message.header.data_size);
            std::memcpy(message.data.data(), data.data() + sizeof(MessageHeader), message.header.data_size);
        }

        // Проверка контрольной суммы
        if (!ValidateChecksum(message)) {
            return std::nullopt;
        }

        return message;
    }

    uint32_t IPCManager::CalculateChecksum(const IPCMessage& message) const {
        uint32_t checksum = 0;

        // Простая контрольная сумма на основе XOR
        const auto* header_bytes = reinterpret_cast<const uint8_t*>(&message.header);
        for (size_t i = 0; i < sizeof(MessageHeader) - sizeof(uint32_t); ++i) { // Исключаем поле checksum
            checksum ^= header_bytes[i];
        }

        for (uint8_t byte : message.data) {
            checksum ^= byte;
        }

        return checksum;
    }

    bool IPCManager::ValidateChecksum(const IPCMessage& message) const {
        uint32_t calculated = CalculateChecksum(message);
        return calculated == message.header.checksum;
    }

    // ============================================================================
    // Утилитарные функции
    // ============================================================================

    namespace Utils {

        std::string CommandTypeToString(CommandType type) {
            switch (type) {
                case CommandType::START_SCAN: return "START_SCAN";
                case CommandType::STOP_SCAN: return "STOP_SCAN";
                case CommandType::PAUSE_SCAN: return "PAUSE_SCAN";
                case CommandType::RESUME_SCAN: return "RESUME_SCAN";
                case CommandType::QUARANTINE_FILE: return "QUARANTINE_FILE";
                case CommandType::RESTORE_FILE: return "RESTORE_FILE";
                case CommandType::DELETE_FILE: return "DELETE_FILE";
                case CommandType::SHUTDOWN_SERVICE: return "SHUTDOWN_SERVICE";
                case CommandType::RESTART_SERVICE: return "RESTART_SERVICE";
                case CommandType::GET_STATUS: return "GET_STATUS";
                case CommandType::UPDATE_CONFIG: return "UPDATE_CONFIG";
                case CommandType::GET_CONFIG: return "GET_CONFIG";
                case CommandType::AUTHENTICATE: return "AUTHENTICATE";
                case CommandType::LOGOUT: return "LOGOUT";
                case CommandType::CUSTOM_COMMAND: return "CUSTOM_COMMAND";
                default: return "UNKNOWN";
            }
        }

        CommandType StringToCommandType(const std::string& str) {
            if (str == "START_SCAN") return CommandType::START_SCAN;
            if (str == "STOP_SCAN") return CommandType::STOP_SCAN;
            if (str == "PAUSE_SCAN") return CommandType::PAUSE_SCAN;
            if (str == "RESUME_SCAN") return CommandType::RESUME_SCAN;
            if (str == "QUARANTINE_FILE") return CommandType::QUARANTINE_FILE;
            if (str == "RESTORE_FILE") return CommandType::RESTORE_FILE;
            if (str == "DELETE_FILE") return CommandType::DELETE_FILE;
            if (str == "SHUTDOWN_SERVICE") return CommandType::SHUTDOWN_SERVICE;
            if (str == "RESTART_SERVICE") return CommandType::RESTART_SERVICE;
            if (str == "GET_STATUS") return CommandType::GET_STATUS;
            if (str == "UPDATE_CONFIG") return CommandType::UPDATE_CONFIG;
            if (str == "GET_CONFIG") return CommandType::GET_CONFIG;
            if (str == "AUTHENTICATE") return CommandType::AUTHENTICATE;
            if (str == "LOGOUT") return CommandType::LOGOUT;
            return CommandType::CUSTOM_COMMAND;
        }

        std::string ClientTypeToString(ClientType type) {
            switch (type) {
                case ClientType::UI_CLIENT: return "UI_CLIENT";
                case ClientType::CORE_CLIENT: return "CORE_CLIENT";
                case ClientType::UNKNOWN_CLIENT: return "UNKNOWN_CLIENT";
                default: return "UNKNOWN";
            }
        }

        ClientType StringToClientType(const std::string& str) {
            if (str == "UI_CLIENT") return ClientType::UI_CLIENT;
            if (str == "CORE_CLIENT") return ClientType::CORE_CLIENT;
            return ClientType::UNKNOWN_CLIENT;
        }

        std::string TransportTypeToString(TransportType type) {
            switch (type) {
                case TransportType::NAMED_PIPES: return "NAMED_PIPES";
                case TransportType::SHARED_MEMORY: return "SHARED_MEMORY";
                case TransportType::AUTO_SELECT: return "AUTO_SELECT";
                default: return "UNKNOWN";
            }
        }

        TransportType StringToTransportType(const std::string& str) {
            if (str == "NAMED_PIPES") return TransportType::NAMED_PIPES;
            if (str == "SHARED_MEMORY") return TransportType::SHARED_MEMORY;
            if (str == "AUTO_SELECT") return TransportType::AUTO_SELECT;
            return TransportType::AUTO_SELECT;
        }

        uint32_t GenerateMessageId() {
            static std::atomic<uint32_t> counter{1};
            return counter.fetch_add(1);
        }

        uint32_t GenerateClientId() {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<uint32_t> dis(1000, std::numeric_limits<uint32_t>::max());
            return dis(gen);
        }

        bool ValidateAccessToken(const std::string& token) {
            // Простая валидация - в реальной системе должна быть более сложная
            return !token.empty() && token.length() >= 16;
        }

        std::string GenerateAccessToken() {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            for (int i = 0; i < 32; ++i) {
                ss << std::hex << dis(gen);
            }

            return ss.str();
        }

        uint64_t GetCurrentTimestamp() {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
        }

        std::chrono::system_clock::time_point TimestampToTimePoint(uint64_t timestamp) {
            return std::chrono::system_clock::time_point(std::chrono::milliseconds(timestamp));
        }

        std::string GetProcessName() {
#ifdef _WIN32
            char buffer[MAX_PATH];
            if (GetModuleFileNameA(nullptr, buffer, MAX_PATH)) {
                std::filesystem::path path(buffer);
                return path.filename().string();
            }
            return "unknown";
#else
            std::ifstream comm("/proc/self/comm");
            std::string name;
            if (std::getline(comm, name)) {
                return name;
            }
            return "unknown";
#endif
        }

        uint32_t GetProcessId() {
#ifdef _WIN32
            return static_cast<uint32_t>(GetCurrentProcessId());
#else
            return static_cast<uint32_t>(getpid());
#endif
        }
    }
}