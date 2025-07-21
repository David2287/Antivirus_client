
# **Строение антивирусной программы на ```C++, Rust, HTML, JavaScript```**

## **Структура ```antivirus-core/``` — ядро антивируса на ```C++```**

``` .text
antivirus-core/
├── include/
│   └── scanner/
│       ├── scanner.h               # сканирование файлов/каталогов
│       ├── signatures.h            # обработка сигнатурных баз
│       └── quarantine.h            # управление карантином
│
│   ├── core_api.h              # C API экспортируемое ядро
│   ├── logger.h                # логирование событий
│   ├── auth.h                  # регистрация, аутентификация
│   ├── ipc_events.h            # обработка событий из UI/службы
│   └── file_utils.h            # утилиты для работы с файлами
│
├── src/
└── scanner/
│       ├── scanner.h               
│       ├── signatures.h            
│       └── quarantine.h   
│        
│   ├── core_api.cpp            # реализация экспортируемого API
│   ├── logger.cpp
│   ├── auth.cpp
│   ├── ipc_events.cpp
│   └── file_utils.cpp
│
├── tests/
│   └── test_scanner.cpp        # модульные тесты
│
└── CMakeLists.txt              # сборка ядра
```

### **Назначение ключевых файлов**

| Модуль           | Назначение                                                               |
| ---------------- | ------------------------------------------------------------------------ |
| `core_api.h/cpp` | Интерфейс между UI (Tauri) или Windows-службой и C++ ядром               |
| `scanner.*`      | Рекурсивный обход каталогов, хэш-фильтрация, сигнатурное сравнение       |
| `signatures.*`   | Загрузка `.sigdb` базы, парсинг и проверка хэшей                         |
| `quarantine.*`   | Изоляция, перемещение, шифрование/сжатие подозрительных файлов           |
| `logger.*`       | Централизованное логирование всех действий (для UI и отправки на сервер) |
| `auth.*`         | Аутентификация/авторизация клиента с сервером, регистрация по токену     |
| `ipc_events.*`   | Обработка вызовов UI: кнопка "Сканировать", "Удалить", "Очистить" и пр.  |
| `file_utils.*`   | Работа с файлами (чтение, хэширование, временные пути и пр.)             |



## **Структура Windows службы ```windows-service/```**

``` .text
windows-service/
├── src/
│   ├── ipc_comm.cpp
│   ├── network_client.cpp
│   ├── updater.cpp
│   ├── task_router.cpp
│   ├── auth_state.cpp
│   ├── config_loader.cpp
│   └── logger.cpp
│
├── include/
│   ├── ipc_comm.h          # IPC канал общения с ядром и UI
│   ├── network_client.h    # Работа с сервером (регистрация, логин, обновления)
│   ├── updater.h           # Получение и установка сигнатур
│   ├── task_router.h       # Обработка входящих команд (от UI или ядра)
│   ├── auth_state.h        # Хранение и проверка авторизации
│   ├── config_loader.h     # Загрузка настроек из файла/реестра
│   └── logger.h            # Логи действий службы
│
├── service_main.cpp           # Точка входа в службу, обработка команд
└── CMakeLists.txt             # Сборка сервиса
```

### **Назначение ключевых файлов**

| Модуль             | Назначение                                                             |
| ------------------ | ---------------------------------------------------------------------- |
| `service_main.cpp` | Запуск службы, регистрация через `ServiceMain` / `Handler`             |
| `ipc_comm`         | Получение команд от UI и ядра (через named pipes или shared memory)    |
| `network_client`   | TLS клиент, подключение к серверу, отправка/получение JSON/gRPC        |
| `auth_state`       | Хранение ключа авторизации, проверка авторизации перед каждым запросом |
| `task_router`      | Диспетчер входящих задач (scan, update, login, register)               |
| `updater`          | Получение обновлений сигнатур или модулей                              |
| `logger`           | Логгирование событий и ошибок в файл/журнал Windows                    |


## **Структура UI + Backend на _Tauri 2.0_**


``` .text
frontend/                    # UI (Svelte / React / Vue)
├── src/
│   ├── pages/
│   │   ├── Home.tsx         # Главная страница
│   │   ├── Scan.tsx         # Экран сканирования
│   │   ├── Login.tsx        # Авторизация
│   │   └── Register.tsx     # Регистрация
│   ├── components/
│   │   ├── FileList.tsx     # Таблица найденных файлов
│   │   ├── Button.tsx
│   │   └── Input.tsx
│   ├── api.ts               # Методы invoke() к Rust API
│   └── main.tsx
├── public/
└── package.json

src-tauri/                   # Rust backend
├── src/
│   └── main.rs              # Команды UI → Rust → C++
├── rust-wrapper/
│   ├── lib.rs               # FFI в C++ ядро
│   └── bindings.h
├── tauri.conf.json
└── build.rs

```

### **Механика взаимодействия UI ⇆ Backend ⇆ Ядро/Служба**

``` .text
flowchart TD
  UI["React/Svelte UI"]
  RustBackend["Rust Tauri Backend"]
  CPPCore["C++ core.dll"]
  WinService["Windows Service"]

  UI --> | invoke('start_scan') | RustBackend
  RustBackend --> | unsafe FFI | CPPCore
  UI --> | invoke('register') | RustBackend --> WinService
  UI --> | invoke('login') | RustBackend --> WinService

```

