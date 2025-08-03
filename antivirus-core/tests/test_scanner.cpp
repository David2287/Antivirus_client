//
// Created by WhySkyDie on 21.07.2025.
//


#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

// Подключаем тестируемые модули (предполагая их наличие)
#include "../scanner.h"
#include "../file_utils.h"
#include "../signatures.h"
#include "../quarantine.h"
#include "../logger.h"

using namespace testing;
using namespace std::chrono_literals;

namespace AntivirusTests {

// ============================================================================
// Mock классы для зависимостей
// ============================================================================

class MockLogger {
public:
    MOCK_METHOD(void, Info, (const std::string& message), ());
    MOCK_METHOD(void, Warning, (const std::string& message), ());
    MOCK_METHOD(void, Error, (const std::string& message), ());
    MOCK_METHOD(void, Debug, (const std::string& message), ());
};

class MockSignatureDatabase {
public:
    MOCK_METHOD(bool, LoadDatabase, (const std::filesystem::path& path), ());
    MOCK_METHOD(std::vector<SignatureMatch>, CheckFileHash,
                (const std::string& hash, SignatureType type), ());
    MOCK_METHOD(std::vector<SignatureMatch>, CheckFileContent,
                (const std::filesystem::path& file_path), ());
    MOCK_METHOD(bool, IsInitialized, (), (const));
};

class MockQuarantineManager {
public:
    MOCK_METHOD(QuarantineResult, QuarantineFile,
                (const std::filesystem::path& file_path, QuarantineReason reason,
                 const std::string& detection_info), ());
    MOCK_METHOD(bool, IsInitialized, (), (const));
};

class MockFileManager {
public:
    MOCK_METHOD(bool, FileExists, (const std::filesystem::path& path), ());
    MOCK_METHOD(std::uintmax_t, GetFileSize, (const std::filesystem::path& path), ());
    MOCK_METHOD(ReadResult, ReadFile, (const std::filesystem::path& path), ());
    MOCK_METHOD(std::optional<FileInfo>, GetFileInfo, (const std::filesystem::path& path), ());
};

// ============================================================================
// Тестовые фикстуры
// ============================================================================

class ScannerTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Создание тестовой директории
        test_dir = std::filesystem::temp_directory_path() / "antivirus_test";
        std::filesystem::create_directories(test_dir);

        // Создание тестовых файлов
        CreateTestFiles();

        // Настройка конфигурации сканера
        scanner_config.scan_archives = true;
        scanner_config.scan_memory = false;
        scanner_config.max_file_size = 100 * 1024 * 1024; // 100MB
        scanner_config.scan_timeout = std::chrono::seconds{30};
        scanner_config.thread_count = 2;
        scanner_config.enable_heuristics = true;

        // Инициализация моков
        mock_logger = std::make_shared<MockLogger>();
        mock_signature_db = std::make_shared<MockSignatureDatabase>();
        mock_quarantine = std::make_shared<MockQuarantineManager>();
        mock_file_manager = std::make_shared<MockFileManager>();
    }

    void TearDown() override {
        // Очистка тестовой директории
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    void CreateTestFiles() {
        // Чистый текстовый файл
        clean_file = test_dir / "clean_file.txt";
        std::ofstream clean(clean_file);
        clean << "This is a clean text file with normal content.";
        clean.close();

        // Подозрительный файл (имитация вируса)
        virus_file = test_dir / "virus_file.exe";
        std::ofstream virus(virus_file, std::ios::binary);
        // Записываем сигнатуру PE файла + подозрительный контент
        virus << "MZ" << std::string(1000, 'X') << "VIRUS_SIGNATURE_TEST";
        virus.close();

        // Архив
        archive_file = test_dir / "test_archive.zip";
        std::ofstream archive(archive_file, std::ios::binary);
        archive << "PK" << std::string(100, 'A'); // ZIP signature
        archive.close();

        // Большой файл
        large_file = test_dir / "large_file.dat";
        std::ofstream large(large_file, std::ios::binary);
        std::string large_content(10 * 1024 * 1024, 'B'); // 10MB
        large << large_content;
        large.close();

        // Скрытый файл
        hidden_file = test_dir / ".hidden_file";
        std::ofstream hidden(hidden_file);
        hidden << "Hidden file content";
        hidden.close();
    }

protected:
    std::filesystem::path test_dir;
    std::filesystem::path clean_file;
    std::filesystem::path virus_file;
    std::filesystem::path archive_file;
    std::filesystem::path large_file;
    std::filesystem::path hidden_file;

    ScannerEngine::ScanConfig scanner_config;

    std::shared_ptr<MockLogger> mock_logger;
    std::shared_ptr<MockSignatureDatabase> mock_signature_db;
    std::shared_ptr<MockQuarantineManager> mock_quarantine;
    std::shared_ptr<MockFileManager> mock_file_manager;
};

// ============================================================================
// Тесты базовой функциональности сканера
// ============================================================================

TEST_F(ScannerTestFixture, ScannerInitialization) {
    // Arrange
    EXPECT_CALL(*mock_signature_db, IsInitialized())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_quarantine, IsInitialized())
        .WillRepeatedly(Return(true));

    // Act
    ScannerEngine::Scanner scanner(scanner_config);
    bool init_result = scanner.Initialize();

    // Assert
    EXPECT_TRUE(init_result);
    EXPECT_TRUE(scanner.IsInitialized());
}

TEST_F(ScannerTestFixture, ScannerInitializationFailure) {
    // Arrange
    EXPECT_CALL(*mock_signature_db, IsInitialized())
        .WillRepeatedly(Return(false));

    // Act
    ScannerEngine::Scanner scanner(scanner_config);
    bool init_result = scanner.Initialize();

    // Assert
    EXPECT_FALSE(init_result);
    EXPECT_FALSE(scanner.IsInitialized());
}

TEST_F(ScannerTestFixture, ScanCleanFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(Return(std::vector<SignatureMatch>{})); // Пустой результат = чистый файл

    EXPECT_CALL(*mock_signature_db, CheckFileHash(_, _))
        .WillOnce(Return(std::vector<SignatureMatch>{}));

    EXPECT_CALL(*mock_logger, Info(HasSubstr("Scanning file")))
        .Times(AtLeast(1));

    // Act
    auto result = scanner.ScanFile(clean_file);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.threat_level, ScannerEngine::ThreatLevel::CLEAN);
    EXPECT_TRUE(result.detected_threats.empty());
    EXPECT_GT(result.scan_time.count(), 0);
}

TEST_F(ScannerTestFixture, ScanInfectedFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    SignatureMatch virus_match;
    virus_match.signature_name = "Test.Virus.A";
    virus_match.threat_level = SignatureEngine::ThreatLevel::MALWARE;
    virus_match.description = "Test virus signature";

    std::vector<SignatureMatch> matches = {virus_match};

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(Return(matches));

    EXPECT_CALL(*mock_logger, Warning(HasSubstr("Threat detected")))
        .Times(AtLeast(1));

    // Act
    auto result = scanner.ScanFile(virus_file);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.threat_level, ScannerEngine::ThreatLevel::HIGH);
    EXPECT_FALSE(result.detected_threats.empty());
    EXPECT_EQ(result.detected_threats[0].signature_name, "Test.Virus.A");
}

TEST_F(ScannerTestFixture, ScanNonExistentFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);
    std::filesystem::path non_existent = test_dir / "non_existent.txt";

    // Act
    auto result = scanner.ScanFile(non_existent);

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_THAT(result.error_message, HasSubstr("File does not exist"));
}

TEST_F(ScannerTestFixture, ScanDirectoryRecursive) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillRepeatedly(Return(std::vector<SignatureMatch>{}));

    EXPECT_CALL(*mock_signature_db, CheckFileHash(_, _))
        .WillRepeatedly(Return(std::vector<SignatureMatch>{}));

    // Act
    auto result = scanner.ScanDirectory(test_dir, true);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_GT(result.files_scanned, 0);
    EXPECT_GE(result.files_scanned, 4); // Минимум 4 созданных файла
}

TEST_F(ScannerTestFixture, ScanWithFileSizeLimit) {
    // Arrange
    scanner_config.max_file_size = 1024; // 1KB лимит
    ScannerEngine::Scanner scanner(scanner_config);

    // Act
    auto result = scanner.ScanFile(large_file);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.threat_level, ScannerEngine::ThreatLevel::CLEAN);
    EXPECT_THAT(result.scan_info, HasSubstr("File too large"));
}

// ============================================================================
// Тесты асинхронного сканирования
// ============================================================================

TEST_F(ScannerTestFixture, AsyncScanFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(Return(std::vector<SignatureMatch>{}));

    std::atomic<bool> callback_called{false};
    auto callback = [&callback_called](const ScannerEngine::ScanResult& result) {
        callback_called = true;
        EXPECT_TRUE(result.success);
    };

    scanner.SetScanCallback(callback);

    // Act
    std::string scan_id = scanner.ScanFileAsync(clean_file);

    // Ждем завершения
    std::this_thread::sleep_for(100ms);

    // Assert
    EXPECT_FALSE(scan_id.empty());
    EXPECT_TRUE(callback_called);
}

TEST_F(ScannerTestFixture, CancelAsyncScan) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    // Замедляем сканирование для возможности отмены
    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(InvokeWithoutArgs([]() {
            std::this_thread::sleep_for(200ms);
            return std::vector<SignatureMatch>{};
        }));

    // Act
    std::string scan_id = scanner.ScanFileAsync(large_file);
    std::this_thread::sleep_for(50ms); // Даем время начать сканирование
    bool cancel_result = scanner.CancelScan(scan_id);

    // Assert
    EXPECT_TRUE(cancel_result);
}

// ============================================================================
// Тесты карантина
// ============================================================================

TEST_F(ScannerTestFixture, QuarantineInfectedFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);
    scanner_config.auto_quarantine = true;

    SignatureMatch virus_match;
    virus_match.signature_name = "Test.Virus.B";
    virus_match.threat_level = SignatureEngine::ThreatLevel::MALWARE;

    QuarantineResult quarantine_result;
    quarantine_result.success = true;
    quarantine_result.quarantine_id = "test_quarantine_123";

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(Return(std::vector<SignatureMatch>{virus_match}));

    EXPECT_CALL(*mock_quarantine, QuarantineFile(_, _, _))
        .WillOnce(Return(quarantine_result));

    // Act
    auto result = scanner.ScanFile(virus_file);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.threat_level, ScannerEngine::ThreatLevel::HIGH);
    EXPECT_TRUE(result.quarantined);
    EXPECT_EQ(result.quarantine_id, "test_quarantine_123");
}

// ============================================================================
// Тесты производительности
// ============================================================================

TEST_F(ScannerTestFixture, ScanPerformance) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillRepeatedly(Return(std::vector<SignatureMatch>{}));

    auto start_time = std::chrono::high_resolution_clock::now();

    // Act
    auto result = scanner.ScanFile(clean_file);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Assert
    EXPECT_TRUE(result.success);
    EXPECT_LT(duration.count(), 1000); // Сканирование должно завершиться менее чем за 1 секунду
}

TEST_F(ScannerTestFixture, ConcurrentScanning) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillRepeatedly(Return(std::vector<SignatureMatch>{}));

    std::vector<std::future<ScannerEngine::ScanResult>> futures;
    std::vector<std::filesystem::path> files = {clean_file, archive_file, hidden_file};

    // Act
    auto start_time = std::chrono::high_resolution_clock::now();

    for (const auto& file : files) {
        futures.push_back(std::async(std::launch::async, [&scanner, file]() {
            return scanner.ScanFile(file);
        }));
    }

    // Ожидание завершения всех сканирований
    std::vector<ScannerEngine::ScanResult> results;
    for (auto& future : futures) {
        results.push_back(future.get());
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Assert
    EXPECT_EQ(results.size(), 3);
    for (const auto& result : results) {
        EXPECT_TRUE(result.success);
    }

    // Параллельное сканирование должно быть быстрее последовательного
    EXPECT_LT(total_duration.count(), 2000);
}

// ============================================================================
// Тесты обработки ошибок
// ============================================================================

TEST_F(ScannerTestFixture, ScanTimeout) {
    // Arrange
    scanner_config.scan_timeout = std::chrono::milliseconds{100}; // Очень короткий таймаут
    ScannerEngine::Scanner scanner(scanner_config);

    // Имитируем долгое сканирование
    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(InvokeWithoutArgs([]() {
            std::this_thread::sleep_for(200ms);
            return std::vector<SignatureMatch>{};
        }));

    // Act
    auto result = scanner.ScanFile(large_file);

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_THAT(result.error_message, HasSubstr("timeout"));
}

TEST_F(ScannerTestFixture, ScanCorruptedFile) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillOnce(Throw(std::runtime_error("File is corrupted")));

    EXPECT_CALL(*mock_logger, Error(HasSubstr("corrupted")))
        .Times(AtLeast(1));

    // Act
    auto result = scanner.ScanFile(virus_file);

    // Assert
    EXPECT_FALSE(result.success);
    EXPECT_THAT(result.error_message, HasSubstr("corrupted"));
}

// ============================================================================
// Тесты конфигурации
// ============================================================================

TEST_F(ScannerTestFixture, ConfigurationValidation) {
    // Arrange
    ScannerEngine::ScanConfig invalid_config;
    invalid_config.thread_count = 0; // Недопустимое значение
    invalid_config.max_file_size = 0;

    // Act & Assert
    EXPECT_THROW(ScannerEngine::Scanner scanner(invalid_config), std::invalid_argument);
}

TEST_F(ScannerTestFixture, UpdateConfiguration) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    ScannerEngine::ScanConfig new_config = scanner_config;
    new_config.scan_archives = false;
    new_config.thread_count = 4;

    // Act
    scanner.UpdateConfig(new_config);
    auto retrieved_config = scanner.GetConfig();

    // Assert
    EXPECT_FALSE(retrieved_config.scan_archives);
    EXPECT_EQ(retrieved_config.thread_count, 4);
}

// ============================================================================
// Тесты статистики
// ============================================================================

TEST_F(ScannerTestFixture, StatisticsTracking) {
    // Arrange
    ScannerEngine::Scanner scanner(scanner_config);

    EXPECT_CALL(*mock_signature_db, CheckFileContent(_))
        .WillRepeatedly(Return(std::vector<SignatureMatch>{}));

    // Act
    scanner.ScanFile(clean_file);
    scanner.ScanFile(archive_file);

    auto stats = scanner.GetStatistics();

    // Assert
    EXPECT_EQ(stats.total_files_scanned, 2);
    EXPECT_EQ(stats.clean_files, 2);
    EXPECT_EQ(stats.infected_files, 0);
    EXPECT_GT(stats.total_scan_time.count(), 0);
}

// ============================================================================
// Интеграционные тесты
// ============================================================================

class ScannerIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Создание реальной тестовой среды
        test_dir = std::filesystem::temp_directory_path() / "integration_test";
        std::filesystem::create_directories(test_dir);

        // Создание реальных компонентов (без моков)
        signature_db = std::make_unique<SignatureEngine::SignatureDatabase>();
        quarantine_manager = std::make_unique<QuarantineEngine::QuarantineManager>();
        file_manager = std::make_unique<FileUtils::FileManager>();

        // Настройка сканера
        ScannerEngine::ScanConfig config;
        config.enable_real_time = false;
        config.scan_archives = true;
        config.thread_count = 1;

        scanner = std::make_unique<ScannerEngine::Scanner>(config);
    }

    void TearDown() override {
        scanner.reset();
        quarantine_manager.reset();
        signature_db.reset();
        file_manager.reset();

        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

protected:
    std::filesystem::path test_dir;
    std::unique_ptr<ScannerEngine::Scanner> scanner;
    std::unique_ptr<SignatureEngine::SignatureDatabase> signature_db;
    std::unique_ptr<QuarantineEngine::QuarantineManager> quarantine_manager;
    std::unique_ptr<FileUtils::FileManager> file_manager;
};

TEST_F(ScannerIntegrationTest, FullScanWorkflow) {
    // Arrange
    auto test_file = test_dir / "integration_test.txt";
    std::ofstream file(test_file);
    file << "Test file for integration testing";
    file.close();

    // Act
    bool init_result = scanner->Initialize();
    ASSERT_TRUE(init_result);

    auto scan_result = scanner->ScanFile(test_file);

    // Assert
    EXPECT_TRUE(scan_result.success);
    EXPECT_EQ(scan_result.threat_level, ScannerEngine::ThreatLevel::CLEAN);
}

} // namespace AntivirusTests

// ============================================================================
// Главная функция для запуска тестов
// ============================================================================

int main(int argc, char** argv) {
    // Инициализация Google Test
    ::testing::InitGoogleTest(&argc, argv);

    // Настройка вывода
    ::testing::FLAGS_gtest_color = "yes";
    ::testing::FLAGS_gtest_print_time = true;

    // Запуск всех тестов
    return RUN_ALL_TESTS();
}