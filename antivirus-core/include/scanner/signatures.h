//
// Created by WhySkyDie on 21.07.2025.
//

> ParseFile(const std::filesystem::path& file_path);
        std::vector<Signature> ParseBuffer(const std::vector<uint8_t>& buffer);
        std::vector<Signature> ParseString(const std::string& data);

        // Сериализация
        std::vector<uint8_t> SerializeSignatures(const std::vector<Signature>& signatures);
        bool SaveToFile(const std::vector<Signature>& signatures,
                       const std::filesystem::path& file_path);

        // Валидация
        bool ValidateFormat(const std::filesystem::path& file_path);
        std::vector<std::string> GetParseErrors() const;

        // Информация о формате
        std::string GetFormatVersion() const;
        std::vector<std::string> GetSupportedVersions() const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Хэш-валидатор
    class HashValidator {
    public:
        HashValidator();
        ~HashValidator();

        // Проверка хэшей
        bool ValidateHash(const std::string& hash, SignatureType type);
        SignatureType DetectHashType(const std::string& hash);
        std::string NormalizeHash(const std::string& hash, SignatureType type);

        // Вычисление хэшей
        std::string CalculateFileHash(const std::filesystem::path& file_path,
                                    SignatureType hash_type);
        std::string CalculateBufferHash(const std::vector<uint8_t>& buffer,
                                      SignatureType hash_type);

        // Утилиты
        std::vector<SignatureType> GetSupportedHashTypes() const;
        std::size_t GetHashLength(SignatureType type) const;

    private:
        class Impl;
        std::unique_ptr<Impl> pImpl;
    };

    // Утилитарные функции
    namespace Utils {
        std::string ThreatLevelToString(ThreatLevel level);
        ThreatLevel StringToThreatLevel(const std::string& level_str);

        std::string ThreatCategoryToString(ThreatCategory category);
        ThreatCategory StringToThreatCategory(const std::string& category_str);

        std::string SignatureTypeToString(SignatureType type);
        SignatureType StringToSignatureType(const std::string& type_str);

        std::vector<uint8_t> HexStringToBytes(const std::string& hex_str);
        std::string BytesToHexString(const std::vector<uint8_t>& bytes);

        double CalculateEntropy(const std::vector<uint8_t>& data);
        bool IsExecutableFile(const std::filesystem::path& file_path);

        std::string GenerateSignatureId();
        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp);
        std::string FormatTimestamp(const std::chrono::system_clock::time_point& time_point);
    }
}