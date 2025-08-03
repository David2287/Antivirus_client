//
// Created by WhySkyDie on 21.07.2025.
//


#include "signatures.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <random>
#include <iomanip>
#include <zlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <json/json.h>

#ifdef YARA_ENABLED
#include <yara.h>
#endif

namespace SignatureEngine {

    // Реализация SignatureDatabase::Impl
    class SignatureDatabase::Impl {
    public:
        ScanConfig config;
        std::vector<Signature> signatures;
        std::unordered_map<std::string, std::size_t> signature_index;
        std::unordered_map<std::string, std::vector<std::size_t>> hash_lookup;

        // Cache
        struct CacheEntry {
            std::vector<SignatureMatch> matches;
            std::chrono::steady_clock::time_point timestamp;
        };
        mutable std::unordered_map<std::string, CacheEntry> cache;
        mutable std::mutex cache_mutex;

        // Callbacks
        ProgressCallback progress_callback;
        MatchCallback match_callback;
        ErrorCallback error_callback;

        // Statistics
        mutable std::mutex stats_mutex;
        DatabaseStatistics statistics;

        // Threading
        mutable std::mutex signatures_mutex;

        Impl() = default;

        void BuildIndex() {
            std::lock_guard<std::mutex> lock(signatures_mutex);
            signature_index.clear();
            hash_lookup.clear();

            for (std::size_t i = 0; i < signatures.size(); ++i) {
                const auto& sig = signatures[i];
                signature_index[sig.id] = i;

                if (sig.type == SignatureType::HASH_MD5 ||
                    sig.type == SignatureType::HASH_SHA1 ||
                    sig.type == SignatureType::HASH_SHA256) {
                    hash_lookup[sig.pattern].push_back(i);
                }
            }

            UpdateStatistics();
        }

        void UpdateStatistics() {
            std::lock_guard<std::mutex> lock(stats_mutex);
            statistics = DatabaseStatistics{};
            statistics.total_signatures = signatures.size();

            for (const auto& sig : signatures) {
                switch (sig.type) {
                    case SignatureType::HASH_MD5:
                    case SignatureType::HASH_SHA1:
                    case SignatureType::HASH_SHA256:
                        statistics.hash_signatures++;
                        break;
                    case SignatureType::BINARY_PATTERN:
                    case SignatureType::TEXT_PATTERN:
                    case SignatureType::REGEX_PATTERN:
                        statistics.pattern_signatures++;
                        break;
                    case SignatureType::YARA_RULE:
                        statistics.yara_rules++;
                        break;
                    default:
                        break;
                }

                statistics.category_counts[sig.category]++;
                statistics.threat_level_counts[sig.threat_level]++;
            }

            statistics.last_updated = std::chrono::system_clock::now();
        }

        std::vector<SignatureMatch> CheckHashLookup(const std::string& hash,
                                                   SignatureType hash_type) {
            std::vector<SignatureMatch> matches;
            std::lock_guard<std::mutex> lock(signatures_mutex);

            auto it = hash_lookup.find(hash);
            if (it != hash_lookup.end()) {
                for (std::size_t idx : it->second) {
                    const auto& sig = signatures[idx];
                    if (sig.type == hash_type && sig.threat_level >= config.min_threat_level) {
                        SignatureMatch match;
                        match.signature_name = sig.name;
                        match.signature_id = sig.id;
                        match.type = sig.type;
                        match.threat_level = sig.threat_level;
                        match.category = sig.category;
                        match.description = sig.description;
                        match.vendor = sig.vendor;
                        match.created_date = sig.created_date;
                        match.updated_date = sig.updated_date;
                        match.aliases = sig.aliases;
                        match.metadata = sig.metadata;
                        match.confidence_score = 1.0;

                        matches.push_back(match);
                    }
                }
            }

            return matches;
        }

        std::vector<SignatureMatch> CheckPatterns(const std::vector<uint8_t>& buffer,
                                                 const std::string& file_name) {
            std::vector<SignatureMatch> matches;
            std::lock_guard<std::mutex> lock(signatures_mutex);

            for (const auto& sig : signatures) {
                if (sig.threat_level < config.min_threat_level) continue;

                bool pattern_match = false;
                std::size_t match_offset = 0;

                switch (sig.type) {
                    case SignatureType::BINARY_PATTERN:
                        pattern_match = CheckBinaryPattern(buffer, sig.binary_pattern, match_offset);
                        break;
                    case SignatureType::TEXT_PATTERN:
                        pattern_match = CheckTextPattern(buffer, sig.pattern, sig.case_sensitive, match_offset);
                        break;
                    case SignatureType::REGEX_PATTERN:
                        pattern_match = CheckRegexPattern(buffer, sig.pattern, match_offset);
                        break;
                    case SignatureType::ENTROPY_CHECK:
                        if (config.enable_entropy_check) {
                            double entropy = Utils::CalculateEntropy(buffer);
                            pattern_match = (entropy >= sig.min_entropy && entropy <= sig.max_entropy);
                        }
                        break;
                    default:
                        continue;
                }

                if (pattern_match) {
                    SignatureMatch match;
                    match.signature_name = sig.name;
                    match.signature_id = sig.id;
                    match.type = sig.type;
                    match.threat_level = sig.threat_level;
                    match.category = sig.category;
                    match.description = sig.description;
                    match.vendor = sig.vendor;
                    match.created_date = sig.created_date;
                    match.updated_date = sig.updated_date;
                    match.aliases = sig.aliases;
                    match.metadata = sig.metadata;
                    match.match_offset = match_offset;
                    match.match_length = sig.binary_pattern.size();
                    match.confidence_score = 0.95; // Паттерны менее точны чем хэши

                    matches.push_back(match);
                }
            }

            return matches;
        }

        bool CheckBinaryPattern(const std::vector<uint8_t>& buffer,
                               const std::vector<uint8_t>& pattern,
                               std::size_t& match_offset) {
            if (pattern.empty() || buffer.size() < pattern.size()) {
                return false;
            }

            auto it = std::search(buffer.begin(), buffer.end(),
                                pattern.begin(), pattern.end());
            if (it != buffer.end()) {
                match_offset = std::distance(buffer.begin(), it);
                return true;
            }

            return false;
        }

        bool CheckTextPattern(const std::vector<uint8_t>& buffer,
                             const std::string& pattern,
                             bool case_sensitive,
                             std::size_t& match_offset) {
            std::string buffer_str(buffer.begin(), buffer.end());
            std::string search_pattern = pattern;

            if (!case_sensitive) {
                std::transform(buffer_str.begin(), buffer_str.end(), buffer_str.begin(), ::tolower);
                std::transform(search_pattern.begin(), search_pattern.end(), search_pattern.begin(), ::tolower);
            }

            std::size_t pos = buffer_str.find(search_pattern);
            if (pos != std::string::npos) {
                match_offset = pos;
                return true;
            }

            return false;
        }

        bool CheckRegexPattern(const std::vector<uint8_t>& buffer,
                              const std::string& pattern,
                              std::size_t& match_offset) {
            try {
                std::string buffer_str(buffer.begin(), buffer.end());
                std::regex regex_pattern(pattern);
                std::smatch match;

                if (std::regex_search(buffer_str, match, regex_pattern)) {
                    match_offset = match.position();
                    return true;
                }
            } catch (const std::regex_error&) {
                return false;
            }

            return false;
        }

        std::string GetCacheKey(const std::string& identifier) {
            return identifier;
        }

        std::optional<std::vector<SignatureMatch>> GetFromCache(const std::string& key) {
            if (!config.use_cache) return std::nullopt;

            std::lock_guard<std::mutex> lock(cache_mutex);
            auto it = cache.find(key);
            if (it != cache.end()) {
                auto now = std::chrono::steady_clock::now();
                auto age = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.timestamp);
                if (age <= config.cache_ttl) {
                    return it->second.matches;
                } else {
                    cache.erase(it);
                }
            }

            return std::nullopt;
        }

        void PutToCache(const std::string& key, const std::vector<SignatureMatch>& matches) {
            if (!config.use_cache) return;

            std::lock_guard<std::mutex> lock(cache_mutex);
            if (cache.size() >= config.cache_max_entries) {
                // Простая стратегия - удаляем случайный элемент
                auto it = cache.begin();
                std::advance(it, std::rand() % cache.size());
                cache.erase(it);
            }

            CacheEntry entry;
            entry.matches = matches;
            entry.timestamp = std::chrono::steady_clock::now();
            cache[key] = entry;
        }
    };

    // Реализация SigDbParser::Impl
    class SigDbParser::Impl {
    public:
        std::vector<std::string> parse_errors;

        std::vector<Signature> ParseJsonFormat(const Json::Value& root) {
            std::vector<Signature> signatures;
            parse_errors.clear();

            try {
                if (!root.isObject() || !root.isMember("signatures")) {
                    parse_errors.push_back("Invalid JSON format: missing 'signatures' array");
                    return signatures;
                }

                const Json::Value& sig_array = root["signatures"];
                if (!sig_array.isArray()) {
                    parse_errors.push_back("Invalid JSON format: 'signatures' is not an array");
                    return signatures;
                }

                for (Json::ArrayIndex i = 0; i < sig_array.size(); ++i) {
                    const Json::Value& sig_obj = sig_array[i];

                    try {
                        Signature signature = ParseSignatureObject(sig_obj);
                        signatures.push_back(signature);
                    } catch (const std::exception& e) {
                        parse_errors.push_back("Error parsing signature " + std::to_string(i) + ": " + e.what());
                    }
                }

            } catch (const std::exception& e) {
                parse_errors.push_back("JSON parsing error: " + std::string(e.what()));
            }

            return signatures;
        }

        Signature ParseSignatureObject(const Json::Value& obj) {
            Signature signature;

            signature.id = obj.get("id", "").asString();
            signature.name = obj.get("name", "").asString();
            signature.description = obj.get("description", "").asString();
            signature.vendor = obj.get("vendor", "").asString();

            // Type
            std::string type_str = obj.get("type", "hash_md5").asString();
            signature.type = Utils::StringToSignatureType(type_str);

            // Threat level
            std::string level_str = obj.get("threat_level", "clean").asString();
            signature.threat_level = Utils::StringToThreatLevel(level_str);

            // Category
            std::string category_str = obj.get("category", "unknown").asString();
            signature.category = Utils::StringToThreatCategory(category_str);

            // Pattern
            signature.pattern = obj.get("pattern", "").asString();
            if (obj.isMember("binary_pattern")) {
                std::string hex_pattern = obj["binary_pattern"].asString();
                signature.binary_pattern = Utils::HexStringToBytes(hex_pattern);
            }

            // Timestamps
            if (obj.isMember("created_date")) {
                signature.created_date = Utils::ParseTimestamp(obj["created_date"].asString());
            }
            if (obj.isMember("updated_date")) {
                signature.updated_date = Utils::ParseTimestamp(obj["updated_date"].asString());
            }

            // Size constraints
            signature.min_file_size = obj.get("min_file_size", 0).asUInt64();
            signature.max_file_size = obj.get("max_file_size", UINT64_MAX).asUInt64();

            // Entropy constraints
            signature.min_entropy = obj.get("min_entropy", 0.0).asDouble();
            signature.max_entropy = obj.get("max_entropy", 8.0).asDouble();

            // Case sensitivity
            signature.case_sensitive = obj.get("case_sensitive", true).asBool();

            // Aliases
            if (obj.isMember("aliases") && obj["aliases"].isArray()) {
                for (const auto& alias : obj["aliases"]) {
                    signature.aliases.push_back(alias.asString());
                }
            }

            // File extensions
            if (obj.isMember("file_extensions") && obj["file_extensions"].isArray()) {
                for (const auto& ext : obj["file_extensions"]) {
                    signature.file_extensions.push_back(ext.asString());
                }
            }

            // Metadata
            if (obj.isMember("metadata") && obj["metadata"].isObject()) {
                for (const auto& key : obj["metadata"].getMemberNames()) {
                    signature.metadata[key] = obj["metadata"][key].asString();
                }
            }

            return signature;
        }

        Json::Value SerializeSignature(const Signature& signature) {
            Json::Value obj;

            obj["id"] = signature.id;
            obj["name"] = signature.name;
            obj["description"] = signature.description;
            obj["vendor"] = signature.vendor;
            obj["type"] = Utils::SignatureTypeToString(signature.type);
            obj["threat_level"] = Utils::ThreatLevelToString(signature.threat_level);
            obj["category"] = Utils::ThreatCategoryToString(signature.category);
            obj["pattern"] = signature.pattern;

            if (!signature.binary_pattern.empty()) {
                obj["binary_pattern"] = Utils::BytesToHexString(signature.binary_pattern);
            }

            obj["created_date"] = Utils::FormatTimestamp(signature.created_date);
            obj["updated_date"] = Utils::FormatTimestamp(signature.updated_date);
            obj["min_file_size"] = static_cast<Json::UInt64>(signature.min_file_size);
            obj["max_file_size"] = static_cast<Json::UInt64>(signature.max_file_size);
            obj["min_entropy"] = signature.min_entropy;
            obj["max_entropy"] = signature.max_entropy;
            obj["case_sensitive"] = signature.case_sensitive;

            if (!signature.aliases.empty()) {
                Json::Value aliases(Json::arrayValue);
                for (const auto& alias : signature.aliases) {
                    aliases.append(alias);
                }
                obj["aliases"] = aliases;
            }

            if (!signature.file_extensions.empty()) {
                Json::Value extensions(Json::arrayValue);
                for (const auto& ext : signature.file_extensions) {
                    extensions.append(ext);
                }
                obj["file_extensions"] = extensions;
            }

            if (!signature.metadata.empty()) {
                Json::Value metadata;
                for (const auto& pair : signature.metadata) {
                    metadata[pair.first] = pair.second;
                }
                obj["metadata"] = metadata;
            }

            return obj;
        }
    };

    // Реализация HashValidator::Impl
    class HashValidator::Impl {
    public:
        std::vector<SignatureType> supported_hash_types = {
            SignatureType::HASH_MD5,
            SignatureType::HASH_SHA1,
            SignatureType::HASH_SHA256
        };

        bool ValidateHashFormat(const std::string& hash, SignatureType type) {
            std::size_t expected_length = GetHashLength(type);
            if (hash.length() != expected_length) {
                return false;
            }

            // Проверка что строка содержит только hex символы
            return std::all_of(hash.begin(), hash.end(), [](char c) {
                return std::isxdigit(c);
            });
        }

        std::string CalculateHashImpl(const std::vector<uint8_t>& data, SignatureType hash_type) {
            switch (hash_type) {
                case SignatureType::HASH_MD5:
                    return CalculateMD5(data);
                case SignatureType::HASH_SHA1:
                    return CalculateSHA1(data);
                case SignatureType::HASH_SHA256:
                    return CalculateSHA256(data);
                default:
                    throw std::invalid_argument("Unsupported hash type");
            }
        }

        std::string CalculateMD5(const std::vector<uint8_t>& data) {
            unsigned char hash[MD5_DIGEST_LENGTH];
            MD5(data.data(), data.size(), hash);

            std::stringstream ss;
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string CalculateSHA1(const std::vector<uint8_t>& data) {
            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA1(data.data(), data.size(), hash);

            std::stringstream ss;
            for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }

        std::string CalculateSHA256(const std::vector<uint8_t>& data) {
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(data.data(), data.size(), hash);

            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            return ss.str();
        }
    };

    // Реализация основных классов

    // SignatureDatabase
    SignatureDatabase::SignatureDatabase() : pImpl(std::make_unique<Impl>()) {}

    SignatureDatabase::SignatureDatabase(const ScanConfig& config) : pImpl(std::make_unique<Impl>()) {
        pImpl->config = config;
    }

    SignatureDatabase::~SignatureDatabase() = default;

    bool SignatureDatabase::LoadDatabase(const std::filesystem::path& sigdb_path) {
        try {
            if (!std::filesystem::exists(sigdb_path)) {
                if (pImpl->error_callback) {
                    pImpl->error_callback("Database file does not exist: " + sigdb_path.string());
                }
                return false;
            }

            SigDbParser parser;
            auto signatures = parser.ParseFile(sigdb_path);

            if (signatures.empty()) {
                if (pImpl->error_callback) {
                    pImpl->error_callback("No signatures loaded from: " + sigdb_path.string());
                }
                return false;
            }

            std::lock_guard<std::mutex> lock(pImpl->signatures_mutex);
            pImpl->signatures = std::move(signatures);
            pImpl->BuildIndex();

            return true;

        } catch (const std::exception& e) {
            if (pImpl->error_callback) {
                pImpl->error_callback("Error loading database: " + std::string(e.what()));
            }
            return false;
        }
    }

    std::vector<SignatureMatch> SignatureDatabase::CheckFileHash(const std::string& hash_value,
                                                                SignatureType hash_type) {
        // Проверка кэша
        std::string cache_key = hash_value + "_" + Utils::SignatureTypeToString(hash_type);
        auto cached_result = pImpl->GetFromCache(cache_key);
        if (cached_result) {
            return *cached_result;
        }

        // Валидация хэша
        HashValidator validator;
        if (!validator.ValidateHash(hash_value, hash_type)) {
            return {};
        }

        std::string normalized_hash = validator.NormalizeHash(hash_value, hash_type);
        auto matches = pImpl->CheckHashLookup(normalized_hash, hash_type);

        // Сохранение в кэш
        pImpl->PutToCache(cache_key, matches);

        // Callback для найденных совпадений
        for (const auto& match : matches) {
            if (pImpl->match_callback) {
                pImpl->match_callback(match);
            }
        }

        return matches;
    }

    std::vector<SignatureMatch> SignatureDatabase::CheckFileContent(const std::filesystem::path& file_path) {
        try {
            if (!std::filesystem::exists(file_path)) {
                return {};
            }

            std::uintmax_t file_size = std::filesystem::file_size(file_path);
            if (file_size > pImpl->config.max_scan_size) {
                return {};
            }

            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) {
                return {};
            }

            std::vector<uint8_t> buffer(std::min(file_size, pImpl->config.pattern_buffer_size));
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

            return CheckBuffer(buffer, file_path.filename().string());

        } catch (const std::exception& e) {
            if (pImpl->error_callback) {
                pImpl->error_callback("Error checking file content: " + std::string(e.what()));
            }
            return {};
        }
    }

    std::vector<SignatureMatch> SignatureDatabase::CheckBuffer(const std::vector<uint8_t>& buffer,
                                                              const std::string& file_name) {
        if (buffer.empty()) {
            return {};
        }

        std::vector<SignatureMatch> all_matches;

        // Проверка паттернов
        if (pImpl->config.enable_pattern_matching) {
            auto pattern_matches = pImpl->CheckPatterns(buffer, file_name);
            all_matches.insert(all_matches.end(), pattern_matches.begin(), pattern_matches.end());
        }

        // Проверка хэшей всего буфера
        if (pImpl->config.enable_hash_check) {
            HashValidator validator;

            for (auto hash_type : {SignatureType::HASH_MD5, SignatureType::HASH_SHA1, SignatureType::HASH_SHA256}) {
                try {
                    std::string hash = validator.CalculateBufferHash(buffer, hash_type);
                    auto hash_matches = CheckFileHash(hash, hash_type);
                    all_matches.insert(all_matches.end(), hash_matches.begin(), hash_matches.end());
                } catch (const std::exception&) {
                    // Игнорируем ошибки вычисления хэша
                }
            }
        }

        // Удаление дубликатов
        std::sort(all_matches.begin(), all_matches.end(),
                 [](const SignatureMatch& a, const SignatureMatch& b) {
                     return a.signature_id < b.signature_id;
                 });
        all_matches.erase(std::unique(all_matches.begin(), all_matches.end(),
                                     [](const SignatureMatch& a, const SignatureMatch& b) {
                                         return a.signature_id == b.signature_id;
                                     }), all_matches.end());

        return all_matches;
    }

    DatabaseStatistics SignatureDatabase::GetStatistics() const {
        std::lock_guard<std::mutex> lock(pImpl->stats_mutex);
        return pImpl->statistics;
    }

    // SigDbParser
    SigDbParser::SigDbParser() : pImpl(std::make_unique<Impl>()) {}
    SigDbParser::~SigDbParser() = default;

    std::vector<Signature> SigDbParser::ParseFile(const std::filesystem::path& file_path) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + file_path.string());
        }

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());

        return ParseBuffer(buffer);
    }

    std::vector<Signature> SigDbParser::ParseBuffer(const std::vector<uint8_t>& buffer) {
        std::string data(buffer.begin(), buffer.end());
        return ParseString(data);
    }

    std::vector<Signature> SigDbParser::ParseString(const std::string& data) {
        Json::Value root;
        Json::Reader reader;

        if (!reader.parse(data, root)) {
            throw std::runtime_error("Invalid JSON format");
        }

        return pImpl->ParseJsonFormat(root);
    }

    // HashValidator
    HashValidator::HashValidator() : pImpl(std::make_unique<Impl>()) {}
    HashValidator::~HashValidator() = default;

    bool HashValidator::ValidateHash(const std::string& hash, SignatureType type) {
        return pImpl->ValidateHashFormat(hash, type);
    }

    SignatureType HashValidator::DetectHashType(const std::string& hash) {
        switch (hash.length()) {
            case 32: return SignatureType::HASH_MD5;
            case 40: return SignatureType::HASH_SHA1;
            case 64: return SignatureType::HASH_SHA256;
            default: return SignatureType::HASH_MD5; // default
        }
    }

    std::string HashValidator::NormalizeHash(const std::string& hash, SignatureType type) {
        std::string normalized = hash;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
        return normalized;
    }

    std::string HashValidator::CalculateFileHash(const std::filesystem::path& file_path,
                                               SignatureType hash_type) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file for hashing");
        }

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());

        return CalculateBufferHash(buffer, hash_type);
    }

    std::string HashValidator::CalculateBufferHash(const std::vector<uint8_t>& buffer,
                                                  SignatureType hash_type) {
        return pImpl->CalculateHashImpl(buffer, hash_type);
    }

    std::size_t HashValidator::GetHashLength(SignatureType type) const {
        switch (type) {
            case SignatureType::HASH_MD5: return 32;
            case SignatureType::HASH_SHA1: return 40;
            case SignatureType::HASH_SHA256: return 64;
            default: return 0;
        }
    }

    // Утилитарные функции
    namespace Utils {

        std::string ThreatLevelToString(ThreatLevel level) {
            switch (level) {
                case ThreatLevel::CLEAN: return "clean";
                case ThreatLevel::SUSPICIOUS: return "suspicious";
                case ThreatLevel::POTENTIALLY_UNWANTED: return "potentially_unwanted";
                case ThreatLevel::MALWARE: return "malware";
                case ThreatLevel::CRITICAL: return "critical";
                default: return "unknown";
            }
        }

        ThreatLevel StringToThreatLevel(const std::string& level_str) {
            if (level_str == "clean") return ThreatLevel::CLEAN;
            if (level_str == "suspicious") return ThreatLevel::SUSPICIOUS;
            if (level_str == "potentially_unwanted") return ThreatLevel::POTENTIALLY_UNWANTED;
            if (level_str == "malware") return ThreatLevel::MALWARE;
            if (level_str == "critical") return ThreatLevel::CRITICAL;
            return ThreatLevel::CLEAN;
        }

        std::string ThreatCategoryToString(ThreatCategory category) {
            switch (category) {
                case ThreatCategory::VIRUS: return "virus";
                case ThreatCategory::TROJAN: return "trojan";
                case ThreatCategory::WORM: return "worm";
                case ThreatCategory::ADWARE: return "adware";
                case ThreatCategory::SPYWARE: return "spyware";
                case ThreatCategory::ROOTKIT: return "rootkit";
                case ThreatCategory::BACKDOOR: return "backdoor";
                case ThreatCategory::KEYLOGGER: return "keylogger";
                case ThreatCategory::RANSOMWARE: return "ransomware";
                case ThreatCategory::CRYPTOCURRENCY_MINER: return "cryptocurrency_miner";
                case ThreatCategory::POTENTIALLY_UNWANTED_PROGRAM: return "potentially_unwanted_program";
                case ThreatCategory::HACKING_TOOL: return "hacking_tool";
                case ThreatCategory::JOKE_PROGRAM: return "joke_program";
                default: return "unknown";
            }
        }

        std::string SignatureTypeToString(SignatureType type) {
            switch (type) {
                case SignatureType::HASH_MD5: return "hash_md5";
                case SignatureType::HASH_SHA1: return "hash_sha1";
                case SignatureType::HASH_SHA256: return "hash_sha256";
                case SignatureType::BINARY_PATTERN: return "binary_pattern";
                case SignatureType::TEXT_PATTERN: return "text_pattern";
                case SignatureType::YARA_RULE: return "yara_rule";
                case SignatureType::REGEX_PATTERN: return "regex_pattern";
                case SignatureType::ENTROPY_CHECK: return "entropy_check";
                default: return "unknown";
            }
        }

        std::vector<uint8_t> HexStringToBytes(const std::string& hex_str) {
            std::vector<uint8_t> bytes;
            for (std::size_t i = 0; i < hex_str.length(); i += 2) {
                std::string byte_str = hex_str.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        }

        std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
            std::stringstream ss;
            for (auto byte : bytes) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            return ss.str();
        }

        double CalculateEntropy(const std::vector<uint8_t>& data) {
            if (data.empty()) return 0.0;

            std::array<int, 256> frequencies{};
            for (uint8_t byte : data) {
                frequencies[byte]++;
            }

            double entropy = 0.0;
            double data_size = static_cast<double>(data.size());

            for (int freq : frequencies) {
                if (freq > 0) {
                    double probability = static_cast<double>(freq) / data_size;
                    entropy -= probability * std::log2(probability);
                }
            }

            return entropy;
        }

        std::string GenerateSignatureId() {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, 15);

            std::stringstream ss;
            for (int i = 0; i < 32; ++i) {
                ss << std::hex << dis(gen);
            }
            return ss.str();
        }

        std::chrono::system_clock::time_point ParseTimestamp(const std::string& timestamp) {
            // Простой парсер ISO 8601 формата
            std::tm tm = {};
            std::istringstream ss(timestamp);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }

        std::string FormatTimestamp(const std::chrono::system_clock::time_point& time_point) {
            auto time_t = std::chrono::system_clock::to_time_t(time_point);
            std::tm* tm = std::gmtime(&time_t);

            std::stringstream ss;
            ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
            return ss.str();
        }
    }
}