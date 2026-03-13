//
// Simple JSON Parser - Replacement for nlohmann/json
// This is a simplified parser for basic JSON parameter parsing
//

#ifndef __VEREMIVNDN_SIMPLEJSON_H
#define __VEREMIVNDN_SIMPLEJSON_H

#include <string>
#include <map>
#include <sstream>
#include <stdexcept>

namespace nlohmann {

class json {
private:
    std::map<std::string, std::string> data;

    std::string trim(const std::string& str) const {
        size_t first = str.find_first_not_of(" \t\n\r\"{}");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\n\r\"{}");
        return str.substr(first, (last - first + 1));
    }

    std::string extractValue(const std::string& str) const {
        std::string trimmed = trim(str);
        // Remove quotes if present
        if (trimmed.front() == '"' && trimmed.back() == '"') {
            return trimmed.substr(1, trimmed.length() - 2);
        }
        return trimmed;
    }

public:
    static json parse(const std::string& jsonStr) {
        json j;
        std::string str = jsonStr;

        // Remove outer braces
        size_t start = str.find('{');
        size_t end = str.rfind('}');
        if (start != std::string::npos && end != std::string::npos) {
            str = str.substr(start + 1, end - start - 1);
        }

        // Simple parser for key:value pairs
        std::istringstream iss(str);
        std::string token;

        while (std::getline(iss, token, ',')) {
            size_t colonPos = token.find(':');
            if (colonPos != std::string::npos) {
                std::string key = j.trim(token.substr(0, colonPos));
                std::string value = j.trim(token.substr(colonPos + 1));

                // Remove quotes from key
                if (!key.empty() && key.front() == '"' && key.back() == '"') {
                    key = key.substr(1, key.length() - 2);
                }

                j.data[key] = value;
            }
        }

        return j;
    }

    bool contains(const std::string& key) const {
        return data.find(key) != data.end();
    }

    std::string operator[](const std::string& key) const {
        auto it = data.find(key);
        if (it != data.end()) {
            return extractValue(it->second);
        }
        return "";
    }

    std::string operator[](const char* key) const {
        return operator[](std::string(key));
    }

    operator std::string() const {
        if (!data.empty()) {
            return extractValue(data.begin()->second);
        }
        return "";
    }

    operator int() const {
        try {
            return std::stoi(extractValue(data.begin()->second));
        } catch (...) {
            return 0;
        }
    }

    operator double() const {
        try {
            return std::stod(extractValue(data.begin()->second));
        } catch (...) {
            return 0.0;
        }
    }

    operator bool() const {
        std::string val = extractValue(data.begin()->second);
        return (val == "true" || val == "1" || val == "True" || val == "TRUE");
    }

    // Helper to get typed values
    template<typename T>
    T get() const {
        return static_cast<T>(*this);
    }
};

} // namespace nlohmann

#endif // __VEREMIVNDN_SIMPLEJSON_H
