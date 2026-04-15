#pragma once
#include <string>

// JSON string deðerini unescape ederek döndür
inline std::string json_unescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            switch (s[i + 1]) {
            case '"':  out += '"';  i++; break;
            case '\\': out += '\\'; i++; break;
            case 'n':  out += '\n'; i++; break;
            case 'r':  out += '\r'; i++; break;
            case 't':  out += '\t'; i++; break;
            default:   out += s[i]; break;
            }
        }
        else {
            out += s[i];
        }
    }
    return out;
}

// JSON'dan key'e ait string deðerini döndür (escape'li string'leri de okur)
inline std::string json_get(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";

    size_t colon = json.find(":", pos + pattern.size());
    if (colon == std::string::npos) return "";

    // Deðerin baþýný bul
    size_t start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos) return "";

    // String deðer
    if (json[start] == '"') {
        std::string result;
        size_t i = start + 1;
        while (i < json.size()) {
            if (json[i] == '\\' && i + 1 < json.size()) {
                switch (json[i + 1]) {
                case '"':  result += '"';  i += 2; break;
                case '\\': result += '\\'; i += 2; break;
                case 'n':  result += '\n'; i += 2; break;
                case 'r':  result += '\r'; i += 2; break;
                case 't':  result += '\t'; i += 2; break;
                default:   result += json[i]; i++; break;
                }
            }
            else if (json[i] == '"') {
                break;  // string bitti
            }
            else {
                result += json[i];
                i++;
            }
        }
        return result;
    }

    // Number veya bool deðer
    size_t end = json.find_first_of(",}]", start);
    return json.substr(start, end - start);
}

inline std::string json_resp(const std::string& status, const std::string& msg) {
    // msg içindeki özel karakterleri escape et
    std::string escaped;
    for (char c : msg) {
        switch (c) {
        case '"':  escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n";  break;
        case '\r': escaped += "\\r";  break;
        case '\t': escaped += "\\t";  break;
        default:   escaped += c;
        }
    }
    return "{\"status\":\"" + status + "\",\"msg\":\"" + escaped + "\"}";
}