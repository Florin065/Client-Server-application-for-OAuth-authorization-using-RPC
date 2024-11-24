#pragma once

#include <string>

struct Operation {
    // Define options for the operation
    static constexpr const char* USER_NOT_FOUND = "USER_NOT_FOUND";
    static constexpr const char* REQUEST_DENIED = "REQUEST_DENIED";
    static constexpr const char* PERMISSION_GRANTED = "PERMISSION_GRANTED";
    static constexpr const char* PERMISSION_DENIED = "PERMISSION_DENIED";
    static constexpr const char* TOKEN_EXPIRED = "TOKEN_EXPIRED";
    static constexpr const char* TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND";
    static constexpr const char* RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND";
    static constexpr const char* OPERATION_NOT_PERMITTED = "OPERATION_NOT_PERMITTED";
    static constexpr const char* ERR = "ERR";
    static constexpr const char* EMPTY = "";
    static constexpr const char* NO_APPR = "*";
    static constexpr const char* NULL_CHAR = "\0";
    static constexpr const char* DENY = "DENY";
    static constexpr const char* PERMIT = "PERMIT";

    // function to convert string to permission
    static const char* strToPerm(const std::string& str) {
        static const std::unordered_map<std::string, const char*> operationMap = {
            {"REQUEST", "-"},
            {"READ", "R"},
            {"INSERT", "I"},
            {"MODIFY", "M"},
            {"DELETE", "D"},
            {"EXECUTE", "X"}
        };

        auto it = operationMap.find(str);
        if (it != operationMap.end()) {
            return it->second;
        }
        return "-"; // default permission
    }
};

