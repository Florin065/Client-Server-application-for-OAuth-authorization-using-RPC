#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <time.h>

#include "oauth.h"
#include "helper.h"

#define TOKEN_LEN 15

class OAuthServer {
    public:
        static OAuthServer& getInstance() {
            static OAuthServer instance;
            return instance;
        }

        void initServer(int argc, char *argv[]) {
            if (argc != 5) {
                std::cerr << "./server <clients file> <resources file> <approvals file> <tokens valability>" << std::endl;
                exit(EXIT_FAILURE);
            }

            // read lines from files
            auto readLines = [](const std::string &filename, std::vector<std::string> &out) {
                std::ifstream file(filename);
                if (!file) {
                    std::cerr << "Error opening file " << filename << ".\n";
                    return false;
                }

                std::string line;
                while (getline(file, line)) {
                    out.push_back(line);
                }

                return true;
            };

            // read clients and resources
            std::vector<std::string> cli, res;

            // check if files are valid
            if (!readLines(argv[1], cli) || !readLines(argv[2], res)) {
                exit(EXIT_FAILURE);
            }

            // add clients to database
            for (size_t i = 0; i < cli.size(); i++) {
                database[cli[i]] = User();
            }

            // add resources to set
            resources.insert(res.begin() + 1, res.end());
            ttl = std::atoi(argv[4]); // token lifetime 
            responses_file.open(argv[3]); // open approvals file
        }

        std::string getAuthToken(const std::string &clientID) {
            // log request
            std::cout << "BEGIN " << clientID << " AUTHZ\n";
            std::flush(std::cout);

            // verify if user exists
            if (database.find(clientID) == database.end())
                return Operation::USER_NOT_FOUND;

            // generate auth token
            auto authToken = std::string(generate_access_token((char* )clientID.c_str()));
            std::cout << "  RequestToken = " << authToken << std::endl;
            std::flush(std::cout);

            // save token in database
            database[clientID].authToken = authToken;

            return authToken;
        }

        std::tuple<std::string, std::string, int> getAccessToken(
            const std::string &clientID,
            const std::string &authToken,
            bool refresh
        ) {
            // verify if user exists and token is valid
            auto it = database.find(clientID);
            if (it == database.end() || it->second.authToken != authToken || it->second.permissions.empty()) {
                return {Operation::REQUEST_DENIED, Operation::EMPTY, 0};
            }

            // generate new tokens
            std::string accessToken = std::string(generate_access_token((char* )authToken.c_str()));
            std::string refreshToken = refresh ?
                                    std::string(generate_access_token((char* )accessToken.c_str()))
                                    : Operation::EMPTY;

            // Log new tokens
            std::cout << "  AccessToken = " << accessToken << std::endl;
            if (refresh) {
                std::cout << "  RefreshToken = " << refreshToken << std::endl;
            }
            std::flush(std::cout);

            // Save data in database
            it->second = {authToken, accessToken, refreshToken, ttl, it->second.permissions};

            return std::make_tuple(accessToken, refreshToken, ttl);
        }

        std::tuple<std::string, std::string, int> refreshAccessToken(
            const std::string& accessToken,
            const std::string& refreshToken
        ) {
            for (auto& user : database) {
                // find user by token
                if (user.second.accessToken != accessToken) continue;

                // log refresh
                std::cout << "BEGIN " << user.first << " AUTHZ REFRESH\n";
                std::flush(std::cout);

                // generate new tokens
                std::string newAccessToken = std::string(generate_access_token((char* )refreshToken.c_str()));
                std::string newRefreshToken = std::string(generate_access_token((char* )newAccessToken.c_str()));

                // log new tokens
                std::cout << "  AccessToken = " << newAccessToken << std::endl;
                std::cout << "  RefreshToken = " << newRefreshToken << std::endl;

                // update tokens in database
                user.second = {Operation::EMPTY, newAccessToken, newRefreshToken, ttl, user.second.permissions};

                // return new tokens
                return std::make_tuple(newAccessToken, newRefreshToken, ttl);
            }

            // return empty tokens if user not found
            return std::make_tuple(Operation::EMPTY, Operation::EMPTY, 0);
        }

        std::string validateAction(
            const std::string& op,
            const std::string& resource,
            const std::string& accessToken
        ) {
            // search user by token
            auto userIter = std::find_if(
                database.begin(),
                database.end(),
                [&](const auto& user) {
                    return user.second.accessToken == accessToken;
                }
            );

            // user not found or token is invalid
            if (accessToken == Operation::EMPTY || userIter->second.accessToken != accessToken) {
                printMessage(Operation::DENY, op, resource, accessToken, 0);
                return Operation::PERMISSION_DENIED;
            }

            // token expired
            if (userIter->second.ttl <= 0) {
                printMessage(Operation::DENY, op, resource, Operation::EMPTY, userIter->second.ttl);
                return Operation::TOKEN_EXPIRED;
            }

            // decrement token lifetime
            userIter->second.ttl--;

            // check if resource is available
            auto resource_available = std::find(resources.begin(), resources.end(), resource) != resources.end();
            if (!resource_available) {
                printMessage(Operation::DENY, op, resource, accessToken, userIter->second.ttl);
                return Operation::RESOURCE_NOT_FOUND;
            }

            // check if user has permission
            auto actionPerm = Operation::strToPerm(op);
            bool hasPermission = std::find_if(
                userIter->second.permissions.begin(),
                userIter->second.permissions.end(),
                [&](const auto& perm) {
                    return perm.first == resource && perm.second.find(actionPerm) != std::string::npos;
                }
            ) != userIter->second.permissions.end();

            // permission denied
            if (!hasPermission) {
                printMessage(Operation::DENY, op, resource, accessToken, userIter->second.ttl);
                return Operation::OPERATION_NOT_PERMITTED;
            }

            // permission granted
            printMessage(Operation::PERMIT, op, resource, accessToken, userIter->second.ttl);
            return Operation::PERMISSION_GRANTED;
        }

        void approveRequestToken(
            const std::string& clientID,
            const std::string& authToken
        ) {
            std::string response;
            responses_file >> response;

            // clear permissions
            database[clientID].permissions.clear();

            // check if user exists and token is valid
            if (database.find(clientID) == database.end() || database[clientID].authToken != authToken) {
                return;
            }

            std::istringstream ss(response);
            std::string token;

            // parse response
            while (std::getline(ss, token, ',')) {
                std::string resource = token;
                if (resource == Operation::NO_APPR) {
                    // skip the wildcard resource
                    std::getline(ss, token, ',');
                    continue;
                }

                // add permissions
                if (std::getline(ss, token, ',')) {
                    std::string action = token;
                    database[clientID].permissions.push_back({resource, action});
                }
            }
        }

    private:
        struct User {
            std::string authToken;
            std::string accessToken;
            std::string refreshToken;
            int ttl;
            std::vector<std::pair<std::string, std::string>> permissions;
        };

        OAuthServer() { }

        /**
         * generate alpha-numeric string based on random char*
         * 
         * INPUT: fixed length of 16
         * OUTPUT: rotated string
         * */
        char* generate_access_token(char* clientIdToken) {
            char *token = (char *) malloc(TOKEN_LEN * sizeof(char*));
            int i, key, used[TOKEN_LEN];
            int rotationIndex = TOKEN_LEN;

            memset(used, 0, TOKEN_LEN * sizeof(int));
            for (i = 0; i < TOKEN_LEN; i++) {
                do {
                    key = rand() % rotationIndex;
                } while (used[key] == 1);
                token[i] = clientIdToken[key];
                used[key] = 1;
            }
            token[TOKEN_LEN] = '\0';
            return token;
        }

        /**
         * print message to stdout
         */
        inline void printMessage(
            const std::string& type,
            const std::string& op,
            const std::string& resource,
            const std::string& accessToken,
            int tokenLifetime
        ) {
            std::cout << type << " ("
                    << op << ","
                    << resource << ","
                    << accessToken << ","
                    << tokenLifetime
                    << ")\n";

            std::flush(std::cout);
        }

    protected:
        std::unordered_set<std::string> resources;
        std::unordered_map<std::string, User> database;
        std::ifstream responses_file;
        int ttl;
};