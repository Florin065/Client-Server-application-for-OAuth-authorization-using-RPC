struct AuthRequest {
    string user_id<15>;
};

struct AuthResponse {
    string request_token<15>;
};

struct AccessTokenRequest {
    string user_id<15>;
    string request_token<15>;
    bool refresh;
};

struct RefreshTokenRequest {
    string access_token<15>;
    string refresh_token<15>;
};

struct AccessTokenResponse {
    string access_token<15>;
    string refresh_token<15>;
    int ttl;
};

struct ValidateActionRequest {
    string operation<>;
    string resource<>;
    string access_token<15>;
};

struct ValidateActionResponse {
    string response<>;
};

struct ApproveRequestToken {
    string user_id<15>;
    string request_token<15>;
};

program OAUTH_PROG {
    version OAUTH_VERS {
        AuthResponse RequestAuthorization(AuthRequest) = 1;
        AccessTokenResponse RequestAccessToken(AccessTokenRequest) = 2;
        AccessTokenResponse RefreshAccessToken(RefreshTokenRequest) = 3;
        ValidateActionResponse ValidateAction(ValidateActionRequest) = 4;
        void ApproveRequest(ApproveRequestToken) = 5;
    } = 1;
} = 0x20000001;
