/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */

#include "oauth_server.h"

AuthResponse *
requestauthorization_1_svc(AuthRequest arg1,  struct svc_req *rqstp)
{
	static AuthResponse result;

	try {
		// Get the auth token from the server
		std::string authToken = OAuthServer::getInstance().getAuthToken(arg1.user_id);
		// Set the result to the auth token received
		result.request_token = strdup(authToken.c_str());
	} catch (const std::exception& e) {
		result.request_token = strdup(Operation::ERR);
	}

	return &result;
}

AccessTokenResponse *
requestaccesstoken_1_svc(AccessTokenRequest arg1,  struct svc_req *rqstp)
{
	static AccessTokenResponse result;

	try {
		// Get the access token from the server
		auto [accessToken, refreshToken, ttl] = OAuthServer::getInstance().getAccessToken(
			arg1.user_id,
			arg1.request_token,
			arg1.refresh
		);

		// Set the result to the access token received
		result = {
			.access_token = strdup(accessToken.c_str()),
			.refresh_token = strdup(refreshToken.c_str()),
			.ttl = ttl
		};
	} catch (const std::exception& e) {
		result = {
			.access_token = strdup(Operation::ERR),
			.refresh_token = strdup(Operation::ERR),
			.ttl = 0
		};
	}

	return &result;
}

AccessTokenResponse *
refreshaccesstoken_1_svc(RefreshTokenRequest arg1,  struct svc_req *rqstp)
{
	static AccessTokenResponse result;

	try {
		// Refresh the access token
		auto [accessToken, refreshToken, ttl] = OAuthServer::getInstance().refreshAccessToken(
			arg1.access_token,
			arg1.refresh_token
		);

		// Set the result to the access token received
		result = {
			.access_token = strdup(accessToken.c_str()),
			.refresh_token = strdup(refreshToken.c_str()),
			.ttl = ttl
		};
	} catch (const std::exception& e) {
		result = {
			.access_token = strdup(Operation::ERR),
			.refresh_token = strdup(Operation::ERR),
			.ttl = 0
		};
	}

	return &result;
}

ValidateActionResponse *
validateaction_1_svc(ValidateActionRequest arg1,  struct svc_req *rqstp)
{
	static ValidateActionResponse result;

	try {
		// Validate the action
		std::string response = OAuthServer::getInstance().validateAction(
			arg1.operation,
			arg1.resource,
			arg1.access_token
		);

		// Set the result to the response received
		result.response = strdup(response.c_str());
	} catch (const std::exception& e) {
		result.response = strdup(Operation::ERR);
	}

	return &result;
}

void *
approverequest_1_svc(ApproveRequestToken arg1,  struct svc_req *rqstp)
{
	static char *result;

	try {
		// Approve the request token
		OAuthServer::getInstance().approveRequestToken(arg1.user_id, arg1.request_token);

		// Set the result to 1 if successful
		result = strdup("1");
	} catch (const std::exception& e) {
		result = strdup(Operation::NULL_CHAR);
	}

	return (void *) &result;
}
