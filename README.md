# OAuth Server Implementation

This project is an OAuth server implementation using RPC (Remote Procedure Call). It provides functionality for user authentication, token management (access tokens, refresh tokens), and action validation, as defined in the OAuth 2.0 specification.

## Features

- **Request Authorization**: Issues an authorization request token to the user.
- **Request Access Token**: Exchanges a request token for an access token.
- **Refresh Access Token**: Refreshes the access token when it expires.
- **Validate Action**: Validates user actions based on their access token.
- **Approve Request Token**: Approves or denies the request token.

### Structures

- **AuthRequest**: Contains the `user_id` for requesting authorization.
- **AuthResponse**: Contains the `request_token` issued after requesting authorization.
- **AccessTokenRequest**: Contains `user_id`, `request_token`, and `refresh` flag to request an access token.
- **AccessTokenResponse**: Contains the `access_token`, `refresh_token`, and `ttl` (time to live) after requesting an access token.
- **RefreshTokenRequest**: Contains `access_token` and `refresh_token` for refreshing the access token.
- **ValidateActionRequest**: Contains the `operation`, `resource`, and `access_token` to validate the user's action.
- **ValidateActionResponse**: Contains the response from the server after validating the action.
- **ApproveRequestToken**: Contains `user_id` and `request_token` for approving or denying the request token.

## Technologies Used

- **RPC**: Communication between client and server is handled using Remote Procedure Calls (RPC).
- **C++**: The implementation of the server is done in C++.
- **`rpcgen`**: Code generation tool used for RPC interface definitions.
- **TCP/UDP**: The server supports both TCP and UDP protocols for communication.

## Project Structure

- **oauth.x**: Defines the RPC interface with structures and procedure declarations.
- **oauth_server.cpp**: Contains the main logic of the OAuth server, including functions to handle requests for tokens and validation.
- **oauth_server.h**: Header file containing declarations for the OAuth server's methods.
- **oauth_client.cpp**: Client-side logic for making requests to the OAuth server.
- **oauth_client.h**: Header file for the client-side implementation.
- **oauth_svc.cpp**: Contains the server-side handler functions for each RPC procedure defined in `oauth.x`.
- **oauth_clnt.cpp**: Contains client-side code for sending requests to the OAuth server.
- **oauth_xdr.cpp**: Contains the code generated by `rpcgen` to encode and decode the RPC data.
- **oauth.h**: Contains common declarations and includes for both server and client code.
- **Makefile**: Build configuration for compiling the server and client code.

## How to Build

1. Ensure you have the necessary tools installed:
   - `rpcgen`: For generating RPC code.
   - `g++`: For compiling C++ code.
   - `make`: To automate the build process.
2. Run the following commands to compile the project:

```bash
make
```

## How to Run

1. Start the OAuth server by running:

```bash
./oauth_server <clients_file> <resources_file> <approvals_file> <tokens validity>
```

- `<clients_file>`: Path to the file containing client information.
- `<resources_file>`: Path to the file containing resource information.
- `<approvals_file>`: Path to the file containing request token approvals.
- `<tokens validity>`: Time in seconds for which the access token is valid.

2. Start the OAuth client by running:

```bash
./oauth_client <server address> <operation file>
```

- `<server address>`: IP address or hostname of the OAuth server.
- `<operation file>`: Path to the file containing user operations.
