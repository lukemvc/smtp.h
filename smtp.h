/*
 * SMTP Client Library for C++
 * https://github.com/lukemvc/smtp.h
 *
 * MIT License
 *
 * Full license at the bottom of the file.
 */

#ifndef SMTP_H
#define SMTP_H

#include <iostream>
#include <cstring>
#include <utility>
#include <regex>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>


#define VALID_EHLO_STATUS 250
#define VALID_STARTTLS_STATUS 220
#define VALID_USERNAME_STATUS 334
#define VALID_AUTH_STATUS 235
#define VALID_MAIL_FROM_STATUS 250
#define VALID_RCPT_TO_STATUS 250
#define VALID_DATA_STATUS 354
#define VALID_EMAIL_CONTENT_STATUS 250
#define VALID_QUIT_RESPONSE 221

/**
 * @brief Represents an outbound email message with sender, recipient, subject, and body/html.
 */
struct Email {
    std::string from;     // Email From address
    std::string to;       // Email recipient address
    std::string subject;  // Email subject
    std::string body;     // Email body if sending plain text email
    std::string html;     // Email html if sending a html email

};

/**
 * @brief Represents an SMTP client.
 *
 * This class provides methods to establish an SMTP connection, send email messages,
 * and perform various SMTP-related operations.
 */
class Smtp {
public:
    /**
     * @brief Constructs an SMTP client instance with the specified host and port.
     *
     * @param host The SMTP server hostname or IP address.
     * @param port The port number to connect to the SMTP server.
     */
    Smtp(const std::string& host, int port);

    /**
     * @brief Destroys the SMTP client instance and closes the connection.
     */
    ~Smtp();

    /**
     * @brief Initiates the EHLO handshake with the SMTP server.
     *
     * @return The response received from the server.
     *
     * @throws std::runtime_error if EHLO response is unexpected/invalid.
     */
    std::string Ehlo();

    /**
     * @brief Initiates a secure TLS connection with the SMTP server.
     *
     * @throws std::runtime_error if the STARTTLS response is unexpected/invalid.
     */
    void StartTls();

    /**
     * @brief Logs in to the SMTP server using the provided username and password.
     *
     * @param username The SMTP server username.
     * @param password The SMTP server password.
     *
     * @throws std::runtime_error if authentication fails or if an unexpected response is received.
     *
     * @return The response received from the server.
     */
    std::string Login(const std::string& username, const std::string& password);

    /**
     * @brief Sends an email using the provided Email structure.
     *
     * @param email Email structure containing email details.
     *
     * @throws std::runtime_error if authentication is not done before sending emails or if an unexpected response is received.
     *
     * @return Server response to sending the email.
     */
    std::string SendMail(Email& email);

    /**
     * @brief Initiates the QUIT command to gracefully close the SMTP connection.
     *
     * @throws std::runtime_error if an unexpected response is received.
     *
     * @return The response received from the server.
     */
    std::string Quit();


private:
    /**
     * @brief Internal class for handling socket communication and functions for Smtp.
     *
     * This class provides methods for initializing and managing an SMTP smtp_socket_, sending SMTP commands,
     * and handling SSL/TLS connections.
     *
     */
    class SmtpSocket {
    public:
        /**
         * @brief Constructs an SMTP smtp_socket_ instance.
         *
         * Initializes the SMTP smtp_socket_ and establishes a connection to the server.
         *
         * @param host The SMTP server hostname or IP address.
         * @param port The port number to connect to the SMTP server.
         */
        SmtpSocket(std::string  host, int port);

        /**
         * @brief Destroys the SMTP smtp_socket_ instance.
         *
         * Closes the smtp_socket_ and performs SSL cleanup if SSL is enabled.
         */
        ~SmtpSocket();

        /**
         * @brief Sends an SMTP command to the server and receives a response.
         *
         * @param command The SMTP command to send.
         * @return The response received from the server.
         * @throws std::runtime_error if there is an error with the smtp_socket_ or while sending/receiving data.
         */
        std::string sendCommand(const std::string& command);

        /**
         * @brief Initializes the SSL/TLS connection with the SMTP server.
         *
         * Initializes SSL libraries, creates an SSL context and smtp_socket_, and performs the SSL handshake.
         *
         * @throws std::runtime_error if there is an error initializing SSL or performing the handshake.
         */
        void initializeSSL();

    private:
        /**
         * @brief Creates a smtp_socket_ for SMTP communication.
         *
         * Creates a smtp_socket_ and stores the file descriptor in 'sock_fd_'.
         *
         * @throws std::runtime_error if there is an error creating the smtp_socket_.
         */
        void createSocket();

        /**
         * @brief Resolves the server's IP address from its hostname.
         *
         * Resolves the IP address of the SMTP server from its hostname and stores it in 'server_ip_'.
         *
         * @param hostName The SMTP server hostname.
         * @throws std::runtime_error if there is an error resolving the IP address.
         */
        void getServerIpFromHostName(const std::string& hostName);

        /**
         * @brief Connects to the SMTP server.
         *
         * Establishes a connection to the SMTP server using the resolved server IP and port.
         *
         * @throws std::runtime_error if there is an error connecting to the server or if the connection status is invalid.
         */
        void connectServer();

        /**
         * @brief Parses the status code from a connection response.
         *
         * Extracts and returns the status code from the connection response received from the server.
         *
         * @param connectionBuffer The buffer containing the connection response.
         * @return The extracted status code.
         * @throws std::runtime_error if there is an error parsing the status code.
         */
        static int statusFromConnection(const char* connectionBuffer);

        /**
         * @brief Cleans up SSL resources and closes the SSL smtp_socket_.
         *
         * Shuts down the SSL smtp_socket_, frees SSL context and SSL smtp_socket_ resources, and performs SSL cleanup.
         */
        void cleanupSSL();

        /**
         * @brief Closes the SMTP smtp_socket_ if it is open.
         */
        void closeSocket() const;

        std::string host_name_;  // Smtp server host name. i.e smtp.domain.com
        std::string server_ip_;  // Smtp server ip address.
        int port_;               // Smtp server port.
        int sock_fd_;            // Socket file descriptor.
        bool is_ssl_;            // Represents if socket has been moved to ssl.
        SSL* ssl_socket_{};      // Pointer to SSL socket.
        SSL_CTX* ssl_context_{}; // Pointer to SSL context.
    };

    /**
     * @brief Extract email address from varying formats.
     *        Examples: "test@example.com" | "My Name <test@example.com>"
     *
     * @param content The input content containing an email address.
     * @return The extracted email address.
     */
    static std::string extractEmail(std::string& content);

    /**
     * @brief Construct MAIL FROM command.
     *
     * @param fromName The sender's email address or name.
     * @return The formatted MAIL FROM command.
     */
    static std::string makeMailFromCmd(std::string& fromName);

    /**
     * @brief Construct RCPT TO command.
     *
     * @param recipient The recipient's email address.
     * @return The formatted RCPT TO command.
     */
    static std::string makeRcptToCmd(std::string& recipient);

    /**
     * @brief Construct AUTH PLAIN command by joining credentials and base64 encoding them.
     *
     * @param username The SMTP server username.
     * @param password The SMTP server password.
     * @return The formatted AUTH PLAIN command.
     */
    static std::string makePlainAuthCommand(const std::string& username, const std::string& password);

    /**
     * @brief Perform AUTH PLAIN login
     * @param authCommand AUTH PLAIN command with base64 encoded credentials;
     * @throws std::runtime_error if authentication fails or if an unexpected response is received.
     * @return Server response to login.
     */
    std::string plainAuthLogin(std::string& authCommand);

    /**
     * @brief Perform AUTH LOGIN login
     * @param username smtp server username
     * @param password smtp server password
     * @throws std::runtime_error if authentication fails or if an unexpected response is received.
     * @return Server response to login.
     */
    std::string loginAuthLogin(const std::string& username, const std::string& password);

    /**
     * @brief Construct a formatted email from the Email struct.
     *
     * @return The formatted email content.
     */
    [[nodiscard]] std::string makeEmailContentCommand() const;

    /**
     * @brief Construct MAIL FROM command and send it to the server.
     */
    void sendMailFromCommand();

    /**
     * @brief Construct RCPT TO command and send it to the server.
     */
    void sendRcptToCommand();

    /**
     * @brief Send DATA command to the server.
     */
    void sendDataCommand();

    /**
     * @brief Send the Email content/data to the server.
     *
     * @return Server response to sending the email.
     */
    std::string sendEmailContent();

    /**
     * @brief Parses the status code from an SMTP server response.
     *
     * @param response The response received from the server.
     * @return The extracted status code.
     */
    static int statusCodeFromResponse(std::string& response);

    /**
     * @brief Parse the advertised/supported methods from the EHLO response.
     * @param response Response from issuing EHLO command.
     * @return Vector containing advertised/supported methods.
     */
    std::vector<std::string> advertisedFromEhloResponse(std::string& response);

    /**
     * @brief Encodes a string using base64 encoding.
     *
     * @param input The input string to be encoded.
     * @return The base64 encoded string.
     */
    static std::string base64_encode(const std::string& input);


    /**
     * @brief Represents the state of the SMTP client during the connection and email sending process.
     */
    enum SmtpState {
        CONNECTED,
        EHLO_SENT,
        TLS_CONFIRMED,
        AUTH_CONFIRMED,
        MAIL_FROM_SENT,
        RCPT_TO_SENT,
        DATA_COMMAND_SENT,
        EMAIL_CONTENT_SENT,
        QUIT_SENT,
    };

    SmtpSocket smtp_socket_;                      // Socket for SMTP communication
    Email sending_email_;                         // Email being sent
    SmtpState smtp_state_;                        // Current state of the SMTP client
    std::vector<std::string> advertised_methods_; // Advertised methods from server response to EHLO
    bool tls_supported_ = false;                  // Indicates if the server support TLS. Set to false as default
    std::string auth_methods_;                    // Supported auth methods from the server
};

///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                            Smtp method definitions                            //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////

Smtp::Smtp(const std::string& host, int port) : smtp_socket_(host, port), smtp_state_(CONNECTED) {}

Smtp::~Smtp() {
    if (smtp_state_ < QUIT_SENT) {
        Quit();
    }
}

std::string Smtp::Ehlo() {
    std::string ehloCmd = "EHLO [127.0.0.1]\r\n";
    std::string response = smtp_socket_.sendCommand(ehloCmd);
    advertised_methods_ = advertisedFromEhloResponse(response);
    int ehloStatus = statusCodeFromResponse(response);
    if (ehloStatus != VALID_EHLO_STATUS) {
        throw std::runtime_error("Unexpected EHLO response: " + response);
    }
    if (smtp_state_ < EHLO_SENT) {
        smtp_state_ = EHLO_SENT;
    }
    return response;
}

void Smtp::StartTls() {
    if (smtp_state_ < EHLO_SENT) {
        Ehlo();
    }
    if (smtp_state_ < TLS_CONFIRMED) {
        if (!tls_supported_) {
            throw std::runtime_error("Server doesnt support TLS.");
        }
        std::string tlsCommand = "STARTTLS\r\n";
        std::string response = smtp_socket_.sendCommand(tlsCommand);
        int startTlsStatus = statusCodeFromResponse(response);
        if (startTlsStatus != VALID_STARTTLS_STATUS) {
            throw std::runtime_error("Unexpected STARTTLS response: " + response);
        }
        smtp_socket_.initializeSSL();
        smtp_state_ = TLS_CONFIRMED;
    }
}

std::string Smtp::Login(const std::string& username, const std::string& password) {
    if (smtp_state_ < TLS_CONFIRMED) {
        throw std::runtime_error("Must use StartTls() before authenticating.");
    }
    if (smtp_state_ >= AUTH_CONFIRMED) {
        throw std::runtime_error("Attempted login while already authenticated.");
    }
    if (auth_methods_.empty()) {
        Ehlo();
    }
    std::string response;
    if (auth_methods_.find("PLAIN") != std::string::npos) {
        std::string authCommand = makePlainAuthCommand(username, password);
        response = plainAuthLogin(authCommand);
    } else if (auth_methods_.find("LOGIN") != std::string::npos) {
        response = loginAuthLogin(username, password);
    } else {
        throw std::runtime_error("server doesnt support AUTH PLAIN or AUTH LOGIN authentication methods.");
    }
    smtp_state_ = AUTH_CONFIRMED;
    return response;
}

std::string Smtp::SendMail(Email& email) {
    if (email.from.empty() || email.to.empty() || email.subject.empty()) {
        throw std::runtime_error("Fields 'from', 'to', and 'subject' are required for SendEmail.");
    }
    if (email.body.empty() && email.html.empty()) {
        throw std::runtime_error("Must set either body or html for the email.");
    }
    sending_email_ = email;
    sendMailFromCommand();
    sendRcptToCommand();
    sendDataCommand();
    std::string emailResponse = sendEmailContent();
    return emailResponse;
}

std::string Smtp::Quit() {
    std::string quitCommand = "QUIT\r\n";
    std::string response = smtp_socket_.sendCommand(quitCommand);
    int quitStatus = statusCodeFromResponse(response);
    if (quitStatus != VALID_QUIT_RESPONSE) {
        throw std::runtime_error("Unexpected quit response: " + response);
    }
    smtp_state_ = QUIT_SENT;
    return response;
}

std::string Smtp::extractEmail(std::string& content) {
    std::regex emailRegex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");
    std::smatch match;
    if (std::regex_search(content, match, emailRegex)) {
        return match.str();
    }
    throw std::runtime_error("Unable to parse email from: " + content);
}

std::string Smtp::makeMailFromCmd(std::string& fromName) {
    std::string cleanEmail = extractEmail(fromName);
    std::stringstream mailFromFormat;
    mailFromFormat << "MAIL FROM:<" << cleanEmail << ">\r\n";
    return mailFromFormat.str();

}

std::string Smtp::makeRcptToCmd(std::string& recipient) {
    std::string cleanEmail = extractEmail(recipient);
    std::stringstream rcptToFormat;
    rcptToFormat << "RCPT TO:<" << cleanEmail << ">\r\n";
    return rcptToFormat.str();
}

std::string Smtp::makePlainAuthCommand(const std::string& username, const std::string& password) {
    std::stringstream joinedCredentials;
    joinedCredentials << '\0' << username << '\0' << password ;
    std::string encodedCredentials = base64_encode(joinedCredentials.str());
    std::string authCommand = "AUTH PLAIN " + encodedCredentials + "\r\n";
    return authCommand;
}

std::string Smtp::plainAuthLogin(std::string& authCommand) {
    std::string response = smtp_socket_.sendCommand(authCommand);
    int authStatus = statusCodeFromResponse(response);
    if (authStatus != VALID_AUTH_STATUS) {
        throw std::runtime_error("Unexpected Auth response: " + response);
    }
    return response;
}

std::string Smtp::loginAuthLogin(const std::string& username, const std::string& password) {
    std::string encodedUsername = base64_encode(username);
    std::string usernameCommand = "AUTH LOGIN " + encodedUsername + "\r\n";
    std::string usernameResponse = smtp_socket_.sendCommand(usernameCommand);
    int usernameStatus = statusCodeFromResponse(usernameResponse);
    if (usernameStatus != VALID_USERNAME_STATUS){
        throw std::runtime_error("Unexpected server response to username: " + usernameResponse);
    }
    std::string encodedPassword = base64_encode(password);
    std::string passwordCommand = encodedPassword + "\r\n";
    std::string passwordResponse = smtp_socket_.sendCommand(passwordCommand);
    int passwordStatus = statusCodeFromResponse(passwordResponse);
    if (passwordStatus != VALID_AUTH_STATUS) {
        throw std::runtime_error("Unexpected server response to password: " + passwordResponse);
    }
    return passwordResponse;
}


std::string Smtp::makeEmailContentCommand() const {
    std::string emailContent;
    std::string contentType;
    if (!sending_email_.html.empty()) {
        emailContent = sending_email_.html;
        contentType = "text/html;";
    } else {
        emailContent = sending_email_.body;
        contentType = "text/plain;";
    }
    std::stringstream emailFormat;
    emailFormat << "From: " << sending_email_.from << "\r\n"
                << "To: " << sending_email_.to << "\r\n"
                << "Subject: " << sending_email_.subject << "\r\n"
                << "Content-Type: " << contentType << " charset=\"utf-8\"\r\n"
                << "Content-Transfer-Encoding: 7bit\r\n"
                << "MIME-Version: 1.0\r\n\r\n"
                << emailContent
                << "\r\n.\r\n";
    return emailFormat.str();
}

void Smtp::sendMailFromCommand() {
    std::string mailFromCmd = makeMailFromCmd(sending_email_.from);
    std::string response = smtp_socket_.sendCommand(mailFromCmd);
    int mailFromStatus = statusCodeFromResponse(response);
    if (mailFromStatus != VALID_MAIL_FROM_STATUS) {
        throw std::runtime_error("Unexpected Mail From response: " + response);
    }
    smtp_state_ = MAIL_FROM_SENT;
}

void Smtp::sendRcptToCommand() {
    std::string rcptToCmd = makeRcptToCmd(sending_email_.to);
    std::string response = smtp_socket_.sendCommand(rcptToCmd);
    int rcptToStatus = statusCodeFromResponse(response);
    if (rcptToStatus != VALID_RCPT_TO_STATUS) {
        throw std::runtime_error("Unexpected Rcpt To response: " + response);
    }
    smtp_state_ = RCPT_TO_SENT;
}

void Smtp::sendDataCommand() {
    std::string dataCommand = "DATA\r\n";
    std::string response = smtp_socket_.sendCommand(dataCommand);
    int dataStatus = statusCodeFromResponse(response);
    if (dataStatus != VALID_DATA_STATUS) {
        throw std::runtime_error("Unexpected response to DATA command: " + response);
    }
    smtp_state_ = DATA_COMMAND_SENT;
}

std::string Smtp::sendEmailContent() {
    if (smtp_state_ < DATA_COMMAND_SENT) {
        throw std::runtime_error("Invalid client state. Must issue proper command sequence before sending an email.");
    }
    std::string emailCommand = makeEmailContentCommand();
    std::string response = smtp_socket_.sendCommand(emailCommand);
    int emailContentStatus = statusCodeFromResponse(response);
    if (emailContentStatus != VALID_EMAIL_CONTENT_STATUS) {
        throw std::runtime_error("Unexpected Email Content response: " + response);
    }
    smtp_state_ = EMAIL_CONTENT_SENT;
    return response;
}

int Smtp::statusCodeFromResponse(std::string& response) {
    if (response.length() >= 3) {
        for (int i = 0; i < 3; i++) {
            if (!isdigit(response[i])) {
                throw std::runtime_error("An error occurred while parsing status code from response: " + response);
            }
        }
        return std::stoi(response.substr(0, 3));
    } else {
        throw std::runtime_error("An error occurred while parsing status code from response: " + response);
    }
}

std::vector<std::string> Smtp::advertisedFromEhloResponse(std::string& response) {
    std::vector<std::string> advertised;
    std::istringstream responseStream(response);
    std::string line;
    while (std::getline(responseStream, line, '\n')) {
        if (line.find("250") == 0) {
            while (line.back() == '\r' || line.back() == '\n') {
                line.pop_back();
            }
            std::string subStr = line.substr(4);
            advertised.push_back(subStr);
            if (subStr.find("AUTH") == 0) {
                auth_methods_ = subStr;
            } else if (subStr.find("STARTTLS") == 0) {
                tls_supported_ = true;
            }
        }
    }
    return advertised;
}

std::string Smtp::base64_encode(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input.c_str(), int(input.length()));
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
//                          SmtpSocket method definitions                        //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////

Smtp::SmtpSocket::SmtpSocket(std::string host, const int port)
    : host_name_(std::move(host)), port_(port), sock_fd_(-1), is_ssl_(false) {
    createSocket();
    connectServer();
}

Smtp::SmtpSocket::~SmtpSocket() {
    cleanupSSL();
    closeSocket();
}

std::string Smtp::SmtpSocket::sendCommand(const std::string& command) {
    if (sock_fd_ == -1) {
        throw std::runtime_error("Cannot send command. Error with smtp_socket_.");
    }
    ssize_t bytes_sent;
    if (is_ssl_) {
        if (!ssl_socket_) {
            throw std::runtime_error("Cannot send command. Error with SSL smtp_socket_.");
        }
        bytes_sent = SSL_write(ssl_socket_, command.c_str(), int(command.length()));
    } else {
        bytes_sent = send(sock_fd_, command.c_str(), command.length(), 0);
    }
    if (bytes_sent <= 0) {
        throw std::runtime_error("Error while sending command.");
    }
    char buffer[1024];
    ssize_t bytes_received;
    if (is_ssl_) {
        bytes_received = SSL_read(ssl_socket_, buffer, sizeof(buffer));
    } else {
        bytes_received = recv(sock_fd_, buffer, sizeof(buffer), 0);
    }
    if (bytes_received <= 0) {
        throw std::runtime_error("Error receiving data from server.");
    }
    buffer[bytes_received] = '\0';
    std::string socketResponse = std::string(buffer);
    while (socketResponse.back() == '\r' || socketResponse.back() == '\n') {
        socketResponse.pop_back();
    }
    return socketResponse;
}

void Smtp::SmtpSocket::initializeSSL() {
    SSL_library_init();
    ssl_context_ = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_context_) {
        throw std::runtime_error("Error initializing SSL context.");
    }
    ssl_socket_ = SSL_new(ssl_context_);
    if (!ssl_socket_) {
        throw std::runtime_error("Error creating SSL smtp_socket_.");
    }
    SSL_set_fd(ssl_socket_, sock_fd_);
    int handshake_result = SSL_connect(ssl_socket_);
    if (handshake_result != 1) {
        throw std::runtime_error("SSL/TLS handshake failed.");
    }
    is_ssl_ = true;
}

void Smtp::SmtpSocket::createSocket() {
    sock_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ == -1) {
        throw std::runtime_error("Error creating smtp_socket_: " + std::string(strerror(errno)));
    }
}

void Smtp::SmtpSocket::getServerIpFromHostName(const std::string& hostName) {
    struct addrinfo hints{};
    struct addrinfo* result;

    std::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostName.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        throw std::runtime_error("getaddrinfo of domain failed for " + hostName +": "
                                + std::string(gai_strerror(status)));
    }

    if (result != nullptr) {
        auto* addr = (struct sockaddr_in*)(result->ai_addr);
        char ipString[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ipString, INET_ADDRSTRLEN);
        freeaddrinfo(result);
        server_ip_ = ipString;
    } else {
        throw std::runtime_error("Server IP not found.");
    }
}

void Smtp::SmtpSocket::connectServer() {
    getServerIpFromHostName(host_name_);
    struct sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port_);
    serverAddress.sin_addr.s_addr = inet_addr(server_ip_.c_str());

    if (connect(sock_fd_, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        throw std::runtime_error("Error connecting to server: " + std::string(strerror(errno)));
    }

    char connectionBuffer[1024];
    ssize_t n = recv(sock_fd_, connectionBuffer, sizeof(connectionBuffer), 0);
    if (n == -1) {
        throw std::runtime_error("Error reading connection response from server: " + std::string(strerror(errno)));
    }
    connectionBuffer[n] = '\0';
    int connectionStatus = statusFromConnection(connectionBuffer);
    if (connectionStatus != 220) {
        throw std::runtime_error("Invalid connection response: " + std::string(connectionBuffer));
    }
}

int Smtp::SmtpSocket::statusFromConnection(const char* connectionBuffer) {
    std::string response = std::string(connectionBuffer);
    if (response.length() >= 3) {
        for (int i = 0; i < 3; i++) {
            if (!isdigit(response[i])) {
                throw std::runtime_error("An error occurred while parsing status code from connection response: " + response);
            }
        }
        return std::stoi(response.substr(0, 3));
    } else {
        throw std::runtime_error("An error occurred while parsing status code from connection response: " + response);
    }
}

void Smtp::SmtpSocket::cleanupSSL() {
    if (ssl_socket_) {
        SSL_shutdown(ssl_socket_);
        SSL_free(ssl_socket_);
    }
    if (ssl_context_) {
        SSL_CTX_free(ssl_context_);
    }
    ERR_free_strings();
    EVP_cleanup();
}

void Smtp::SmtpSocket::closeSocket() const {
    if (sock_fd_ != -1) {
        close(sock_fd_);
    }
}

#endif //SMTP_H

// MIT License
//
// Copyright (c) 2023 Luke Mccabe
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.