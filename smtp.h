/*
 * SMTP Library for C++
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
#define VALID_AUTH_STATUS 235
#define VALID_MAIL_FROM_STATUS 250
#define VALID_RCPT_TO_STATUS 250
#define VALID_DATA_STATUS 354
#define VALID_EMAIL_CONTENT_STATUS 250
#define VALID_QUIT_RESPONSE 221

/**
 * @brief Represents an outbound email message with sender, recipient, subject, and body.
 */
struct Email {
    std::string from, to, subject, body;
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
    Smtp(const char* host, int port);

    /**
     * @brief Destroys the SMTP client instance and closes the connection.
     */
    ~Smtp();

    /**
     * @brief Initiates the EHLO (Extended Hello) handshake with the SMTP server.
     *
     * @return The response received from the server.
     *
     * @throws std::runtime_error if EHLO response is unexpected.
     */
    std::string Ehlo();

    /**
     * @brief Initiates a secure TLS (Transport Layer Security) connection with the SMTP server.
     *
     * @throws std::runtime_error if EHLO was not sent before using StartTls() or if the STARTTLS response is unexpected.
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
    std::string Login(const std::string &username, const std::string &password);

    /**
     * @brief Sends an email using the provided Email structure.
     *
     * @param email Pointer to the Email structure containing email details.
     *
     * @throws std::runtime_error if authentication is not done before sending emails or if an unexpected response is received.
     *
     * @return A message indicating the email has been sent.
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
     * This class provides methods for initializing and managing an SMTP smtpSocket, sending SMTP commands,
     * and handling SSL/TLS connections.
     *
     */
    class SmtpSocket {
    public:
        /**
         * @brief Constructs an SMTP smtpSocket instance.
         *
         * Initializes the SMTP smtpSocket and establishes a connection to the server.
         *
         * @param host The SMTP server hostname or IP address.
         * @param port The port number to connect to the SMTP server.
         */
        SmtpSocket(const char* host, int port);

        /**
         * @brief Destroys the SMTP smtpSocket instance.
         *
         * Closes the smtpSocket and performs SSL cleanup if SSL is enabled.
         */
        ~SmtpSocket();

        /**
         * @brief Sends an SMTP command to the server and receives a response.
         *
         * Sends the specified command to the server and returns the response received from the server.
         *
         * @param command The SMTP command to send.
         * @return The response received from the server.
         * @throws std::runtime_error if there is an error with the smtpSocket or while sending/receiving data.
         */
        std::string sendCommand(const std::string& command);

        /**
         * @brief Initializes the SSL/TLS connection with the SMTP server.
         *
         * Initializes SSL libraries, creates an SSL context and smtpSocket, and performs the SSL handshake.
         *
         * @throws std::runtime_error if there is an error initializing SSL or performing the handshake.
         */
        void initializeSSL();

    private:
        /**
         * @brief Creates a smtpSocket for SMTP communication.
         *
         * Creates a smtpSocket and stores the file descriptor in 'sock_fd_'.
         *
         * @throws std::runtime_error if there is an error creating the smtpSocket.
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
        void getServerIpFromHostName(const std::string &hostName);

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
         * @brief Cleans up SSL resources and closes the SSL smtpSocket.
         *
         * Shuts down the SSL smtpSocket, frees SSL context and SSL smtpSocket resources, and performs SSL cleanup.
         */
        void cleanupSSL();

        /**
         * @brief Closes the SMTP smtpSocket if it is open.
         */
        void closeSocket() const;

        std::string host_name_, server_ip_;
        int port_, sock_fd_;
        bool is_ssl_;
        SSL* ssl_socket_{};
        SSL_CTX* ssl_context_{};
    };

    /**
     * @brief Extract email address from varying formats.
     *        Examples: "test@example.com" | "My Name <test@example.com>"
     *
     * @param content The input content containing an email address.
     * @return The extracted email address.
     */
    static std::string extractEmail(std::string &content);

    /**
     * @brief Construct MAIL FROM command.
     *
     * @param fromName The sender's email address or name.
     * @return The formatted MAIL FROM command.
     */
    static std::string makeMailFromCmd(std::string &fromName);

    /**
     * @brief Construct RCPT TO command.
     *
     * @param recipient The recipient's email address.
     * @return The formatted RCPT TO command.
     */
    static std::string makeRcptToCmd(std::string &recipient);

    /**
     * @brief Construct Auth command by joining credentials and base64 encoding them (AUTH PLAIN).
     *
     * @param username The SMTP server username.
     * @param password The SMTP server password.
     * @return The formatted AUTH command.
     */
    static std::string makeAuthCommand(const std::string &username, const std::string &password);

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
     */
    void sendEmailContent();

    /**
     * @brief Parses the status code from an SMTP server response.
     *
     * @param response The response received from the server.
     * @return The extracted status code.
     */
    static int statusCodeFromResponse(std::string &response);

    /**
     * @brief Encodes a string using base64 encoding.
     *
     * @param input The input string to be encoded.
     * @return The base64 encoded string.
     */
    static std::string base64_encode(const std::string &input);


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

    SmtpSocket smtpSocket;  // Socket for SMTP communication
    Email sendingEmail;  // Pointer to the email being sent
    SmtpState smtpState;    // Current state of the SMTP client
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//                               Smtp method definitions
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Smtp::Smtp(const char* host, int port) : smtpSocket(host, port), smtpState(CONNECTED) {}

Smtp::~Smtp() {
    if (smtpState < QUIT_SENT) {
        Quit();
    }
}

std::string Smtp::Ehlo() {
    std::string ehloCmd = "EHLO hello.com\r\n";
    std::string response = smtpSocket.sendCommand(ehloCmd);
    int ehloStatus = statusCodeFromResponse(response);
    if (ehloStatus != VALID_EHLO_STATUS) {
        throw std::runtime_error("Unexpected EHLO response: " + response);
    }
    if (smtpState < EHLO_SENT) {
        smtpState = EHLO_SENT;
    }
    return response;
}

void Smtp::StartTls() {
    if (smtpState < EHLO_SENT) {
        throw std::runtime_error("Must use Ehlo() before using StartTls()");
    }
    if (smtpState < TLS_CONFIRMED) {
        std::string tlsCommand = "STARTTLS\r\n";
        std::string response = smtpSocket.sendCommand(tlsCommand);
        int startTlsStatus = statusCodeFromResponse(response);
        if (startTlsStatus != VALID_STARTTLS_STATUS) {
            throw std::runtime_error("Unexpected STARTTLS response: " + response);
        }
        smtpSocket.initializeSSL();
        smtpState = TLS_CONFIRMED;
    }
}

std::string Smtp::Login(const std::string &username, const std::string &password) {
    if (smtpState < TLS_CONFIRMED) {
        throw std::runtime_error("Must use StartTls() before authenticating.");
    }
    if (smtpState >= AUTH_CONFIRMED) {
        throw std::runtime_error("Attempted login while already authenticated.");
    }
    std::string authCommand = makeAuthCommand(username, password);
    std::string response = smtpSocket.sendCommand(authCommand);
    int authStatus = statusCodeFromResponse(response);
    if (authStatus != VALID_AUTH_STATUS) {
        throw std::runtime_error("Unexpected Auth response: " + response);
    }
    smtpState = AUTH_CONFIRMED;
    return response;
}

std::string Smtp::SendMail(Email& email) {
    if (email.from.empty() || email.to.empty() || email.subject.empty() || email.body.empty()) {
        throw std::runtime_error("All Email fields (from, to, subject, or body) are required for SendEmail.");
    }
    sendingEmail = email;
    sendMailFromCommand();
    sendRcptToCommand();
    sendDataCommand();
    sendEmailContent();
    return "Email Sent.";
}

std::string Smtp::Quit() {
    std::string quitCommand = "QUIT\r\n";
    std::string response = smtpSocket.sendCommand(quitCommand);
    int quitStatus = statusCodeFromResponse(response);
    if (quitStatus != VALID_QUIT_RESPONSE) {
        throw std::runtime_error("Unexpected quit response: " + response);
    }
    smtpState = QUIT_SENT;
    return response;
}

std::string Smtp::extractEmail(std::string &content) {
    std::regex emailRegex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");
    std::smatch match;
    if (std::regex_search(content, match, emailRegex)) {
        return match.str();
    }
    throw std::runtime_error("Unable to parse email from: " + content);
}

std::string Smtp::makeMailFromCmd(std::string &fromName) {
    std::string cleanEmail = extractEmail(fromName);
    std::stringstream mailFromFormat;
    mailFromFormat << "MAIL FROM:<" << cleanEmail << ">\r\n";
    return mailFromFormat.str();

}

std::string Smtp::makeRcptToCmd(std::string &recipient) {
    std::string cleanEmail = extractEmail(recipient);
    std::stringstream rcptToFormat;
    rcptToFormat << "RCPT TO:<" << cleanEmail << ">\r\n";
    return rcptToFormat.str();
}

std::string Smtp::makeAuthCommand(const std::string &username, const std::string &password) {
    std::stringstream joinedCredentials;
    joinedCredentials << '\0' << username << '\0' << password ;
    std::string encodedCredentials = base64_encode(joinedCredentials.str());
    std::stringstream authCommandFormat;
    authCommandFormat << "AUTH PLAIN " << encodedCredentials << "\r\n";
    return authCommandFormat.str();
}

std::string Smtp::makeEmailContentCommand() const {
    std::stringstream emailFormat;
    emailFormat << "From: " << sendingEmail.from << "\r\n" << "To: " << sendingEmail.to << "\r\n"
                << "Subject: " << sendingEmail.subject << "\r\n"
                << "Content-Type: text/plain; charset=\"utf-8\"\r\n""Content-Transfer-Encoding: 7bit\r\n"
                << "MIME-Version: 1.0\r\n\r\n" << sendingEmail.body << "\r\n.\r\n";
    return emailFormat.str();
}

void Smtp::sendMailFromCommand() {
    std::string mailFromCmd = makeMailFromCmd(sendingEmail.from);
    std::string response = smtpSocket.sendCommand(mailFromCmd);
    int mailFromStatus = statusCodeFromResponse(response);
    if (mailFromStatus != VALID_MAIL_FROM_STATUS) {
        throw std::runtime_error("Unexpected Mail From response: " + response);
    }
    smtpState = MAIL_FROM_SENT;
}

void Smtp::sendRcptToCommand() {
    std::string rcptToCmd = makeRcptToCmd(sendingEmail.to);
    std::string response = smtpSocket.sendCommand(rcptToCmd);
    int rcptToStatus = statusCodeFromResponse(response);
    if (rcptToStatus != VALID_RCPT_TO_STATUS) {
        throw std::runtime_error("Unexpected Rcpt To response: " + response);
    }
    smtpState = RCPT_TO_SENT;
}

void Smtp::sendDataCommand() {
    std::string dataCommand = "DATA\r\n";
    std::string response = smtpSocket.sendCommand(dataCommand);
    int dataStatus = statusCodeFromResponse(response);
    if (dataStatus != VALID_DATA_STATUS) {
        throw std::runtime_error("Unexpected response to DATA command: " + response);
    }
    smtpState = DATA_COMMAND_SENT;
}

void Smtp::sendEmailContent() {
    if (smtpState < DATA_COMMAND_SENT) {
        throw std::runtime_error("Invalid client state. Must issue proper command sequence before sending an email.");
    }
    std::string emailCommand = makeEmailContentCommand();
    std::string response = smtpSocket.sendCommand(emailCommand);
    int emailContentStatus = statusCodeFromResponse(response);
    if (emailContentStatus != VALID_EMAIL_CONTENT_STATUS) {
        throw std::runtime_error("Unexpected Email Content response: " + response);
    }
    smtpState = EMAIL_CONTENT_SENT;
}

int Smtp::statusCodeFromResponse(std::string &response) {
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

std::string Smtp::base64_encode(const std::string &input) {
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//                            SmtpSocket method definitions
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Smtp::SmtpSocket::SmtpSocket(const char *host, const int port) : host_name_(host), port_(port), sock_fd_(-1), is_ssl_(false) {
    createSocket();
    connectServer();
}

Smtp::SmtpSocket::~SmtpSocket() {
    cleanupSSL();
    closeSocket();
}

std::string Smtp::SmtpSocket::sendCommand(const std::string &command) {
    if (sock_fd_ == -1) {
        throw std::runtime_error("Cannot send command. Error with smtpSocket.");
    }
    ssize_t bytes_sent;
    if (is_ssl_) {
        if (!ssl_socket_) {
            throw std::runtime_error("Cannot send command. Error with SSL smtpSocket.");
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
    return buffer;
}

void Smtp::SmtpSocket::initializeSSL() {
    SSL_library_init();
    ssl_context_ = SSL_CTX_new(SSLv23_client_method());
    if (!ssl_context_) {
        throw std::runtime_error("Error initializing SSL context.");
    }
    ssl_socket_ = SSL_new(ssl_context_);
    if (!ssl_socket_) {
        throw std::runtime_error("Error creating SSL smtpSocket.");
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
        throw std::runtime_error("Error creating smtpSocket: " + std::string(strerror(errno)));
    }
}

void Smtp::SmtpSocket::getServerIpFromHostName(const std::string &hostName) {
    struct addrinfo hints{};
    struct addrinfo* result;

    std::memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostName.c_str(), nullptr, &hints, &result);
    if (status != 0) {
        throw std::runtime_error("getaddrinfo failed: " + std::string(gai_strerror(status)));
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
        throw std::runtime_error("Invalid connection status. Expected 220 but got: " + std::to_string(connectionStatus));
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