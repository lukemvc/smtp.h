# SMTP Client Library for C++

Single header SMTP client library for C++

## Features
- Send email using the Simple Mail Transfer Protocol (SMTP).
- East-to-use syntax.
- Supports TLS connections.
- Authentication for sending emails via SMTP.
- Minimalistic, single-header design for easy usage.
- Plain Text or Html email support

## Dependencies
- [OpenSSL](https://www.openssl.org/): This library uses OpenSSL for secure TLS connections and Encoding.
    - On Debian/Ubuntu: `sudo apt-get install libssl-dev`

## Usage
Include the `smtp.h` header file in your C++ project. 

```c++
#include "smtp.h"

int main() {
    Email email;
    email.from = "your_email@domiain.com"; // OR "Your Name <your_email@domain.com>"
    email.to = "recipient@example.com"; // OR "Rcpt Name <recipient@example.com>"
    email.subject = "Hello World";
    email.body = "This is a test email sent using the SMTP library.";
    // For Html:
    // email.html = R"(
    // <<!DOCTYPE html>
    // <html lang="en">
    // <body>
    //     <p>This is a test email sent using the SMTP library.</p>
    // </body>
    // </html>)"
    
    Smtp server("smtp.domain.com", 587);
    server.Ehlo();
    server.StartTls();
    server.Login("your_username", "your_password");
    server.SendMail(email);
    server.Quit();

    return 0;
}
``` 

Compile your project with OpenSSL using the `-lssl` `-lcrypto` flags.

```bash
g++ main.cpp -lssl -lcrypto
```

## Note
- This library is currently only designed for Unix-based systems due to the use of sys/socket.h.
- Ensure you have OpenSSL installed on your system.

## License
This project is licensed under the MIT License - see the [LICENSE](/LICENSE) file for details.
