# SMTP Library for C++

![GitHub](https://img.shields.io/github/license/lukemvc/smtp.h)

Single header SMTP client library for C++.

## Features
- Send email using the Simple Mail Transfer Protocol (SMTP).
- East-to-use syntax.
- Supports TLS connections.
- Authentication for sending emails via SMTP.
- Minimalistic, single-header design for easy usage.

## Dependencies
- [OpenSSL](https://www.openssl.org/): This library uses OpenSSL for secure TLS connections. (-l)
    - On Debian/Ubuntu: `sudo apt-get install libssl-dev`

## Usage
Include the `smtp.h` header file in your C++ project. 

```c++
#include "smtp.h"

int main() {
    Email email;
    email.from = "your_email@gmail.com";
    email.to = "recipient@example.com";
    email.subject = "Hello, SMTP Library!";
    email.body = "This is a test email sent using the SMTP library.";

    Smtp server("smtp.example.com", 587);
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
g++ -o send_email main.cpp -lssl -lcrypto
```

## Note
- This library is currently designed for Linux-based systems due to the use of sys/socket.h.
- Ensure you have OpenSSL installed on your system.

## License
This project is licensed under the MIT License - see the [LICENSE](/LICENSE) file for details.
