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