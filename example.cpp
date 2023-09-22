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