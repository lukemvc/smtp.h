#include "smtp.h"

int main() {
    Email email;
    email.from = "Test <Test@domain.com";
    email.to = "Friend <friend@dexample.com>";
    email.subject = "Testing";
    email.body = "Hello World!";

    Smtp server("smtp.domain.com", 587);
    server.Ehlo();
    server.StartTls();
    server.Login("test@domain.com", "password123");
    server.SendMail(email);
    server.Quit();
    return 0;
}