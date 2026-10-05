#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    int server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (server < 0)
        return 3;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path))
        return 4;
    strcpy(address.sun_path, argv[1]);
    unlink(argv[1]);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(server, 1) < 0)
        return 5;
    int client = accept(server, NULL, NULL);
    if (client < 0)
        return 6;
    FILE *ready = fopen(argv[2], "w");
    if (ready)
    {
        fputs("accepted\n", ready);
        fclose(ready);
    }
    sleep(5); /* deliberately do not read from the accepted socket */
    close(client);
    close(server);
    unlink(argv[1]);
    return 0;
}
