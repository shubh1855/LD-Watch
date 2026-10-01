#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define RECORD_SIZE 1024

static uint16_t get16(const unsigned char *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint32_t get32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    int server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (server < 0)
        return 3;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path))
        return 4;
    strcpy(address.sun_path, argv[1]);
    unlink(argv[1]);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind");
        return 5;
    }
    if (listen(server, 1) < 0)
    {
        perror("listen");
        return 5;
    }

    int client = accept(server, NULL, NULL);
    if (client < 0)
        return 6;
    unsigned char record[RECORD_SIZE + 1];
    ssize_t received = recv(client, record, sizeof(record), 0);
    close(client);
    close(server);
    unlink(argv[1]);

    if (received != RECORD_SIZE || memcmp(record, "LDW1", 4) != 0 ||
        get16(record + 4) != 1 || get16(record + 6) != RECORD_SIZE ||
        record[8] < 1 || record[8] > 4 || get32(record + 12) == 0 ||
        get32(record + 16) == 0)
        return 7;

    printf("WIRE_OK type=%u pid=%u tid=%u\n", record[8],
           get32(record + 12), get32(record + 16));
    return 0;
}
