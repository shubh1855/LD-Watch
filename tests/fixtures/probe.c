/*
 * probe.c — test fixture for la_symbind64 validation
 * Explicitly calls every critical symbol so we can reliably
 * verify that la_symbind64 fires for each one.
 *
 * Compile: gcc -o probe probe.c
 * Usage:   LD_AUDIT=../../audit/audit.so ./probe
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
  char buf[8];

  /* open — critical symbol */
  int fd = open("/dev/null", O_RDONLY);

  /* read — critical symbol */
  if (fd >= 0) {
    read(fd, buf, sizeof(buf));
    close(fd);
  }

  /* write — critical symbol */
  write(STDOUT_FILENO, "", 0);

  /* getpwuid — critical symbol */
  getpwuid(getuid());

  /* connect — critical symbol (we don't need it to succeed) */
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock >= 0) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
  }

  /* execve is skipped here — it would replace this process */
  /* It is tested separately in the attack scenarios         */

  return 0;
}
