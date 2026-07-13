#define _GNU_SOURCE

#include "protocol.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void start_daemon_process(void)
{
    char executable[PATH_MAX];
    char daemon_path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    char *separator;

    if (length > 0 && length < (ssize_t)sizeof(executable)) {
        executable[length] = '\0';
        separator = strrchr(executable, '/');
        if (separator != NULL) {
            *separator = '\0';
            if (snprintf(daemon_path, sizeof(daemon_path), "%s/netstatd", executable) <
                (int)sizeof(daemon_path)) {
                execl(daemon_path, daemon_path, NULL);
            }
        }
    }

    execlp("netstatd", "netstatd", NULL);
    perror("cant run netstatd");
    _exit(EXIT_FAILURE);
}

static int connect_to_daemon(void)
{
    struct sockaddr_un address;
    int fd;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        return fd;
    }
    close(fd);
    return -1;
}

static int send_cmd(const char *cmd)
{
    int fd = connect_to_daemon();

    if (fd == -1) {
        pid_t pid = fork();
        int retries = 20;

        if (pid < 0) {
            perror("fork");
            return -1;
        }
        if (pid == 0) {
            start_daemon_process();
        }

        while (retries-- > 0) {
            usleep(100000);
            fd = connect_to_daemon();
            if (fd != -1) {
                break;
            }
        }
        if (fd == -1) {
            fprintf(stderr, "netstatctl: cant connect\n");
            return -1;
        }
    }

    if (write(fd, cmd, strlen(cmd)) == -1) {
        perror("write");
        close(fd);
        return -1;
    }

    char response[MAX_RESP_LEN];
    ssize_t received;
    int command_failed = 0;
    while ((received = read(fd, response, sizeof(response) - 1)) > 0) {
        response[received] = '\0';
        if (strncmp(response, "error:", 6) == 0) {
            command_failed = 1;
        }
        fputs(response, stdout);
    }
    if (received < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    close(fd);
    return command_failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    char command[MAX_CMD_LEN] = {0};

    if (argc < 2) {
        fprintf(stderr, "use: ./netstatctl [command] [params]\n");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "start") == 0 || strcmp(argv[1], "stop") == 0) {
        if (argc != 2) {
            fprintf(stderr, "use: ./netstatctl %s\n", argv[1]);
            return EXIT_FAILURE;
        }
        snprintf(command, sizeof(command), "%s", argv[1]);
    } else if (strcmp(argv[1], "select") == 0) {
        if (argc != 4 || strcmp(argv[2], "iface") != 0) {
            fprintf(stderr, "use: ./netstatctl select iface [iface]\n");
            return EXIT_FAILURE;
        }
        snprintf(command, sizeof(command), "select iface %s", argv[3]);
    } else if (strcmp(argv[1], "show") == 0) {
        if (argc != 4 || strcmp(argv[3], "count") != 0) {
            fprintf(stderr, "use: ./netstatctl show [ip] count\n");
            return EXIT_FAILURE;
        }
        snprintf(command, sizeof(command), "show %s count", argv[2]);
    } else if (strcmp(argv[1], "stat") == 0) {
        if (argc == 2) {
            snprintf(command, sizeof(command), "stat");
        } else if (argc == 3) {
            snprintf(command, sizeof(command), "stat %s", argv[2]);
        } else {
            fprintf(stderr, "use: ./netstatctl stat [iface]\n");
            return EXIT_FAILURE;
        }
    } else if (strcmp(argv[1], "--help") == 0 && argc == 2) {
        printf("commands:\n"
               "  start                 Start sniffing\n"
               "  stop                  Stop sniffing\n"
               "  select iface [iface]  choose interface\n"
               "  show [ip] count       Get packet count for IP\n"
               "  stat [iface]         Show all stats\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return send_cmd(command) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
