#define _GNU_SOURCE

#include "protocol.h"
#include "sniff.h"
#include "stats.h"

#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static char current_iface[IF_NAMESIZE] = "eth0";
static char stats_db_path[PATH_MAX];
static volatile sig_atomic_t stop_requested;

static void signal_handler(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void configure_stats_path(void)
{
    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    char *separator;

    if (length <= 0 || length >= (ssize_t)sizeof(executable)) {
        snprintf(stats_db_path, sizeof(stats_db_path), "data/stats.db");
        return;
    }

    executable[length] = '\0';
    separator = strrchr(executable, '/');
    if (separator == NULL) {
        snprintf(stats_db_path, sizeof(stats_db_path), "data/stats.db");
        return;
    }

    *separator = '\0';
    if (snprintf(stats_db_path, sizeof(stats_db_path), "%s/data/stats.db", executable) >=
        (int)sizeof(stats_db_path)) {
        snprintf(stats_db_path, sizeof(stats_db_path), "data/stats.db");
    }
}

static void save_stats(void)
{
    if (stats_save(stats_db_path) != 0) {
        fprintf(stderr, "cant save stats to %s\n", stats_db_path);
    }
}

static int send_response(int client_fd, const char *response)
{
    size_t length = strlen(response);
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = write(client_fd, response + sent, length - sent);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static void handle_command(const char *command, char *response, size_t response_size)
{
    char iface[IF_NAMESIZE];
    char ip[INET_ADDRSTRLEN];
    char word[16];
    char extra;
    struct in_addr address;

    if (strcmp(command, "start") == 0) {
        if (sniff_open(current_iface) == 0) {
            snprintf(response, response_size, "ok: sniffing %s\n", current_iface);
        } else {
            snprintf(response, response_size, "error: cant sniff %s\n", current_iface);
        }
    } else if (strcmp(command, "stop") == 0) {
        sniff_close();
        save_stats();
        snprintf(response, response_size, "ok: sniffing stopped\n");
    } else if (strncmp(command, "select iface ", 13) == 0) {
        if (sscanf(command, "select iface %15s %c", iface, &extra) != 1) {
            snprintf(response, response_size, "error: use select iface [iface]\n");
        } else if (if_nametoindex(iface) == 0) {
            snprintf(response, response_size, "error: no such iface: %s\n", iface);
        } else {
            int was_running = sniff_fd() != -1;
            if (was_running) {
                sniff_close();
            }
            strcpy(current_iface, iface);
            if (was_running && sniff_open(current_iface) != 0) {
                snprintf(response, response_size, "error: cant sniff %s\n",
                         current_iface);
            } else {
                snprintf(response, response_size, "ok: iface %s\n", current_iface);
            }
        }
    } else if (strcmp(command, "stat") == 0) {
        stats_format_all(response, response_size);
    } else if (strncmp(command, "show ", 5) == 0) {
        if (sscanf(command, "show %45s %15s %c", ip, word, &extra) != 2 ||
            strcmp(word, "count") != 0 || inet_pton(AF_INET, ip, &address) != 1) {
            snprintf(response, response_size, "error: use show [ip] count\n");
        } else {
            snprintf(response, response_size, "%s %llu\n", ip,
                     (unsigned long long)stats_get_total_count(ip));
        }
    } else if (strncmp(command, "stat ", 5) == 0) {
        if (sscanf(command, "stat %31s %c", iface, &extra) != 1) {
            snprintf(response, response_size, "error: use stat [iface]\n");
        } else {
            stats_format_iface(iface, response, response_size);
        }
    } else if (strcmp(command, "--help") == 0) {
        snprintf(response, response_size,
                 "usage:\n"
                 "  start\n"
                 "  stop\n"
                 "  show [ip] count\n"
                 "  select iface [iface]\n"
                 "  stat [iface]\n"
                 "  --help\n");
    } else {
        snprintf(response, response_size, "error: unknown command: %s\n", command);
    }
}

int main(void)
{
    int server_fd;
    struct sockaddr_un address;
    struct sigaction action;
    time_t last_save;

    configure_stats_path();
    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    unlink(SOCKET_PATH);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
        listen(server_fd, 5) == -1) {
        perror("daemon socket setup");
        close(server_fd);
        unlink(SOCKET_PATH);
        return EXIT_FAILURE;
    }

    if (chmod(SOCKET_PATH, 0666) == -1) {
        perror("chmod");
        close(server_fd);
        unlink(SOCKET_PATH);
        return EXIT_FAILURE;
    }

    if (stats_load(stats_db_path) != 0) {
        fprintf(stderr, "cant load stats from %s\n", stats_db_path);
    }
    last_save = time(NULL);

    while (!stop_requested) {
        struct pollfd descriptors[2];
        nfds_t descriptor_count = 1;
        int poll_result;
        time_t now = time(NULL);

        descriptors[0].fd = server_fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        if (sniff_fd() != -1) {
            descriptors[descriptor_count].fd = sniff_fd();
            descriptors[descriptor_count].events = POLLIN;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }

        poll_result = poll(descriptors, descriptor_count, 1000);

        if (now - last_save >= STATS_SAVE_INTERVAL) {
            save_stats();
            last_save = now;
        }
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        if (poll_result > 0) {
            if (descriptors[0].revents & POLLIN) {
                int client_fd = accept(server_fd, NULL, NULL);
                if (client_fd == -1) {
                    if (errno != EINTR) {
                        perror("accept");
                    }
                } else {
                    char command[MAX_CMD_LEN];
                    char *response = calloc(1, MAX_RESP_LEN);
                    ssize_t received = read(client_fd, command, sizeof(command) - 1);

                    if (response != NULL) {
                        if (received > 0) {
                            command[received] = '\0';
                            command[strcspn(command, "\n")] = '\0';
                            handle_command(command, response, MAX_RESP_LEN);
                            send_response(client_fd, response);
                        }
                        free(response);
                    }
                    close(client_fd);
                }
            }

            if (descriptor_count == 2 && descriptors[1].revents & POLLIN) {
                if (sniff_handle_packet() != 0) {
                    sniff_close();
                }
            }
        }
    }

    sniff_close();
    save_stats();
    stats_cleanup();
    close(server_fd);
    unlink(SOCKET_PATH);
    return EXIT_SUCCESS;
}
