#define _GNU_SOURCE

#include "stats.h"

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    GHashTable *interfaces;
    guint64 total;
} IpStats;

typedef struct {
    char *buffer;
    const char *ip;
    size_t size;
    size_t used;
    const char *iface;
} FormatContext;

static GTree *statistics;

static gint compare_ip(gconstpointer left, gconstpointer right, gpointer unused)
{
    (void)unused;
    return strcmp(left, right);
}

static void free_ip_stats(gpointer data)
{
    IpStats *stats = data;
    g_hash_table_destroy(stats->interfaces);
    g_free(stats);
}

static int valid_ip(const char *ip)
{
    struct in_addr address;
    return ip != NULL && inet_pton(AF_INET, ip, &address) == 1;
}

static IpStats *get_ip_stats(const char *ip, int create)
{
    IpStats *stats = g_tree_lookup(statistics, ip);

    if (stats == NULL && create) {
        stats = g_new0(IpStats, 1);
        stats->interfaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_tree_insert(statistics, g_strdup(ip), stats);
    }
    return stats;
}

static int add_count(const char *iface, const char *ip, guint64 count)
{
    IpStats *stats;
    guint64 *value;

    if (iface == NULL || strlen(iface) >= IF_NAMESIZE || !valid_ip(ip)) {
        return -1;
    }
    stats = get_ip_stats(ip, 1);
    value = g_hash_table_lookup(stats->interfaces, iface);
    if (value == NULL) {
        value = g_new(guint64, 1);
        *value = count;
        g_hash_table_insert(stats->interfaces, g_strdup(iface), value);
    } else {
        *value += count;
    }
    stats->total += count;
    return 0;
}

int stats_increment(const char *iface, const char *ip)
{
    return add_count(iface, ip, 1);
}

uint64_t stats_get_count(const char *iface, const char *ip)
{
    IpStats *stats;
    guint64 *value;

    if (!valid_ip(ip) || iface == NULL || statistics == NULL) {
        return 0;
    }
    stats = get_ip_stats(ip, 0);
    value = stats == NULL ? NULL : g_hash_table_lookup(stats->interfaces, iface);
    return value == NULL ? 0 : *value;
}

uint64_t stats_get_total_count(const char *ip)
{
    IpStats *stats;
    if (!valid_ip(ip) || statistics == NULL) {
        return 0;
    }
    stats = get_ip_stats(ip, 0);
    return stats == NULL ? 0 : stats->total;
}

static void append(FormatContext *context, const char *text)
{
    size_t length = strlen(text);
    if (context->used >= context->size - 1) {
        return;
    }
    if (length > context->size - context->used - 1) {
        length = context->size - context->used - 1;
    }
    memcpy(context->buffer + context->used, text, length);
    context->used += length;
    context->buffer[context->used] = '\0';
}

static void format_interface(gpointer key, gpointer value, gpointer data)
{
    char line[128];
    FormatContext *context = data;

    if (context->iface != NULL && strcmp(context->iface, key) != 0) {
        return;
    }
    snprintf(line, sizeof(line), "%s %s %llu\n", (char *)key,
             context->ip, (unsigned long long)*(guint64 *)value);
    append(context, line);
}

static gboolean format_ip(gpointer key, gpointer value, gpointer data)
{
    FormatContext *context = data;
    char ip[INET_ADDRSTRLEN];

    strncpy(ip, key, sizeof(ip));
    ip[sizeof(ip) - 1] = '\0';
    context->ip = ip;
    g_hash_table_foreach(((IpStats *)value)->interfaces, format_interface, context);
    return FALSE;
}

static int format_stats(const char *iface, char *buffer, size_t size)
{
    FormatContext context = { buffer, NULL, size, 0, iface };

    if (buffer == NULL || size < 2) {
        return -1;
    }
    buffer[0] = '\0';
    if (statistics != NULL) {
        g_tree_foreach(statistics, format_ip, &context);
    }
    if (context.used == 0) {
        snprintf(buffer, size, iface == NULL ? "no stats collected\n" :
                 "no stats for iface %s\n", iface == NULL ? "" : iface);
    }
    return 0;
}

int stats_format_all(char *buffer, size_t size)
{
    return format_stats(NULL, buffer, size);
}

int stats_format_iface(const char *iface, char *buffer, size_t size)
{
    return format_stats(iface, buffer, size);
}

static gboolean save_ip(gpointer key, gpointer value, gpointer data)
{
    FILE *file = data;
    IpStats *stats = value;
    GHashTableIter iterator;
    gpointer iface, count;

    g_hash_table_iter_init(&iterator, stats->interfaces);
    while (g_hash_table_iter_next(&iterator, &iface, &count)) {
        fprintf(file, "%s %s %llu\n", (char *)iface, (char *)key,
                (unsigned long long)*(guint64 *)count);
    }
    return FALSE;
}

int stats_save(const char *path)
{
    char temp[4096];
    FILE *file;
    int result = 1;

    if (path == NULL || snprintf(temp, sizeof(temp), "%s.tmp", path) >= (int)sizeof(temp)) {
        return -1;
    }
    file = fopen(temp, "w");
    if (file == NULL) {
        return -1;
    }
    if (statistics != NULL) {
        g_tree_foreach(statistics, save_ip, file);
    }
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) {
        result = 0;
    }
    if (fclose(file) != 0) {
        result = 0;
    }
    if (result && rename(temp, path) == 0) {
        return 0;
    }
    unlink(temp);
    unlink(temp);
    return -1;
}

void stats_cleanup(void)
{
    if (statistics != NULL) {
        g_tree_destroy(statistics);
    }
    statistics = g_tree_new_full(compare_ip, NULL, g_free, free_ip_stats);
}

int stats_load(const char *path)
{
    FILE *file;
    char line[128], iface[IF_NAMESIZE], ip[INET_ADDRSTRLEN];
    unsigned long long count;

    stats_cleanup();
    file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? 0 : -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "%15s %45s %llu", iface, ip, &count) == 3 && count != 0) {
            add_count(iface, ip, count);
        }
    }
    return fclose(file) == 0 ? 0 : -1;
}
