#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

#include "pal_enclave.h"
#include "pal_error.h"
#include "pal_log.h"
#include "enclave_cache.h"

#define EPM_DIR "/run/epm"
#define EPM_SOCKET_PATH EPM_DIR"/epm.sock"

#define EPM_GET_CMD_MSG "g"
#define EPM_SET_CMD_MSG "s"
#define EPM_CMD_MSG_LEN 1

#define MAX_RANGES 200

struct enclave_range {
    uint64_t addr;
    uint64_t size;
    union {
        struct {
            uint32_t r: 1;
            uint32_t w: 1;
            uint32_t x: 1;
        };
        uint32_t prot;
    };
    union {
        struct {
            uint32_t private: 1;
            uint32_t shared: 1;
        };
        uint32_t flags;
    };
};

struct enclave_info_hdr {
    uint32_t id;
    uint32_t nr_range;
};
struct enclave_info {
    union {
        struct enclave_info_hdr hdr;
        struct {
            uint32_t id;
            uint32_t nr_range;
        };
    };
    struct enclave_range ranges[MAX_RANGES];
};

static int enclave_cache_fd = -1;
static struct enclave_info enclave_cache_info;

int new_unix_socket() {
    return socket(AF_UNIX, SOCK_STREAM, 0);
}

int new_unix_socket_connect(char *sock_path) {
    int sock = new_unix_socket();
    if (sock < 0) {
        return sock;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        close(sock);
        PAL_INFO("return value is %d", ret);
        return ret;
    }

    return sock;
}

int new_unix_socket_bind_listen(char *sock_path) {
    int ret = new_unix_socket();
    if (ret < 0) {
        goto error;
    }
    int sock = ret;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        goto close_return;
    }

    ret = listen(sock, 100);
    if (ret < 0) {
        goto close_return;
    }

    return sock;

close_return:
    close(sock);
error:
    return ret;
}

int recv_fd(char *sock_path) {
    int ret;

    ret = new_unix_socket_bind_listen(sock_path);
    if (ret < 0) {
        goto error;
    }
    int fd_sock = ret;

    struct msghdr msg = {0};
    struct iovec io;
    char buf[100];
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    io.iov_base = buf;
    io.iov_len = 100;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ret = recvmsg(fd_sock, &msg, 0);
    if (ret < 0) {
        goto close_return;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
        goto close_return;
    }

    return *(int *)CMSG_DATA(cmsg);

close_return:
    close(fd_sock);
error:
    return ret;
}

int send_fd(char *sock_path, int fd) {
    int ret;

    ret = new_unix_socket_connect(EPM_SOCKET_PATH);
    if (ret < 0) {
        goto error;
    }
    int fd_sock = ret;

    struct msghdr msg = {0};
    struct iovec io;
    char buf[1] = {' '};
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    io.iov_base = buf;
    io.iov_len = 1;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd;

    ret = sendmsg(fd_sock, &msg, 0);
    if (ret < 0) {
        goto close_return;
    }

    return 0;

close_return:
    close(fd_sock);
error:
    return ret;
}

int map_one_enclave_range(int efd, struct enclave_range *er) {
    int prot = 0;
    if (er->r) { prot |= PROT_READ; }
    if (er->w) { prot |= PROT_WRITE; }
    if (er->x) { prot |= PROT_EXEC; }

    int flags = 0;
    if (er->private) { flags |= MAP_PRIVATE; }
    if (er->shared) { flags |= MAP_SHARED; }

    int64_t ret = (int64_t)mmap((void *)er->addr, er->size, prot, flags, efd, 0);
    if (ret < 0) { return ret; }

    return 0;
}

int map_enclave(int efd, struct enclave_info *einfo) {
    for (int i = 0; i < einfo->nr_range; i++) {
        if (map_one_enclave_range(efd, &einfo->ranges[i]) < 0) { return -1; }
    }
    return 0;
}

int unmap_enclave(int efd, struct enclave_info *einfo) {
    for (int i = 0; i < einfo->nr_range; i++) {
        if (munmap((void *)einfo->ranges[i].addr, einfo->ranges[i].size) < 0) { return -1; }
    }

    return 0;
}

void print_enclave_info_header(struct enclave_info_hdr *hdr) {
    PAL_INFO("EINFO Header: ID %08x nr_ranges %d", hdr->id, hdr->nr_range);
}

void print_one_range(struct enclave_range *range) {
    char prot[10] = {0}, *flags;
    prot[0] = range->r ? 'r' : '-';
    prot[1] = range->w ? 'w' : '-';
    prot[2] = range->x ? 'x' : '-';
    if (range->private) { flags = "private"; }
    else if (range->shared) { flags = "shared"; }
    else { flags = "-"; }
    PAL_INFO("One enclave range: addr %lx, size %lx, prot %s, flags %s",
             range->addr, range->size, prot, flags);
}

void print_enclave_ranges(struct enclave_info *einfo) {
    for (int i = 0; i < einfo->nr_range; i++) {
        print_one_range(&einfo->ranges[i]);
    }
}

int try_get_enclave_cache() {
    int ret;

    PAL_INFO("Connecting to EPM %s", EPM_SOCKET_PATH);
    ret = new_unix_socket_connect(EPM_SOCKET_PATH);
    if (ret < 0) {
        goto error;
    }
    int epm_sock = ret;

    PAL_INFO("Sending GET CMD");
    ret = write(epm_sock, EPM_GET_CMD_MSG, EPM_CMD_MSG_LEN);
    if (ret < 0) {
        goto close_return;
    }

    struct enclave_info *einfo = &enclave_cache_info;

    PAL_INFO("Receiving einfo hdr");
    ret = read(epm_sock, (void *)&einfo->hdr, sizeof(struct enclave_info_hdr));
    if (ret < 0) {
        goto close_return;
    }
    print_enclave_info_header(&einfo->hdr);
    if (einfo->nr_range == 0 || einfo->nr_range >= MAX_RANGES) {
        ret = -1;
        enclave_cache_fd = -1;
        goto close_return;
    }

    PAL_INFO("Receiving einfo");
    ret = read(epm_sock, (void *)einfo->ranges,
               sizeof(struct enclave_range) * einfo->nr_range);
    if (ret < 0) {
        goto close_return;
    }
    print_enclave_ranges(einfo);

    char fd_sock_path[100] = {0};
    sprintf(fd_sock_path, "%s/%08x", EPM_DIR, einfo->id);
    PAL_INFO("Receiving fd");
    ret = recv_fd(fd_sock_path);
    if (ret < 0) {
        goto close_return;
    }
    int efd = ret;
    PAL_INFO("Received fd %d", efd);

    PAL_INFO("Mapping enclave");
    ret = map_enclave(efd, einfo);
    if (ret < 0) {
        goto close_return;
    }

    enclave_cache_fd = efd;
    ret = 0;

close_return:
    close(epm_sock);
error:
    PAL_INFO("return value is %d", ret);
    return ret;
}

int is_sgx_dev_path(const char *p) {
    return !strcmp(p, "/dev/sgx_enclave")
           || !strcmp(p, "/dev/sgx/enclave");
}

int get_enclave_fd() {
    int efd = -1;

    char *fddir = "/proc/self/fd";
    DIR *dir = opendir(fddir);
    if (!dir) { return -1; }

    struct dirent *entry;
    char full_path[1024];
    char link_target[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", fddir, entry->d_name);

        struct stat statbuf;
        if (lstat(full_path, &statbuf) == -1) {
            continue;
        }

        if (!S_ISLNK(statbuf.st_mode)) {
            continue;
        }

        ssize_t len = readlink(full_path, link_target, sizeof(link_target) - 1);
        if (len == -1) {
            continue;
        }
        link_target[len] = '\0';

        if (!is_sgx_dev_path(link_target)) {
            continue;
        }

        efd = atoi(entry->d_name);
        break;
    }

    closedir(dir);
    return efd;
}

#define DELIM " \t\n"
int parse_one_map(char *buf, struct enclave_range *range) {
    char *token;

    // addr
    token = strtok(buf, DELIM);
    sscanf(token, "%lx-%lx", &range->addr, &range->size);
    range->size -= range->addr;

    // prot, flags
    token = strtok(NULL, DELIM);
    for (int i = 0; !isspace(token[i]); i++) {
        switch (buf[i]) {
            case 'r':
                range->r = 1;
                break;
            case 'w':
                range->w = 1;
                break;
            case 'x':
                range->x = 1;
                break;
            case 'p':
                range->private = 1;
                break;
            case 's':
                range->shared = 1;
                break;
        }
    }

    // offset
    token = strtok(NULL, DELIM);
    // device
    token = strtok(NULL, DELIM);
    // inode
    token = strtok(NULL, DELIM);
    // path
    token = strtok(NULL, DELIM);
    if (token && is_sgx_dev_path(token)) {
        // PAL_INFO("Got one enclave map");
        // print_one_range(range);
        return 1;
    } else {
        return 0;
    }
}

int get_enclave_map() {
    int ret;

    PAL_INFO("Parsing enclave map");

    ret = get_enclave_fd();
    if (ret < 0) {
        goto error;
    }
    enclave_cache_fd = ret;
    PAL_INFO("Got enclave fd %d", enclave_cache_fd);

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        ret = -1;
        goto error;
    }

    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(sizeof(char) * fsz + 10);
    uint64_t read = fread(buf, fsz, 1, fp);
    if (read != fsz) {
        goto close_return;
    }
    buf[read] = 0;
    fclose(fp);

    for (uint64_t i = 0; i < read; i++) {
        if (buf[i] == '\n') {
            buf[i] = 0;
        }
    }

    srand(time(0));
    enclave_cache_info.id = rand();

    char *p = buf;
    int slen = 0;
    int nr_range = 0;
    while ((slen = strlen(p))) {
        if (parse_one_map(p, &enclave_cache_info.ranges[nr_range])) {
            nr_range++;
        }
        p += slen;
    }
    enclave_cache_info.nr_range = nr_range;
    PAL_INFO("nr_ranges=%d", nr_range);

    return 0;

close_return:
    fclose(fp);
error:
    return ret;
}

int save_enclave_cache() {
    int ret;

    PAL_INFO("Save Enclave");
    if (enclave_cache_fd < 0) {
        PAL_INFO("Enclave is not from EPM");
        ret = get_enclave_map();
        if (ret < 0) {
            goto error;
        }
    }

    PAL_INFO("Unmmaping enclave");
    ret = unmap_enclave(enclave_cache_fd, &enclave_cache_info);
    if (ret < 0) {
        goto error;
    }

    PAL_INFO("Connecting to EPM");
    ret = new_unix_socket_connect(EPM_SOCKET_PATH);
    if (ret < 0) {
        goto error;
    }
    int epm_sock = ret;

    PAL_INFO("Sending SAVE CMD");
    ret = write(epm_sock, EPM_SET_CMD_MSG, EPM_CMD_MSG_LEN);
    if (ret < 0) {
        goto close_return;
    }

    struct enclave_info *einfo = &enclave_cache_info;
    PAL_INFO("Sending einfo");
    print_enclave_info_header(&einfo->hdr);
    print_enclave_ranges(einfo);
    ret = write(epm_sock, (void *)einfo, sizeof(struct enclave_info));
    if (ret < 0) {
        goto close_return;
    }

    char fd_sock_path[100] = {0};
    sprintf(fd_sock_path, "%s/%08x", EPM_DIR, enclave_cache_info.id);
    PAL_INFO("Sending fd %d", enclave_cache_fd);
    ret = send_fd(fd_sock_path, enclave_cache_fd);
    if (ret < 0) {
        goto close_return;
    }

    enclave_cache_fd = -1;
    close(enclave_cache_fd);
    ret = 0;

close_return:
    close(epm_sock);
error:
    return ret;
}
