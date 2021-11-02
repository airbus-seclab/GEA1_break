#ifndef __FILE_H__
#define __FILE_H__

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

static __inline__
int get_self_absolute_path(char *buffer, size_t bufsiz)
{
    ssize_t ret = readlink("/proc/self/exe", buffer, bufsiz);
    if(ret < 0 || (size_t)ret == bufsiz) {
        printf("[-] readlink() was not provided a big enough buffer!\n");
        return -1;
    }

    return 0;
}

static __inline__
int is_directory_created(char *dirname)
{
    DIR *d;

    d = opendir(dirname);
    if (!d) {
        return 0;
    }
    closedir(d);
    return 1;
}

// Good enough for now.
static __inline__
int create_directory(char *dir_name)
{
    struct stat st = {0};
    int ret;

    ret = stat(dir_name, &st);
    if (!ret) {
        printf("[!] Directory already existing, overwriting its content...\n");
        return 0;
    }

    ret = mkdir(dir_name, 0700);
    if(ret < 0) {
        printf("[-] mkdir() failed! [errno:%d]\n", errno);
        return -1;
    }

    return 0;
}

static __inline__
int64_t get_file_size(char *fname)
{
    struct stat st;
    int ret;

    memset(&st, 0, sizeof(st));
    ret = lstat(fname, &st);
    if(ret < 0) {
        printf("[-] Error, lstat() failed [err:%d]\n", errno);
        return -1;
    }
    return st.st_size;
}

static __inline__
int read_file(char *fname, uint8_t *buffer, uint64_t buffer_size)
{
    uint64_t nr_bytes_remaining, offset;
    int fd, ret;

    fd = open(fname, O_RDONLY);
    if(fd < 0) {
        printf("[-] Error open(%s) failed: [errno:%d]\n", fname, errno);
        return -1;
    }

    // Depending on the disk or other factors, read() "may" return earlier.
    nr_bytes_remaining = buffer_size;
    offset = 0;
    while(nr_bytes_remaining) {
        ret = read(fd, &buffer[offset], nr_bytes_remaining);
        if(ret < 0) {
            printf("[-] Error read(%lu) failed: [errno:%d]\n", nr_bytes_remaining, errno);
            close(fd);
            return -2;
        }
        nr_bytes_remaining -= ret;
        offset += ret;
    }
    close(fd);
    return 0;
}

static __inline__
int write_file(char *fname, uint8_t *buffer, uint32_t buffer_size)
{
    uint32_t nr_bytes_remaining, offset;
    int fd, ret;

    fd = open(fname, O_CREAT | O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP);
    if(fd < 0) {
        printf("[-] Error open() failed to create %s file [errno:%d]\n", fname, errno);
        return -1;
    }

    // Depending on the disk or other factors, write() "may" return earlier.
    nr_bytes_remaining = buffer_size;
    offset = 0;
    while(nr_bytes_remaining) {
        ret = write(fd, &buffer[offset], nr_bytes_remaining);
        if(ret < 0) {
            printf("[-] Error write(%d) failed [errno:%d]\n", nr_bytes_remaining, errno);
            close(fd);
            return -2;
        }
        nr_bytes_remaining -= ret;
        offset += ret;
    }
    close(fd);
    return 0;
}

static __inline__
char *create_tmp_file()
{
    uint8_t buffer[4096];
    char name[512];
    int ret;

    memset(name, 0, sizeof(name));
    memset(buffer, 0, sizeof(buffer));

    snprintf(name, sizeof(name)-1, "/tmp/gea1_shmem_%d_%d", getpid(), rand());
    ret = write_file(name, buffer, sizeof(buffer));
    if(ret < 0)
        return NULL;
    return strdup(name);
}
#endif /* __FILE_H__ */
