/*
 * safebox_client.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ╔══════════════════════════════════════════════════════╗
 * ║  ARCHIVO A IMPLEMENTAR POR LOS ESTUDIANTES           ║
 * ║  Este es el codigo de REFERENCIA del profesor.       ║
 * ║  Los estudiantes entregaran su propia version.       ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Implementa las funciones declaradas en safebox_client.h.
 * Este archivo es la "biblioteca de enlace" entre el
 * minishell (safebox-shell.c) y el daemon.
 *
 * Syscalls principales usadas:
 *   socket(2), connect(2), send(2), recv(2)
 *   sendmsg(2), recvmsg(2) con SCM_RIGHTS
 *   open(2), read(2), fstat(2)
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

#include "safebox.h"
#include "safebox_client.h"


int sb_connect(const char *socket_path, const char *password){

    (void)password;
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    // if (sockfd < 0) {
    //     perror("socket");
    //     exit(EXIT_FAILURE);
    // }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    sb_auth_msg_t message;
    message.op = SB_OP_LIST;
    message.password_hash = sb_djb2(password);
    
    write(sockfd, &message, sizeof(message));

    uint8_t response;
    ssize_t n = read(sockfd, &response, sizeof(response));

    if(n != sizeof(response)){
        perror("lesctura de autenticacion");
        exit(EXIT_FAILURE);
    }
    
    if(!response){
        return sockfd;
    }
    else{
        close(sockfd);
        return -1;
    }
}


void sb_bye(int sockfd){
    sb_auth_msg_t message;
    message.op = SB_OP_BYE;
    message.password_hash = 1;
    printf("%ld\n", sizeof(message));
    write(sockfd, &message, sizeof(message));
    close(sockfd);
}

int sb_list(int sockfd, char *buf, size_t buflen){
    (void)sockfd;
    (void)buf;
    (void)buflen;
    
    return -1;
}

int sb_get(int sockfd, const char *filename){
    (void)sockfd;
    (void)filename;
    
    return -1;
}

int sb_put(int sockfd, const char *filename, const char *filepath){
    (void) sockfd;
    (void) filename;
    (void) filepath;

    return -1;
}

int sb_del(int sockfd, const char *filename){
    (void) sockfd;
    (void) filename;
    
    return -1;
}