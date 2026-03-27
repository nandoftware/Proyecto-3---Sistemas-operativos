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

#define MAX_PAYLOAD_SIZE 511

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

#pragma pack(push, 1)
typedef struct 
{
    uint8_t op;
    uint8_t payload[MAX_PAYLOAD_SIZE];
}wire_format;
#pragma pack(pop)

void int32toint8(uint32_t *number, uint8_t * payload){
    payload[0] = (*number >> 24) & 0xFF;
    payload[1] = (*number >> 16) & 0xFF;
    payload[2] = (*number >> 8) & 0xFF;
    payload[3] = *number & 0xFF;
}

void int8toint32(uint32_t *number, uint8_t * payload){
    *number |= ((uint32_t)payload[0] << 24);
    *number |= ((uint32_t)payload[1] << 16);
    *number |= ((uint32_t)payload[2] << 8);
    *number |= ((uint32_t)payload[3]);
}

void char2int8(const char *string, uint8_t *payload, int payload_size, int begin){

    int i = begin;
    while (string[i - begin] != '\0' && i < payload_size )
    {
        payload[i] = string[i - begin];
        i++;
    }
    payload[i] = '\0';

}
int int82char(char *string, uint8_t *payload, int payload_size, int begin){
    int i = begin;
    int cont = 0;
    while (payload[i - begin] != '\0' && i < payload_size )
    {
        string[i] = payload[i - begin];
        i++;
        cont++;
    }
    string[i] = '\0';
    cont++;
    return cont;
}

static int recibir_fd(int socket_fd) {

    /* Byte dummy que el sender envía como datos reales */
    char dummy;
    struct iovec iov = {
        .iov_base = &dummy,
        .iov_len  = sizeof(dummy)
    };

    /* Buffer para el mensaje de control (mismo tamaño que el sender) */
    union {
        struct cmsghdr cmh;
        char           control[CMSG_SPACE(sizeof(int))];
    } control_buf;

    memset(&control_buf, 0, sizeof(control_buf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control_buf.control;
    msg.msg_controllen = sizeof(control_buf.control);

    /* recvmsg() bloquea hasta recibir el mensaje.
     * El kernel ya duplicó el fd en nuestra tabla de fds
     * antes de que recvmsg() retorne. */
    if (recvmsg(socket_fd, &msg, 0) < 0) {
        perror("recvmsg");
        exit(EXIT_FAILURE);
    }

    /* Extraer el fd del mensaje de control */
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL ||
        cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type  != SCM_RIGHTS) {
        fprintf(stderr, "No se recibió SCM_RIGHTS\n");
        exit(EXIT_FAILURE);
    }

    int fd_recibido;
    memcpy(&fd_recibido, CMSG_DATA(cmsg), sizeof(int));
    return fd_recibido;
}


int sb_connect(const char *socket_path, const char *password){

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

    wire_format message;
    message.op = SB_OP_LIST;
    uint32_t pass = sb_djb2(password);
    int32toint8(&pass, message.payload);
    // message.password_hash = sb_djb2(password);
    // printf("hasheado: %d\n", sb_djb2(password));
    // char palabra[11] = "murcielago";
    // printf("tamaño de la palabra: %ld\n", sizeof(palabra));
    // uint8_t arr[11];
    // char2int8(palabra, arr, 11, 0);

    // for (int i = 0; i < 11; i++)
    // {
    //     printf("letra: %d\n", arr[i]);
    // }
    
    // printf("troceado: %d,%d,%d,%d,\n",arr[0],arr[1],arr[2],arr[3]);
    // uint32_t npass;
    // int8toint32(&npass, arr);
    // printf("normal: %d\n", npass);
    
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
    wire_format message;
    message.op = SB_OP_BYE;
    // message.password_hash = 1;
    
    write(sockfd, &message, sizeof(message));
    close(sockfd);
}

int sb_list(int sockfd, char *buf, size_t buflen){
    wire_format message;
    message.op = SB_OP_LIST;
    message.payload[0] = 0;
    
    // le pides al daemos que te de la lista de archivos
    
    write(sockfd, &message, sizeof(message));

    // ellos vendrar en un char[] plano, y eso lo tengo que poner en el buf
    // si no viene nada la shell se encarga de decirlo, pero nosotro se lo decimos a la shell
    ssize_t n;
    n = read(sockfd, buf, buflen);
    
    
    if(n >= 0){
        int files;
        for (int i = 0; i < (int)buflen; i++)
        {
            if (buf[i] == '\n'){
                files++;
            }
        }
        return files;
    }
    else{
        return -1;
    }
    
}

int sb_get(int sockfd, const char *filename){
    wire_format message;
    message.op = SB_OP_GET;
    char2int8(filename, message.payload, sizeof(filename), 0);

    write(sockfd, &message, sizeof(message));

    int fd = recibir_fd(sockfd);
    
    

    return fd;
}

int sb_put(int sockfd, const char *filename, const char *filepath){
    wire_format message;
    message.op = SB_OP_PUT;
    // printf("tamano filename: %ld , %ld\n",sizeof(filename), sizeof(message.payload));

    char2int8(filename, message.payload, sizeof(filename), 0);
    // for (int i = 0; i < 40; i++)
    // {
    //     printf("letra: %d\n", message.payload[i]);
    // }
    // printf("tamano filename: %ld , %ld\n",sizeof(filename), sizeof(message.payload));
    char2int8(filepath, message.payload, sizeof(message.payload), sizeof(filename));
    
    // for (int i = 0; i < 40; i++)
    // {
    //     printf("letra: %d\n", message.payload[i]);
    // }
    write(sockfd, &message, sizeof(message));

    uint8_t op;
    ssize_t n;
    n = read(sockfd, &op, sizeof(op));
    if(n != sizeof(op)){
        return -1;
    }

    
    if(op == SB_OK){
        return 0;
    }
    else{
        return -1;
    }
    return -1;
}

int sb_del(int sockfd, const char *filename){
    wire_format message;
    message.op = SB_OP_DEL;
    char2int8(filename, message.payload, sizeof(message.payload), 0);

    write(sockfd, &message, sizeof(message));

    uint8_t op;
    ssize_t n = read(sockfd, &op, sizeof(op));
    if (n != sizeof(op)){
        return -1;
    }

    if(op == SB_OK){
        return 0;
    }
    else{
        return -1;
    }
}