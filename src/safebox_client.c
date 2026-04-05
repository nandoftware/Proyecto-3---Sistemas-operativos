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
#include <arpa/inet.h>

#include "safebox.h"
#include "safebox_client.h"

/**
 * @brief funcion para escribir al socket
 *
 * escribe en sockfd lo que tengas en el buf
 * 
 * @param int sockfd: socket
 * @param void *buf: buffer en gegenrico
 * @param size_t n: cantidad de bytes a mandar
 */
ssize_t Super_Send(int sockfd, const void *buf, size_t n) {
    size_t enviado = 0;
    const char *env = buf;
    while (enviado < n) {
        ssize_t r = send(sockfd, env + enviado, n - enviado, 0);
        if (r <= 0) return r;
        enviado += r;
    }
    return (ssize_t)n;
}

/**
 * @brief funcion para leer al socket
 *
 * la pesdilla de mis noches y el mal de todas mis desgracias
 * esta bendita funcion, LEE COMPLETO, se alimenta bien
 * y no deja el plato (socket) vacio 
 * 
 * @param int sockfd: socket
 * @param void *buf: buffer en gegenrico
 * @param size_t n: cantidad de bytes a mandar
 */
ssize_t Super_Read(int socket, void *buf, size_t n) {
    size_t recivido = 0;
    char *rec = buf;
    while (recivido < n) {
        ssize_t r = recv(socket, rec + recivido, n - recivido, 0);
        if (r <= 0) return r;
        recivido += r;
    }

    // y se tiene que castear porque afuera lloran si no
    return (ssize_t)n;
}


int sb_connect(const char *socket_path, const char *password) {
    int socket_fd;
    struct sockaddr_un direccion;
    sb_auth_msg_t mensaje_auth; 
    uint8_t respuesta;

    if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) return -1;

    memset(&direccion, 0, sizeof(struct sockaddr_un));
    direccion.sun_family = AF_UNIX;
    strncpy(direccion.sun_path, socket_path, sizeof(direccion.sun_path) - 1);

    if (connect(socket_fd, (struct sockaddr *)&direccion, sizeof(struct sockaddr_un)) == -1) {
        close(socket_fd);
        return -1;
    }

    mensaje_auth.op = 0; 
    mensaje_auth.password_hash = sb_djb2(password);

    if (Super_Send(socket_fd, &mensaje_auth, sizeof(sb_auth_msg_t)) <= 0) {
        close(socket_fd);
        return -1;
    }

    if (Super_Read(socket_fd, &respuesta, 1) <= 0 || respuesta != SB_OK) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

void sb_bye(int sockfd) {
    if (sockfd < 0) return;
    uint8_t op = SB_OP_BYE;
    Super_Send(sockfd, &op, 1);
    close(sockfd);
}

int sb_list(int sockfd, char *buf, size_t buflen) {
    uint8_t op = SB_OP_LIST;
    uint32_t files = 0;

    if (Super_Send(sockfd, &op, 1) <= 0){
         return -1;
    }

    if (Super_Read(sockfd, &files, sizeof(uint32_t)) <= 0){
        return -1;
    }

    uint32_t cont = ntohl(files);
    if (cont > 0) {
        size_t mini_len = (cont * MAX_FNAME_LEN < buflen) ? cont * MAX_FNAME_LEN : buflen - 1;
        ssize_t r = recv(sockfd, buf, mini_len, 0);
        if (r > 0) buf[r] = '\0';
    } else {
        buf[0] = '\0';
    }
    return (int)cont;
}

int sb_get(int sockfd, const char *filename) {
    uint8_t op = SB_OP_GET;
    if (Super_Send(sockfd, &op, 1) <= 0) return -1;
    
    char filename_sb[MAX_FNAME_LEN] = {0};
    strncpy(filename_sb, filename, MAX_FNAME_LEN - 1);
    if (Super_Send(sockfd, filename_sb, MAX_FNAME_LEN) <= 0) return -1;

    uint8_t respuesta;
    if (Super_Read(sockfd, &respuesta, 1) <= 0) return -1;

    if (respuesta != SB_OK) {
        if (respuesta == SB_ERR_CORRUPT) {
            fprintf(stderr, "Error: El daemon reporta corrupcion de datos.\n");
        }
        return -1;
    }

    //------------ cuestion del fd en memeoria ----------------------
    struct iovec iov = {.iov_base = &respuesta, .iov_len = 1};
    char datos_auxiliares[CMSG_SPACE(sizeof(int))];
    memset(datos_auxiliares, 0, sizeof(datos_auxiliares));

    struct msghdr mensaje = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = datos_auxiliares,
        .msg_controllen = sizeof(datos_auxiliares)
    };

    if (recvmsg(sockfd, &mensaje, 0) <= 0) return -1;

    struct cmsghdr *cabecera_control = CMSG_FIRSTHDR(&mensaje);
    if (cabecera_control && cabecera_control->cmsg_level == SOL_SOCKET && 
        cabecera_control->cmsg_type == SCM_RIGHTS) {
        
        int fd_recibido = *((int *)CMSG_DATA(cabecera_control));
        lseek(fd_recibido, 0, SEEK_SET);
        return fd_recibido;
    }
    //------------ cuestion del fd en memeoria ----------------------

    return -1;
}

int sb_put(int sockfd, const char *filename, const char *filepath) {
    struct stat info_archivo;
    int fp_fd = open(filepath, O_RDONLY);
    if (fp_fd < 0 || fstat(fp_fd, &info_archivo) < 0) {
        return -1;
    }

    uint8_t op = SB_OP_PUT;
    if (Super_Send(sockfd, &op, 1) <= 0) {
        close(fp_fd);
        return -1;
    }

    char filename_sb[MAX_FNAME_LEN] = {0};
    strncpy(filename_sb, filename, MAX_FNAME_LEN - 1);
    Super_Send(sockfd, filename_sb, MAX_FNAME_LEN);
    
    uint32_t tamano_be = htonl((uint32_t)info_archivo.st_size);
    Super_Send(sockfd, &tamano_be, sizeof(uint32_t));

    char buffer_datos[4096];
    ssize_t n;
    while ((n = read(fp_fd, buffer_datos, sizeof(buffer_datos))) > 0) {
        // me salio mal o raro lo del size_t y ssize_t pero bueno
        if (Super_Send(sockfd, buffer_datos, (size_t)n) <= 0) break;
    }
    close(fp_fd);

    uint8_t respuesta;
    if (Super_Read(sockfd, &respuesta, 1) <= 0 || respuesta != SB_OK) return -1;
    return 0;
}

int sb_del(int sockfd, const char *filename) {
    uint8_t op = SB_OP_DEL;
    uint8_t respuesta;
    if (Super_Send(sockfd, &op, 1) <= 0) return -1;

    char filename_sb[MAX_FNAME_LEN] = {0};
    strncpy(filename_sb, filename, MAX_FNAME_LEN - 1);
    if (Super_Send(sockfd, filename_sb, MAX_FNAME_LEN) <= 0){
      return -1;  
    }

    if (Super_Read(sockfd, &respuesta, 1) <= 0 || respuesta != SB_OK){
        return -1;
    }
    return 0;
}





















// #define MAX_PAYLOAD_SIZE 511

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <errno.h>
// #include <sys/socket.h>
// #include <sys/un.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <stdint.h>

// #include "safebox.h"
// #include "safebox_client.h"

// #pragma pack(push, 1)
// typedef struct 
// {
//     uint8_t op;
//     uint8_t payload[MAX_PAYLOAD_SIZE];
// }wire_format;
// #pragma pack(pop)

// void int32toint8(uint32_t *number, uint8_t * payload){
//     payload[0] = (*number >> 24) & 0xFF;
//     payload[1] = (*number >> 16) & 0xFF;
//     payload[2] = (*number >> 8) & 0xFF;
//     payload[3] = *number & 0xFF;
// }

// void int8toint32(uint32_t *number, uint8_t * payload){
//     *number |= ((uint32_t)payload[0] << 24);
//     *number |= ((uint32_t)payload[1] << 16);
//     *number |= ((uint32_t)payload[2] << 8);
//     *number |= ((uint32_t)payload[3]);
// }

// void char2int8(const char *string, uint8_t *payload, int payload_size, int begin){

//     int i = begin;
//     while (string[i - begin] != '\0' && i < payload_size )
//     {
//         payload[i] = string[i - begin];
//         i++;
//     }
//     payload[i] = '\0';

// }
// int int82char(char *string, uint8_t *payload, int payload_size, int begin){
//     int i = begin;
//     int cont = 0;
//     while (payload[i - begin] != '\0' && i < payload_size )
//     {
//         string[i] = payload[i - begin];
//         i++;
//         cont++;
//     }
//     string[i] = '\0';
//     cont++;
//     return cont;
// }

// static int recibir_fd(int socket_fd) {

//     // if (socket_fd < 0){
//     //     return -1;
//     // }
//     /* Byte dummy que el sender envía como datos reales */
//     char dummy;
//     struct iovec iov = {
//         .iov_base = &dummy,
//         .iov_len  = sizeof(dummy)
//     };

//     /* Buffer para el mensaje de control (mismo tamaño que el sender) */
//     union {
//         struct cmsghdr cmh;
//         char           control[CMSG_SPACE(sizeof(int))];
//     } control_buf;

//     memset(&control_buf, 0, sizeof(control_buf));

//     struct msghdr msg;
//     memset(&msg, 0, sizeof(msg));
//     msg.msg_iov        = &iov;
//     msg.msg_iovlen     = 1;
//     msg.msg_control    = control_buf.control;
//     msg.msg_controllen = sizeof(control_buf.control);

//     /* recvmsg() bloquea hasta recibir el mensaje.
//      * El kernel ya duplicó el fd en nuestra tabla de fds
//      * antes de que recvmsg() retorne. */
//     if (recvmsg(socket_fd, &msg, 0) < 0) {
//         perror("recvmsg");
//         exit(EXIT_FAILURE);
//     }

//     /* Extraer el fd del mensaje de control */
//     struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
//     if (cmsg == NULL ||
//         cmsg->cmsg_level != SOL_SOCKET ||
//         cmsg->cmsg_type  != SCM_RIGHTS) {
//         fprintf(stderr, "No se recibió SCM_RIGHTS\n");
//         exit(EXIT_FAILURE);
//     }

//     int fd_recibido;
//     memcpy(&fd_recibido, CMSG_DATA(cmsg), sizeof(int));
//     return fd_recibido;
// }


// int sb_connect(const char *socket_path, const char *password){

//     int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
//     // if (sockfd < 0) {
//     //     perror("socket");
//     //     exit(EXIT_FAILURE);
//     // }

//     struct sockaddr_un addr;
//     memset(&addr, 0, sizeof(addr));
//     addr.sun_family = AF_UNIX;
//     strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

//     if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
//         return -1;
//     }

//     wire_format message;
//     message.op = SB_OP_LIST;
//     uint32_t pass = sb_djb2(password);
//     int32toint8(&pass, message.payload);
//     // message.password_hash = sb_djb2(password);
//     // printf("hasheado: %d\n", sb_djb2(password));
//     // char palabra[11] = "murcielago";
//     // printf("tamaño de la palabra: %ld\n", sizeof(palabra));
//     // uint8_t arr[11];
//     // char2int8(palabra, arr, 11, 0);

//     // for (int i = 0; i < 11; i++)
//     // {
//     //     printf("letra: %d\n", arr[i]);
//     // }
    
//     // printf("troceado: %d,%d,%d,%d,\n",arr[0],arr[1],arr[2],arr[3]);
//     // uint32_t npass;
//     // int8toint32(&npass, arr);
//     // printf("normal: %d\n", npass);
    
//     write(sockfd, &message, sizeof(message));

//     uint8_t response;
//     ssize_t n = read(sockfd, &response, sizeof(response));

//     if(n != sizeof(response)){
//         perror("lesctura de autenticacion");
//         exit(EXIT_FAILURE);
//     }
    
//     if(!response){
//         return sockfd;
//     }
//     else{
//         close(sockfd);
//         return -1;
//     }
// }


// void sb_bye(int sockfd){
//     wire_format message;
//     message.op = SB_OP_BYE;
//     // message.password_hash = 1;
    
//     write(sockfd, &message, sizeof(message));
//     close(sockfd);
// }

// int sb_list(int sockfd, char *buf, size_t buflen){
//     wire_format message;
//     message.op = SB_OP_LIST;
//     message.payload[0] = 0;
    
//     // le pides al daemos que te de la lista de archivos
    
//     write(sockfd, &message, sizeof(message));

//     // ellos vendrar en un char[] plano, y eso lo tengo que poner en el buf
//     // si no viene nada la shell se encarga de decirlo, pero nosotro se lo decimos a la shell
   
//     ssize_t n;

//     n = recv(sockfd, buf, buflen, 0);
    
//     if(n >= 0){
//         int files = 0;
//         int i ;
//         // int b = 1;
//         for (i = 0; i < (int)buflen; i++)
//         {
//             if (buf[i] == '\n'){
                
                
//                 files++;
//                 // printf("%d\n", i);

//             }
//         }
//         // printf("%d %d\n", i, files);
//         if(strlen(buf) != 0){
//             files++;
//         }
//         return files;
//     }
//     else{
//         return -1;
//     }
    
// }

// int sb_get(int sockfd, const char *filename){
//     wire_format message;
//     message.op = SB_OP_GET;
//     char2int8(filename, message.payload, sizeof(filename), 0);

//     write(sockfd, &message, sizeof(message));

//     int fd = recibir_fd(sockfd);
    
//     printf("%d", fd);

//     return fd;
// }

// int sb_put(int sockfd, const char *filename, const char *filepath){
//     wire_format message;
//     message.op = SB_OP_PUT;
//     // printf("tamano filename: %ld , %ld\n",sizeof(filename), sizeof(message.payload));

//     char2int8(filename, message.payload, sizeof(filename), 0);
//     // for (int i = 0; i < 40; i++)
//     // {
//     //     printf("letra: %d\n", message.payload[i]);
//     // }
//     // printf("tamano filename: %ld , %ld\n",sizeof(filename), sizeof(message.payload));
//     char2int8(filepath, message.payload, sizeof(message.payload), sizeof(filename)+1);
    
//     // for (int i = 0; i < 40; i++)
//     // {
//     //     printf("letra: %d\n", message.payload[i]);
//     // }
//     write(sockfd, &message, sizeof(message));

//     uint8_t op;
//     ssize_t n;
//     n = read(sockfd, &op, sizeof(op));
//     if(n != sizeof(op)){
//         return -1;
//     }

    
//     if(op == SB_OK){
//         return 0;
//     }
//     else{
//         return -1;
//     }
//     return -1;
// }

// int sb_del(int sockfd, const char *filename){
//     wire_format message;
//     message.op = SB_OP_DEL;
//     char2int8(filename, message.payload, sizeof(message.payload), 0);

//     write(sockfd, &message, sizeof(message));

//     uint8_t op;
//     ssize_t n = read(sockfd, &op, sizeof(op));
//     if (n != sizeof(op)){
//         return -1;
//     }

//     if(op == SB_OK){
//         return 0;
//     }
//     else{
//         return -1;
//     }
// }