/*
 * safebox-daemon.c
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
 * Daemon de la boveda de archivos cifrados.
 *
 * Syscalls principales:
 *   termios:         lectura segura del password (sin echo)
 *   fork/setsid:     daemonizacion
 *   socket/bind/
 *   listen/accept:   Unix Domain Socket
 *   getsockopt:      SO_PEERCRED (identidad del cliente)
 *   open/mmap/msync: acceso a archivos cifrados
 *   memfd_create:    fd anonimo en RAM para el contenido descifrado
 *   sendmsg:         SCM_RIGHTS (transferir fd al cliente)
 *   opendir/readdir: listar directorio del safebox
 *   unlink:          eliminar archivos
 *   signal:          SIGTERM handler para cierre limpio
 *
 * Compilacion (la hace el Makefile):
 *   gcc -std=c11 -Wall -Wextra -Werror \
 *       -Iinclude \
 *       -o safebox-daemon src/safebox-daemon.c
 *
 * Uso:
 *   ./safebox-daemon ./mi_boveda
 *   safebox password: ****
 *   [safebox] pid=XXXX listo
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
#include <sys/mman.h>
#include <sys/types.h>

#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "safebox.h"


static char clave[MAX_KEY_LEN];
static uint32_t clave_hash = 0;
static char boveda_path[PATH_MAX];
static int log_fd = -1;

/**
 * @brief funcion XOR
 *
 * aplica el hash XOR a una cadena de caracteres
 * 
 * @param uint8_t *hash: apuntador a la variable hash
 * @param size_t len: longitud del string
 * @param const char *clavesita: la clave a hashear
 */
void XOR(uint8_t *hash, size_t len, const char *clavesita) {
    size_t key_len = strlen(clavesita);
    if (key_len == 0) return;
    for (size_t i = 0; i < len; i++) {
        hash[i] ^= (uint8_t)clavesita[i % key_len];
    }
}

/**
 * @brief Obtiene la clave para el daemon
 *
 * esta funcion va a setear la clave de una vez
 * para el daemon, y, concecuentemente, para los clientes
 */
void Get_Key() {
    struct termios antes, despues;
    char pass[MAX_KEY_LEN];
    printf("safebox password: "); fflush(stdout);
    
    tcgetattr(STDIN_FILENO, &antes);
    despues = antes; 
    despues.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &despues);

    if (fgets(pass, MAX_KEY_LEN, stdin)) {
        pass[strcspn(pass, "\n")] = 0;
        strncpy(clave, pass, MAX_KEY_LEN - 1);
        clave_hash = sb_djb2(pass);
        /* Limpiamos el rastro de la clave en el stack inmediatamente */
        memset(pass, 0, MAX_KEY_LEN);
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &antes);
    printf("\n");
}


// static void daemonizar() {
//     pid_t pid = fork();
//     if (pid < 0) exit(1);
//     if (pid > 0) exit(0); 

//     if (setsid() < 0) exit(1);

//     pid = fork();
//     if (pid < 0) exit(1);
//     if (pid > 0) {
//         printf("[safebox] pid=%d listo\n", pid);
//         fflush(stdout);
//         exit(0);
//     }

//     umask(0);
//     chdir("/");

//     /* Redirigimos los descriptores estandar a /dev/null tal como vimos en mi_daemon.c */
//     int devnull = open("/dev/null", O_RDWR);
//     if (devnull != -1) {
//         dup2(devnull, STDIN_FILENO);
//         dup2(devnull, STDOUT_FILENO);
//         dup2(devnull, STDERR_FILENO);
//         close(devnull);
//     }

//     /* Registramos el PID actual en el archivo correspondiente */
//     int pid_fd = open(SB_PID_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
//     if (pid_fd >= 0) {
//         char buf[16];
//         int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
//         if (len > 0) write(pid_fd, buf, (size_t)len);
//         close(pid_fd);
//     }
// }

/**
 * @brief handler de terminacion del proceso
 *
 * esta funcion se encarga de setear la señal
 * de terminacion
 */
void handle_signterm(int sig) {
    (void)sig;
    sb_log(log_fd, SB_LOG_INFO, "SIGTERM recibido - daemon terminado limpiamente"); 
    unlink(SB_SOCKET_PATH);
    unlink(SB_PID_PATH);
    if (log_fd != -1) close(log_fd);
    exit(0);
}

/**
 * @brief operacion lista 
 *
 * lista los archivos en la boveda
 * 
 * @param int sockfd: socket con el cliente
 */
void List_Operator(int sockfd) {
    DIR *dir = opendir(boveda_path);
    struct dirent *direct;
    char buf[8192] = {0}; 
    uint32_t count = 0; 
    size_t off = 0;
    
    while (dir && (direct = readdir(dir))) {
        if (direct->d_name[0] == '.') continue;
        size_t l = strlen(direct->d_name);
        if (off + l + 1 < 8192) {
            memcpy(buf + off, direct->d_name, l); 
            off += l; 
            buf[off++] = '\n'; 
            count++;
        }
    }
    if (dir) closedir(dir);
    
    uint32_t c_be = htonl(count);
    send(sockfd, &c_be, 4, 0);
    if (count > 0) send(sockfd, buf, off, 0);
}

/**
 * @brief operacion Put 
 *
 * coloca archivos en la boveda
 * 
 * @param int sockfd: socket con el cliente
 * @param int pid: process id del proceso del daemon
 */
void Put_Operator(int sockfd, int pid) {
    char name[MAX_FNAME_LEN]; 
    uint32_t size_be;
    if (recv(sockfd, name, MAX_FNAME_LEN, 0) <= 0) return;
    if (recv(sockfd, &size_be, 4, 0) <= 0) return;
    uint32_t size = ntohl(size_be);

    char path[PATH_MAX + MAX_FNAME_LEN + 2]; 
    snprintf(path, sizeof(path), "%s/%s", boveda_path, name);
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    uint8_t res = 0xFF;

    if (fd >= 0) {
        sb_file_header_t h = { .version = 1, .payload_size = htonl(size + 4) };
        memset(h.reserved, 0, sizeof(h.reserved));

        if (write(fd, &h, sizeof(h)) == sizeof(h)) {
            uint8_t *b = malloc(size + 4);
            if (b) {
                memcpy(b, SB_MAGIC, 4);
                size_t rcv = 0;
                while (rcv < size) {
                    ssize_t r = recv(sockfd, b + 4 + rcv, size - rcv, 0);
                    if (r <= 0) break;
                    rcv += (size_t)r;
                }
                XOR(b, size + 4, clave);
                if (write(fd, b, size + 4) == (ssize_t)(size + 4)) res = SB_OK;
                free(b);
            }
        }
        close(fd);
        if (res == SB_OK) 
            sb_log(log_fd, SB_LOG_OK, "PUT %s - cifrado y guardado (pid=%d)", name, pid);
    }
    send(sockfd, &res, 1, 0);
}

/**
 * @brief operacion Get
 *
 * obtiene archivos en la boveda
 * 
 * @param int sockfd: socket con el cliente
 * @param int pid: process id del proceso del daemon
 */
void Get_Operator(int sockfd, int pid) {
    char filename[MAX_FNAME_LEN]; 
    if (recv(sockfd, filename, MAX_FNAME_LEN, 0) <= 0) return;
    
    char path[PATH_MAX + MAX_FNAME_LEN + 2]; 
    snprintf(path, sizeof(path), "%s/%s", boveda_path, filename);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) { 
        uint8_t r = 0xFF; 
        send(sockfd, &r, 1, 0); 
        return; 
    }

    sb_file_header_t header;
    if (read(fd, &header, sizeof(header)) == sizeof(header)) {
        uint32_t ps = ntohl(header.payload_size);
        uint8_t *cuestion = malloc(ps);
        if (cuestion && read(fd, cuestion, ps) == (ssize_t)ps) {
            XOR(cuestion, ps, clave);
            
            if (memcmp(cuestion, SB_MAGIC, 4) == 0) {
                uint8_t ok = SB_OK; 
                send(sockfd, &ok, 1, 0);
                
                int mfd = memfd_create("sb_mem", 0);
                if (mfd >= 0) {
                    size_t original_sz = ps - 4;
                    write(mfd, cuestion + 4, original_sz);
                    lseek(mfd, 0, SEEK_SET);

                    struct msghdr msg = {0};
                    struct iovec iov = {.iov_base = &ok, .iov_len = 1};
                    char ctrl[CMSG_SPACE(sizeof(int))];
                    msg.msg_iov = &iov; 
                    msg.msg_iovlen = 1;
                    msg.msg_control = ctrl; 
                    msg.msg_controllen = sizeof(ctrl);
                    
                    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
                    cm->cmsg_level = SOL_SOCKET;
                    cm->cmsg_type = SCM_RIGHTS;
                    cm->cmsg_len = CMSG_LEN(sizeof(int));
                    *((int *)CMSG_DATA(cm)) = mfd;
                    
                    sendmsg(sockfd, &msg, 0);
                    close(mfd);
                    sb_log(log_fd, SB_LOG_OK, "GET %s - entregado a pid=%d", filename, pid);
                }
            } else {
                uint8_t err = SB_ERR_CORRUPT;
                send(sockfd, &err, 1, 0);
                sb_log(log_fd, SB_LOG_WARN, "GET %s - error de integridad (Magic Number incorrecto)", filename);
            }
        }
        if (cuestion) free(cuestion);
    }
    close(fd);
}

/**
 * @brief operacion Del
 *
 * borra archivos en la boveda
 * 
 * @param int sockfd: socket con el cliente
 * @param int pid: process id del proceso del daemon
 */
void Del_Operator(int sockfd, int pid) {
    char filename[MAX_FNAME_LEN]; 
    if (recv(sockfd, filename, MAX_FNAME_LEN, 0) <= 0) return;
    
    char path[PATH_MAX + MAX_FNAME_LEN + 2]; 
    snprintf(path, sizeof(path), "%s/%s", boveda_path, filename);
    
    uint8_t sobra = (unlink(path) == 0) ? SB_OK : 0xFF;
    send(sockfd, &sobra, 1, 0);
    if (sobra == SB_OK) 
        sb_log(log_fd, SB_LOG_OK, "DEL %s - eliminado (pid=%d)", filename, pid);
}

/**
 * @brief Gestor del cliente
 *
 * aqui sucede la magia de agarrar la peticion de 
 * un cliente y mandarle una respuesta
 * 
 * @param int sockfd: socket con el cliente
 */
void atender_cliente(int sockfd) {
    struct ucred peer;
    uint8_t op;
    sb_auth_msg_t auth;
    socklen_t len = sizeof(struct ucred);

    int uid = -1, pid = -1;

    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &peer, &len) == 0) {
        uid = peer.uid;
        pid = peer.pid;
    }

    if (recv(sockfd, &auth, sizeof(auth), 0) <= 0) return;
    
    if (auth.password_hash == clave_hash) {
        uint8_t ok = SB_OK;
        send(sockfd, &ok, 1, 0);
        sb_log(log_fd, SB_LOG_OK, "autenticacion exitosa uid=%d pid=%d", uid, pid);
    } else {
        uint8_t err = SB_ERR_AUTH;
        send(sockfd, &err, 1, 0);
        sb_log(log_fd, SB_LOG_WARN, "autenticacion fallida uid=%d pid=%d", uid, pid);
        return;
    }
    
    while (recv(sockfd, &op, 1, 0) > 0) {
        switch (op) {
            case SB_OP_LIST: List_Operator(sockfd); break;
            case SB_OP_GET:  Get_Operator(sockfd, pid);  break;
            case SB_OP_PUT:  Put_Operator(sockfd, pid);  break;
            case SB_OP_DEL:  Del_Operator(sockfd, pid);  break;
            case SB_OP_BYE: 
                sb_log(log_fd, SB_LOG_INFO, "BYE uid=%d pid=%d - sesion cerrada", uid, pid);
                return; 
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || realpath(argv[1], boveda_path) == NULL) {
        fprintf(stderr, "Uso: %s <directorio>\n", argv[0]);
        exit(1);
    }

    Get_Key();
    log_fd = open(SB_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    
    // ------------- daemonizacion ----------------------
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0); 

    if (setsid() < 0) exit(1);

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) {
        printf("[safebox] pid=%d listo\n", pid);
        fflush(stdout);
        exit(0);
    }
    umask(0);
    chdir("/");

    int devnull = open("/dev/null", O_RDWR);
    if (devnull != -1) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    int pid_fd = open(SB_PID_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (pid_fd >= 0) {
        char buf[16];
        int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
        if (len > 0) write(pid_fd, buf, (size_t)len);
        close(pid_fd);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);

    int sb_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SB_SOCKET_PATH, sizeof(addr.sun_path)-1);
    unlink(SB_SOCKET_PATH);
    
    if (bind(sb_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) exit(1);
    listen(sb_fd, 5);

    sb_log(log_fd, SB_LOG_INFO, "daemon iniciado pid=%d boveda=%s", getpid(), boveda_path);
    
    while (1) {
        int cfd = accept(sb_fd, NULL, NULL);
        if (cfd >= 0) { 
            atender_cliente(cfd); 
            close(cfd); 
        }
    }
    return 0;
}







