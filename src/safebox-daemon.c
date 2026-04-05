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
#include <signal.h>
#include <fcntl.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <dirent.h>
#include <limits.h>
#include <stdint.h>

#include "safebox.h"

#define PASSWORD "sbx2026"
#define PASSWORD_LEN 5
#define MAX_LSBUF 8192
#define MAX_PAYLOAD_SIZE 511

#pragma pack(push, 1)
typedef struct 
{
    uint8_t op;
    uint8_t payload[MAX_PAYLOAD_SIZE];
}wire_format;
#pragma pack(pop)

void int32toint8(uint32_t *number, uint8_t * payload, int begin){
    payload[begin] = (*number >> 24) & 0xFF;
    payload[begin + 1] = (*number >> 16) & 0xFF;
    payload[begin + 2] = (*number >> 8) & 0xFF;
    payload[begin + 3] = *number & 0xFF;
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
    while (payload[i] != '\0' && i < payload_size )
    {
        string[i - begin] = payload[i];
        
        i++;
        cont++;
    }
    string[i] = '\0';
    cont++;
    return cont;
}
void XOR(char * original){
    
    int g = 0;
    while (original[g] != '\0')
    {
        original[g] ^= PASSWORD[g % PASSWORD_LEN];
        g++;
    }
    
}


static void enviar_fd(int socket_fd, int fd_a_enviar) {

    /* -------------------------------------------------------
     * Necesitamos enviar al menos 1 byte de datos junto con
     * el mensaje de control. Muchos sistemas ignoran un
     * msghdr con iov_len=0 y nunca entregan el SCM_RIGHTS.
     * Enviamos un byte "insignificante" como dummy.
     * ------------------------------------------------------- */
    char dummy = '!';
    struct iovec iov = {
        .iov_base = &dummy,
        .iov_len  = sizeof(dummy)
    };

    /* -------------------------------------------------------
     * Buffer para el mensaje de control.
     *
     * CMSG_SPACE(sizeof(int)) calcula cuántos bytes necesita
     * la cabecera cmsghdr + el payload (un int = un fd).
     * Usamos un union para garantizar alineación correcta.
     * ------------------------------------------------------- */
    union {
        struct cmsghdr cmh;
        char           control[CMSG_SPACE(sizeof(int))];
    } control_buf;

    memset(&control_buf, 0, sizeof(control_buf));

    /* -------------------------------------------------------
     * Llenar el msghdr principal
     * ------------------------------------------------------- */
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control_buf.control;
    msg.msg_controllen = sizeof(control_buf.control);

    /* -------------------------------------------------------
     * Llenar el cmsghdr (cabecera del mensaje de control)
     *
     * CMSG_FIRSTHDR() devuelve puntero al primer cmsghdr
     * cmsg_level = SOL_SOCKET   (nivel socket)
     * cmsg_type  = SCM_RIGHTS   (tipo: transferir file descriptors)
     * cmsg_len   = tamaño total de este mensaje de control
     * ------------------------------------------------------- */
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    /* CMSG_DATA() apunta al payload del mensaje de control.
     * Ahí copiamos el fd que queremos transferir. */
    memcpy(CMSG_DATA(cmsg), &fd_a_enviar, sizeof(int));

    /* -------------------------------------------------------
     * Enviar el mensaje con sendmsg()
     * El kernel se encarga de duplicar el fd en el receptor.
     * ------------------------------------------------------- */
    if (sendmsg(socket_fd, &msg, 0) < 0) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }
    
}
/* ---------------------------------------------------------------
 * Variable global para comunicar el manejador de señal con el loop
 * 'volatile sig_atomic_t' es el único tipo seguro en signal handlers
 * ------------------------------------------------------------- */
static volatile sig_atomic_t seguir_corriendo = 1;

// con esta funcionsita podemos leer la clave como sudo, no devuelve nada porque de una vez la escribe en buf
static void leer_clave_segura(char *buf, size_t max) {
    /* Abrir /dev/tty: terminal del proceso, independiente de
     * si stdout/stdin están redirigidos */
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) {
        /* Fallback: usar stdin si no hay terminal */
        tty = stdin;
    }

    fprintf(tty, "safebox password: ");
    fflush(tty);

    /* Guardar configuración actual del terminal */
    struct termios original, sin_echo;
    tcgetattr(fileno(tty), &original);
    sin_echo = original;

    /* Desactivar ECHO: las teclas pulsadas no aparecen en pantalla
     * ECHO  = mostrar caracteres al escribir
     * ECHOE = mostrar borrado al presionar backspace
     * Quitamos ambas con el operador ~(NOT de bits) + &= */
    sin_echo.c_lflag &= ~(ECHO | ECHOE);

    /* Aplicar sin echo. TCSAFLUSH = aplica tras vaciar el buffer */
    tcsetattr(fileno(tty), TCSAFLUSH, &sin_echo);

    /* Leer la clave — fgets incluye el '\n', lo quitamos */
    if (fgets(buf, (int)max, tty) != NULL) {
        buf[strcspn(buf, "\n")] = '\0';
    }

    /* Restaurar configuración original */
    tcsetattr(fileno(tty), TCSAFLUSH, &original);

    /* Imprimir newline porque el Enter del usuario no se vio */
    fprintf(tty, "\n");

    if (tty != stdin) fclose(tty);
}

// esto simplemente pone el segir_corriendo en 0 (false)
static void manejador_sigterm(int sig) {
    (void)sig;                   /* suprimir warning de parámetro sin usar */
    seguir_corriendo = 0;        /* señal al loop principal para que termine */
}

int main(int argc, char *argv[]){

    // por si falto colocar el safebox
    if(argc < 2){
        perror("falta el nombre del safebox");
        exit(EXIT_FAILURE);
    }
    // printf("%ld\n", strlen(argv[1]));
    char safebox[strlen(argv[1]) + 2];
    strcpy(safebox, argv[1]);
    if(safebox[strlen(argv[1])-1] != 47){
        safebox[strlen(argv[1])] = 47;
        safebox[strlen(argv[1]) + 1] = '\0';
    }
    // printf("./test_boveda_$$");

    // ojo pelado abrimos un fd de la boveda, al final del programa debe cerrarce
    DIR *sb_fd = opendir(safebox);
    struct stat st;
    if(sb_fd == NULL){
        fprintf(stderr, "error: '%s' no es un drectorio valido\n", safebox);
        exit(EXIT_FAILURE);
    }
    stat(safebox, &st);

    // verificamos que tiene los permisos que son
    if(!(st.st_mode & S_IRUSR)){
        fprintf(stderr, "error: no se puede leer en el directorio '%s'\n", safebox);
        exit(EXIT_FAILURE);
    }
    else if(!(st.st_mode & S_IWUSR)){
        fprintf(stderr, "error: no se puede escribir en el directorio '%s'\n", safebox);
        exit(EXIT_FAILURE);
    }
    


    // Paso 0: hay que verificar si el safebox existe, y si tenemos permiso de escritura y lectura
    // si no, mandamos un mensaje de error en stderr 

    // Paso 1: leemos la clave
    char clave[128];
    leer_clave_segura(clave, sizeof(clave));

    // ahora hay que validar la clave:
    if(strcmp(PASSWORD, clave)){
        perror("clave invalida"); // temporal
        exit(EXIT_FAILURE);
    }


    // paso 2: forkeamos
    pid_t hijo_pid = fork();

    // nos aseguramos que si el fork sale mal, el programa lo capte
    if (hijo_pid < 0) {
        perror("el fork salio mal");
        exit(EXIT_FAILURE);
    }

    if (hijo_pid > 0) {
        // estamos en el padre. El se termina y dice que creo al daemon
        printf("[safebox] pid=%d listo\n", hijo_pid);
        exit(EXIT_SUCCESS);   /* padre termina aquí */
    }

    // a partir de aqui estamos en el hijo, osea, el daemon

    // creamos el fd del socked del daemon
    int daemon_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (daemon_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // unlinkeamos el path del socked de una vez
    unlink(SB_SOCKET_PATH);

    // creamos el addr para baindear el socked despues
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SB_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // aqui lo baindeamos
    if (bind(daemon_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // ponemos al socket en modo escucha, lo de que puede encolar hasta 5 conexiones - es temporal
    if (listen(daemon_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Paso 3: en este cuestionsito independizamos al daemon de la shell
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    // Paso 4: movemos los std in-out-err a dev null
    // ojo pelado porque aqui se crea y se cierra un file descriptor del dev/null
    int dev_null = open("/dev/null", O_RDWR);
    if (dev_null < 0) {
        exit(EXIT_FAILURE);
    }
    dup2(dev_null, STDIN_FILENO);    /* stdin  → /dev/null */
    dup2(dev_null, STDOUT_FILENO);   /* stdout → /dev/null */
    dup2(dev_null, STDERR_FILENO);   /* stderr → /dev/null */
    close(dev_null);                 /* ya no necesitamos este fd extra */


    // Paso 5: abrimos el logger y nos preocupamos porque abra bien
    int log_fd = open(SB_LOG_PATH,
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd < 0) {
        exit(EXIT_FAILURE);   /* stderr ya es /dev/null, no podemos reportar */ 
    }

    // Paso 6: metemos el PID del daemon (del hijo) en esta ruta especial para poder matarlo cuando se nos venga en gana
    int pid_fd = open(SB_PID_PATH,
                      O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pid_fd >= 0) {
        char pid_str[32];
        int n = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
        write(pid_fd, pid_str, (size_t)n);
        close(pid_fd);
    }

    // Paso 7: instalamos el manejador de SIGTERM
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = manejador_sigterm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);

    // ----------------- BUCLE PRINCIPAL DEL DAEMON -----------------

    // acemos los logs de que se inicio el daemon y de que esta escuchando de su socket
    sb_log(log_fd, SB_LOG_INFO, "daemon iniciado pid=%d %s", getpid(), safebox);
    sb_log(log_fd, SB_LOG_INFO, "escuchando en %s", SB_SOCKET_PATH);

    // esta funcioncita es muy importante, pues sin ella el proceso nujnca se puede cerrar bien
    // si solo dejo el accept() dentro del bucle, resulta que este carajo va a bloquear al proceso
    // mientras que le llega una conexion, incluso si mando un KILL -TERM, el proceso va a seguir
    // bloqueado por el accept, para lo cual hacia falta meterce en la shell a hacer lo que sea para 
    // que el accept reaccionace y volviera a verificar la condicion del bucle.
    // ahora este socked no se bloquea con nada.
    fcntl(daemon_fd, F_SETFL, O_NONBLOCK);
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    int cliente_fd = -1;
    while (seguir_corriendo) {
        
        int tmp_fd = accept(daemon_fd, NULL, NULL);
        // aqui empezamos con el accept() para bloquear al daemon hasta que llegue una conexion
        if (tmp_fd < 0) {
            // si el nuevo socket es -1, y como estamos en un socket no bloqueante, puede ser
            // que el accept, como no consiguio conexiones, mandace alguno de dos erroes en errno
            // EAGAIN significa: recurso temporalmente no disponible
            // EWOULDBLOCK: entiendo que este significa que una operacion no puedo completarse porque
            // no esta lista
            // El caso es que si manda alguno de estos, no queremos matar al proceso con un error
            if (!(errno == EAGAIN || errno == EWOULDBLOCK)){
                perror("accept");
                exit(EXIT_FAILURE);   /* intentar con el siguiente cliente */
            }
        }
        else{

            cliente_fd = tmp_fd;
            // para el log del pid y el uid
            if (getsockopt(cliente_fd, SOL_SOCKET, SO_PEERCRED,
                        &peer, &peer_len) == 0) {
                sb_log(log_fd, SB_LOG_INFO, "conexion entrante uid=%d pid=%d", peer.uid, peer.pid);
            }

        }

        if(cliente_fd == -1){
            continue;
        }

        // char buf[256];
        wire_format buf;
        
        // ssize_t n;
        ssize_t n = read(cliente_fd, &buf, sizeof(buf));
        

        if(n == 0){
            continue;
        }
        else if (n != sizeof(buf)){
            sb_log(log_fd, SB_LOG_ERROR, "no se puedo recibier el coso con n %d", n);
            exit(EXIT_FAILURE);
        }

        // sb_log(log_fd, SB_LOG_WARN, "se recivio: %d", buf.op);

        if(buf.op == SB_OP_LIST){
            // aqui hay dos posibilidades, si no hay mas nada entonces quiero llamar a list
            // pero si hay algo mas entonces quiero autenticar

            if(buf.payload[0] != 0x00){
                // queremos autenticar
                uint32_t pass_hash = sb_djb2(PASSWORD);
                uint8_t op;
                uint32_t n_pass;
                int8toint32(&n_pass, buf.payload);


                if (pass_hash == n_pass){
                    // le mandamos que todo chevere (0x00)
                    op = SB_OK;
                    write(cliente_fd, &op,sizeof(op));
                    sb_log(log_fd, SB_LOG_OK, "autenticacion exitosa uid=%d pid=%d", peer.uid, peer.pid);
                }
                else{
                    // le mandamos error de autenticacion (0x01)
                    op = SB_ERR_AUTH;
                    write(cliente_fd, &op, sizeof(op));
                    sb_log(log_fd, SB_LOG_WARN, "autenticacion fallida uid=%d pid=%d", peer.uid, peer.pid);
                }
            }
            else{
                // queremos hacer list 
                
                char buffer[MAX_LSBUF] = "\0";
                struct dirent *files;
                while ((files = readdir(sb_fd)) != NULL)
                {
                    if(files->d_name[0] == '.') continue;

                    strcat(buffer, files->d_name);
                    strcat(buffer, "\n");
                }
                strcat(buffer, "\0");
                // sb_log(log_fd, SB_LOG_INFO, "%d", strlen(buffer));
                if(strlen(buffer) != 0){
                    buffer[strlen(buffer) - 1] = '\0';
                }
                rewinddir(sb_fd);
                write(cliente_fd, buffer, sizeof(buffer));

            }

        }
        else if(buf.op == SB_OP_BYE){
            sb_log(log_fd, SB_LOG_INFO, "BYE uid=%d pid=%d - sesion cerrada", peer.uid, peer.pid);
            close(cliente_fd);
            cliente_fd = -1;
        }
        else if(buf.op == SB_OP_DEL){
            char origina_path[strlen(safebox) + 1];
            origina_path[strlen(safebox) + 1] = '\0';
            strcpy(origina_path, safebox);
            char filename[sizeof(buf.payload)];
            int82char(filename, buf.payload, sizeof(buf.payload), 0);

            strcat(origina_path, filename);
            
            uint8_t op = 0;
            if(unlink(origina_path) == 0){
                op = SB_OK;
                write(cliente_fd, &op, sizeof(op));
                sb_log(log_fd, SB_LOG_OK, "DEL %s - eliminado (pid=%d)", filename, peer.pid);
            }
            else{
                op = SB_ERR_NOFILE;
                write(cliente_fd, &op, sizeof(op));
                sb_log(log_fd, SB_LOG_WARN, "no se puedo eliminar %s (pid=%d)", filename, peer.pid);

            }
        }
        else if(buf.op == SB_OP_PUT){
            char origina_path[strlen(safebox) + 1];
            origina_path[strlen(safebox) + 1] = '\0';
            strcpy(origina_path, safebox);
            char filename[MAX_PAYLOAD_SIZE];
            char fp[MAX_PAYLOAD_SIZE];

            // for (int a = 0; a < 40; a++)
            // {
            //     sb_log(log_fd, SB_LOG_ERROR, "%d", buf.payload[a]);
            // }
            
            int m = int82char(filename, buf.payload, MAX_PAYLOAD_SIZE, 0);

            int u = m;
            int secure = 1;
            while (u < MAX_PAYLOAD_SIZE && secure)
            {
                if(buf.payload[u] != '\0'){
                    secure = 0;
                    u--;
                }
                u++;
            }
            

            // int tmp = 8 - (m % 8);
            sb_log(log_fd, SB_LOG_ERROR, "%d %d %d", m, u);
            int82char(fp, buf.payload,MAX_PAYLOAD_SIZE, u);
            
            strcat(origina_path, filename);
            // sb_log(log_fd, SB_LOG_ERROR, "%s", origina_path);

            FILE *fptr;
            
            fptr = fopen(origina_path, "w");
            
            int fp_fd = open(fp, O_RDONLY);

            uint8_t op = SB_OK;
            char content[1024];
            read(fp_fd, content, sizeof(content));
            // if(j != sizeof(content)){
            //     write(cliente_fd, &op, sizeof(op));
            //     sb_log(log_fd, SB_LOG_ERROR, "entre en 1");
                
            // }

            if(fptr == NULL) {
                op = SB_ERR_NOFILE;
                write(cliente_fd, &op, sizeof(op));
                sb_log(log_fd, SB_LOG_WARN, "PUT %s - no se pudo crear el archivo (pid=%d)", filename, peer.pid);
                
            }

            
            char magic[2048] = SB_MAGIC;
            
            
            
            strcat(magic, content);

            
            XOR(magic);
            // for (int a = 0; a < 40; a++)
            // {
            //     sb_log(log_fd, SB_LOG_ERROR, "%d", magic[a]);
            // }
            // char header[8];
            // uint32_t ml = SB_MAGIC_LEN ;
            // header[0] = 0x01;
            // int32toint8(&ml, header, 1);
            // header[5] = 0x00;
            // header[6] = 0x00;
            // header[7] = 0x00;

            // strcat(header, magic);

            fprintf(fptr, magic);
            fclose(fptr);
            
            // int y = 0;
            // while (h)
            // {
            //     /* code */
            // }
            
            sb_log(log_fd, SB_LOG_OK, "PUT %s - cifrado y guardado (pid=%d)", filename, peer.pid);
            write(cliente_fd, &op, sizeof(op));
            
        }
        else if(buf.op == SB_OP_GET){
            char origina_path[strlen(safebox) + 1];
            origina_path[strlen(safebox) + 1] = '\0';
            strcpy(origina_path, safebox);
            char filename[MAX_PAYLOAD_SIZE];

            int82char(filename, buf.payload, MAX_PAYLOAD_SIZE, 0);
            strcat(origina_path, filename);

            int memfd = memfd_create("contenido_descifrado", MFD_CLOEXEC);
            if (memfd < 0) {
                perror("memfd_create");
                exit(EXIT_FAILURE);
            }

            int minifd = open(origina_path, O_RDONLY);
            if(minifd < 0){
                enviar_fd(cliente_fd, minifd);
                sb_log(log_fd, SB_LOG_WARN, "GET %s - archivo no encontrado (pid=%d)", filename, peer.pid);
                close(memfd);
            }

            char content[4096];
            read(minifd, content, sizeof(content));
            
            XOR(content);
            size_t len = strlen(content);
            write(memfd, content, len);

            lseek(memfd, 0, SEEK_SET);

            sb_log(log_fd, SB_LOG_WARN, "GET %s - entregado a (pid=%d)", filename, peer.pid);
            enviar_fd(cliente_fd, memfd);

            close(memfd);
        }




    }
    
    sb_log(log_fd, SB_LOG_INFO, "SIGTERM recibido — daemon terminado limpiamente");
    // Paso 9: limpear todos los fd
    close(log_fd);
    closedir(sb_fd);
    close(daemon_fd);
    // falta cerrar el fd del socket

    unlink(SB_PID_PATH);
    unlink(SB_SOCKET_PATH);

}