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

    // falto colocar el safebox
    if(argc < 2){
        perror("falta el nombre del safebox");
        exit(EXIT_FAILURE);
    }

    // ojo pelado abrimos un fd de la boveda, al final del programa debe cerrarce
    int sb_fd = open(argv[1], O_RDWR);
    if(sb_fd < 0){
        fprintf(stderr, "error: '%s' no es un drectorio valido", argv[1]);
        exit(EXIT_FAILURE);
    }
    // Paso 0: hay que verificar si el safebox existe, y si tenemos permiso de escritura y lectura
    // si no, mandamos un mensaje de error en stderr 

    // Paso 1: leemos la clave
    char clave[128];
    leer_clave_segura(clave, sizeof(clave));

    // ahora hay que validar la clave:
    if(!strcmp(PASSWORD, clave)){
        perror("clave invalida"); // temporal
        close(sb_fd);
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
    // char msg[256];
    // snprintf(msg, sizeof(msg), "daemon iniciado pid=%d", getpid());
    sb_log(log_fd, SB_LOG_INFO, "daemon iniciado pid=%d", getpid());

    while (seguir_corriendo) {

        // En SafeBox aquí iría accept() esperando conexiones.
    }

    sb_log(log_fd, SB_LOG_INFO, "SIGTERM recibido — daemon terminado limpiamente");
    // Paso 9: limpear todos los fd
    close(log_fd);
    close(sb_fd);
    // falta cerrar el fd del socket
    unlink(SB_PID_PATH);
    unlink(SB_SOCKET_PATH);

}