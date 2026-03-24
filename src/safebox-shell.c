/*
 * safebox-shell.c
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ARCHIVO PROVISTO POR EL PROFESOR - NO MODIFICAR
 *
 * Minishell interactivo para usar el safebox.
 * Llama las funciones definidas en safebox_client.h.
 * Los estudiantes NO tocan este archivo.
 *
 * Compilacion (la hace el Makefile):
 *   gcc -std=c11 -Wall -Wextra -Werror \
 *       -Iinclude \
 *       -o safebox-shell src/safebox-shell.c src/safebox_client.c
 *
 * Uso:
 *   ./safebox-shell
 *   safebox password: ****
 *   safebox> put secreto.txt ~/documentos/archivo.txt
 *   safebox> list
 *   safebox> get secreto.txt
 *   safebox> del secreto.txt
 *   safebox> exit
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

#include "safebox.h"
#include "safebox_client.h"

#define MAX_LINE 512
#define MAX_LSBUF 8192

/* ─────────────────────────────────────────────
 * Lectura de password sin eco (igual que el daemon)
 * ───────────────────────────────────────────── */
static void read_password(const char *prompt, char *buf, size_t buflen)
{
    printf("%s", prompt);
    fflush(stdout);

    /*
     * Si stdin es un terminal (tty), desactivar echo para que el
     * password no se muestre en pantalla.
     * Si stdin es un pipe (modo test/script), leer directamente.
     */
    if (isatty(STDIN_FILENO))
    {
        struct termios old_t, new_t;
        tcgetattr(STDIN_FILENO, &old_t);
        new_t = old_t;
        new_t.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_t);

        if (fgets(buf, (int)buflen, stdin) == NULL)
            buf[0] = '\0';

        tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        printf("\n");
    }
    else
    {
        if (fgets(buf, (int)buflen, stdin) == NULL)
            buf[0] = '\0';
    }

    /* quitar newline si hay */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
}

/* ─────────────────────────────────────────────
 * Ayuda de comandos
 * ───────────────────────────────────────────── */
static void print_help(void)
{
    printf("Comandos disponibles:\n");
    printf("  list                      listar archivos en el safebox\n");
    printf("  get  <nombre>             leer un archivo del safebox\n");
    printf("  put  <nombre> <ruta>      guardar un archivo en el safebox\n");
    printf("  del  <nombre>             eliminar un archivo del safebox\n");
    printf("  help                      mostrar esta ayuda\n");
    printf("  exit / quit               cerrar sesion\n");
}

/* ─────────────────────────────────────────────
 * Comando: get
 * Recibe el fd anonimo y vuelca el contenido a stdout
 * ───────────────────────────────────────────── */
static void cmd_get(int sockfd, const char *filename)
{
    int fd = sb_get(sockfd, filename);
    if (fd < 0)
    {
        fprintf(stderr, "error: no se pudo obtener '%s'\n", filename);
        return;
    }

    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    printf("\n");

    close(fd);
}

/* ─────────────────────────────────────────────
 * main
 * ───────────────────────────────────────────── */
int main(void)
{
    char password[MAX_KEY_LEN] = {0};
    char line[MAX_LINE];
    char listbuf[MAX_LSBUF];

    /* leer password sin eco */
    read_password("safebox password: ", password, sizeof(password));
    if (strlen(password) == 0)
    {
        fprintf(stderr, "error: password vacio\n");
        return 1;
    }

    /* conectar al daemon */
    int sock = sb_connect(SB_SOCKET_PATH, password);
    memset(password, 0, sizeof(password)); /* limpiar password de memoria */

    if (sock < 0)
    {
        fprintf(stderr, "error: no se pudo conectar al daemon en %s\n",
                SB_SOCKET_PATH);
        fprintf(stderr, "       verifique que safebox-daemon esta corriendo\n");
        return 1;
    }

    /* loop principal */
    printf("safebox> ");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin))
    {
        /* quitar newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        /* ignorar lineas vacias */
        if (strlen(line) == 0)
        {
            printf("safebox> ");
            fflush(stdout);
            continue;
        }

        /* ── list ── */
        if (strcmp(line, "list") == 0)
        {
            memset(listbuf, 0, sizeof(listbuf));
            int n = sb_list(sock, listbuf, sizeof(listbuf));
            if (n < 0)
            {
                printf("error al listar\n");
            }
            else if (n == 0)
            {
                printf("(vacio)\n");
            }
            else
            {
                printf("%s\n", listbuf);
            }

            /* ── get <nombre> ── */
        }
        else if (strncmp(line, "get ", 4) == 0)
        {
            const char *name = line + 4;
            if (strlen(name) == 0)
            {
                printf("uso: get <nombre>\n");
            }
            else
            {
                cmd_get(sock, name);
            }

            /* ── put <nombre> <ruta> ── */
        }
        else if (strncmp(line, "put ", 4) == 0)
        {
            char *rest = line + 4;
            char *name = strtok(rest, " ");
            char *path = strtok(NULL, " ");
            if (!name || !path)
            {
                printf("uso: put <nombre> <ruta_local>\n");
            }
            else
            {
                if (sb_put(sock, name, path) == 0)
                    printf("ok\n");
                else
                    printf("error al guardar '%s'\n", name);
            }

            /* ── del <nombre> ── */
        }
        else if (strncmp(line, "del ", 4) == 0)
        {
            const char *name = line + 4;
            if (strlen(name) == 0)
            {
                printf("uso: del <nombre>\n");
            }
            else
            {
                if (sb_del(sock, name) == 0)
                    printf("ok\n");
                else
                    printf("error al eliminar '%s'\n", name);
            }

            /* ── help ── */
        }
        else if (strcmp(line, "help") == 0)
        {
            print_help();

            /* ── exit / quit ── */
        }
        else if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0)
        {
            break;
        }
        else
        {
            printf("comando desconocido: '%s'\n", line);
            printf("escriba 'help' para ver los comandos disponibles\n");
        }

        printf("safebox> ");
        fflush(stdout);
    }

    sb_bye(sock);
    printf("sesion cerrada\n");
    return 0;
}
