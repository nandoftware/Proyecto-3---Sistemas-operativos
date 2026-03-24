/*
 * safebox.h
 *
 * CI3825 - Sistemas de Operacion I
 * Proyecto 3 - SafeBox
 *
 * ARCHIVO PROVISTO POR EL PROFESOR - NO MODIFICAR
 *
 * Contiene:
 *   - Constantes del protocolo (opcodes, codigos de respuesta)
 *   - Estructura del header de archivo en disco
 *   - Estructura del mensaje de autenticacion
 *   - Funcion de log (inline, lista para usar)
 *   - Hash djb2 (inline, lista para usar)
 */

#ifndef SAFEBOX_H
#define SAFEBOX_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* ─────────────────────────────────────────────
 * Límites del protocolo
 * ───────────────────────────────────────────── */
#define MAX_KEY_LEN 64    /* Longitud máxima de una clave (en bytes), incluyendo el terminador nulo. */
#define MAX_FNAME_LEN 256 /* Longitud máxima de una ruta de archivo (en bytes), incluyendo el terminador nulo. */

/* ─────────────────────────────────────────────
 * Rutas del sistema
 * ───────────────────────────────────────────── */
#define SB_SOCKET_PATH "/tmp/safebox.sock"
#define SB_LOG_PATH "/tmp/safebox.log"
#define SB_PID_PATH "/tmp/safebox.pid"

/* ─────────────────────────────────────────────
 * Opcodes del protocolo (1 byte)
 * ───────────────────────────────────────────── */
#define SB_OP_LIST 0x01 /* listar archivos en el safebox          */
#define SB_OP_GET 0x02  /* obtener un archivo (recibe fd anonimo) */
#define SB_OP_PUT 0x03  /* guardar un archivo en el safebox       */
#define SB_OP_DEL 0x04  /* eliminar un archivo del safebox        */
#define SB_OP_BYE 0x05  /* cerrar sesion limpiamente              */

/* ─────────────────────────────────────────────
 * Codigos de respuesta del daemon (1 byte)
 * ───────────────────────────────────────────── */
#define SB_OK 0x00          /* operacion exitosa                  */
#define SB_ERR_AUTH 0x01    /* autenticacion fallida              */
#define SB_ERR_NOFILE 0x02  /* archivo no encontrado              */
#define SB_ERR_CORRUPT 0x03 /* archivo corrupto (magic invalido)  */
#define SB_ERR_EXISTS 0x04  /* archivo ya existe                  */
#define SB_ERR_IO 0x05      /* error de I/O generico              */

/* ─────────────────────────────────────────────
 * Formato de archivo en disco
 *
 * Estructura en disco:
 *   [ sb_file_header_t (8 bytes, en claro) ]
 *   [ payload cifrado (payload_size bytes)  ]
 *
 * El payload cifrado es:
 *   XOR("SBX!" + contenido_original, clave)
 *
 * Al descifrar: si los primeros 4 bytes == "SBX!"
 * el archivo es valido y el contenido empieza en offset 4.
 * ───────────────────────────────────────────── */
#define SB_MAGIC "SBX!" /* 4 bytes: 0x53 0x42 0x58 0x21  */
#define SB_MAGIC_LEN 4
#define SB_VERSION 0x01

#pragma pack(push, 1)
typedef struct
{
    uint8_t version;       /* SB_VERSION = 0x01                 */
    uint32_t payload_size; /* bytes del payload cifrado          */
    uint8_t reserved[3];   /* ceros — reservado para IV futuro   */
} sb_file_header_t;        /* total: 8 bytes                     */
#pragma pack(pop)

/* ─────────────────────────────────────────────
 * Mensaje de autenticacion
 *
 * El cliente envia esto al conectarse, ANTES
 * de cualquier otra operacion.
 * ───────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct
{
    uint8_t op;             /* opcode de la operacion deseada     */
    uint32_t password_hash; /* djb2(password ingresado)           */
} sb_auth_msg_t;
#pragma pack(pop)

/* ─────────────────────────────────────────────
 * Hash djb2
 *
 * Uso:
 *   uint32_t h = sb_djb2("mi_password");
 * ───────────────────────────────────────────── */
static inline uint32_t sb_djb2(const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++))
        hash = ((hash << 5) + hash) + (uint32_t)c;
    return hash;
}

/* ─────────────────────────────────────────────
 * Logger
 *
 * Uso:
 *   sb_log(logfd, SB_LOG_OK,   "GET %s entregado a pid=%d", name, pid);
 *   sb_log(logfd, SB_LOG_WARN, "autenticacion fallida uid=%d", uid);
 *
 * Niveles disponibles: SB_LOG_INFO, SB_LOG_OK, SB_LOG_WARN, SB_LOG_ERROR
 * ───────────────────────────────────────────── */
typedef enum
{
    SB_LOG_INFO = 0,
    SB_LOG_OK = 1,
    SB_LOG_WARN = 2,
    SB_LOG_ERROR = 3
} sb_loglevel_t;

static inline void sb_log(int logfd, sb_loglevel_t level, const char *fmt, ...)
{
    if (logfd < 0)
        return;

    /* timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    /* nivel */
    static const char *lvl_str[] = {"INFO ", "OK   ", "WARN ", "ERROR"};
    const char *lvl = (level <= SB_LOG_ERROR) ? lvl_str[level] : "INFO ";

    /* mensaje */
    char msgbuf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
    va_end(ap);

    /* linea completa */
    char line[600];
    int len = snprintf(line, sizeof(line),
                       "[%s] [%s] %s\n", timebuf, lvl, msgbuf);

    /*
     * write() con O_APPEND es atomico para escrituras <= PIPE_BUF.
     * No necesitamos mutex para el log.
     */
    (void)write(logfd, line, (size_t)len);
}

/* Macro conveniente para no pasar el fd siempre */
#define LOG(fd, lvl, ...) sb_log((fd), (lvl), __VA_ARGS__)

#endif /* SAFEBOX_H */
