# Makefile
# CI3825 - Sistemas de Operacion I
# Proyecto 3 - SafeBox
#
# ARCHIVO PROVISTO POR EL PROFESOR - NO MODIFICAR
#
# Targets disponibles:
#   make           -> compila todo (daemon + shell)
#   make clean     -> elimina binarios y archivos temporales
#   make test      -> ejecuta test_basic.sh (26 verificaciones automaticas)
#   make valgrind  -> corre el daemon en modo no-daemon bajo valgrind
#                     (requiere: sudo apt-get install valgrind)

CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -I./include
LDFLAGS =

DAEMON_SRC = src/safebox-daemon.c
SHELL_SRC    = src/safebox-shell.c src/safebox_client.c

DAEMON_BIN = safebox-daemon
SHELL_BIN  = safebox-shell

.PHONY: all clean test valgrind check-valgrind

all: $(DAEMON_BIN) $(SHELL_BIN)

$(DAEMON_BIN): $(DAEMON_SRC) include/safebox.h
	$(CC) $(CFLAGS) -o $@ $(DAEMON_SRC) $(LDFLAGS)

$(SHELL_BIN): $(SHELL_SRC) include/safebox.h include/safebox_client.h
	$(CC) $(CFLAGS) -o $@ $(SHELL_SRC) $(LDFLAGS)

clean:
	rm -f $(DAEMON_BIN) $(SHELL_BIN)
	rm -f /tmp/safebox.sock /tmp/safebox.pid /tmp/safebox.log

test: all
	@rm -f /tmp/safebox.sock /tmp/safebox.pid /tmp/safebox.log
	@bash tests/test_basic.sh

check-valgrind:
	@which valgrind > /dev/null 2>&1 || \
		{ echo ""; \
		  echo "ERROR: valgrind no esta instalado."; \
		  echo "Instalar con: sudo apt-get install -y valgrind"; \
		  echo ""; \
		  exit 1; }

valgrind: all check-valgrind
	@echo ""
	@echo "Iniciando daemon bajo valgrind (modo no-daemonizar)..."
	@echo ""
	@echo "Instrucciones:"
	@printf "  1. Espere ver: safebox password:\n"
	@printf "  2. Ingrese el password: sbx2026\n"
	@printf "  3. En OTRA terminal: ./safebox-shell\n"
	@printf "  4. Haga sus operaciones (put, get, list, del)\n"
	@printf "  5. En la otra terminal: kill -TERM $$(pgrep -f safebox-daemon)\n"
	@printf "  6. Vea el reporte de memoria aqui\n"
	@echo ""
	@mkdir -p ./mi_boveda
	SAFEBOX_NO_DAEMON=1 valgrind \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--error-exitcode=1 \
		./$(DAEMON_BIN) ./mi_boveda
