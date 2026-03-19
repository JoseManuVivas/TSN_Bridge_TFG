# DEFINICIÓN DE COMPILADORES Y FLAGS
CLANG = clang
CC = gcc

# Flags para el Kernel (XDP)
XDP_CFLAGS = -O2 -g -target bpf

# Flags para el Usuario (C estándar)
# -O3 para máximo rendimiento, -Wall para ver todos los avisos
USER_CFLAGS = -O3 -Wall

# Librerías necesarias para AF_XDP
LIBS = -lxdp -lbpf

# RUTAS DE ARCHIVOS

KERN_SRC = src/bridge_kern.c
USER_SRC = src/bridge_user.c
KERN_OBJ = build/bridge_kern.o
USER_BIN = build/bridge_user

# REGLA PRINCIPAL
# Ahora 'all' necesita tanto el objeto del Kernel como el binario de Usuario
all: $(KERN_OBJ) $(USER_BIN)

#  COMPILACIÓN DEL KERNEL (eBPF)
$(KERN_OBJ): $(KERN_SRC) src/shared_defs.h
	@mkdir -p build
	$(CLANG) $(XDP_CFLAGS) -c $< -o $@

#  COMPILACIÓN DEL USUARIO (C)
$(USER_BIN): $(USER_SRC) src/shared_defs.h
	@mkdir -p build
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBS)

# 6. REGLA DE LIMPIEZA
clean:
	rm -rf build/