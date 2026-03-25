# DEFINICIÓN DE COMPILADORES Y FLAGS
CLANG = clang
CC = gcc

# Flags para el Kernel (XDP)
XDP_CFLAGS = -O2 -g -target bpf -I./common

# Flags para el Usuario (C estándar)
# -O3 para máximo rendimiento, -Wall para ver todos los avisos
USER_CFLAGS = -O3 -Wall -I./common

# Librerías necesarias para AF_XDP
LIBS = -lxdp -lbpf -lelf

# RUTAS DE ARCHIVOS

KERN_SRC = src/af_xdp_kern.c
USER_SRC = src/af_xdp_user.c
KERN_OBJ = build/af_xdp_kern.o
USER_BIN = build/af_xdp_user

# ARCHIVOS COMUNES DE AF_XDP_TUTORIAL
COMMON_SRC = common/common_user_bpf_xdp.c

# REGLA PRINCIPAL
# Ahora 'all' necesita tanto el objeto del Kernel como el binario de Usuario
all: $(KERN_OBJ) $(USER_BIN)

#  COMPILACIÓN DEL KERNEL (eBPF)
$(KERN_OBJ): $(KERN_SRC)
	@mkdir -p build
	$(CLANG) $(XDP_CFLAGS) -c $< -o $@

#  COMPILACIÓN DEL USUARIO (C)
$(USER_BIN): $(USER_SRC) $(COMMON_SRC)
	@mkdir -p build
	$(CC) $(USER_CFLAGS) $^ -o $@ $(LIBS)

# 6. REGLA DE LIMPIEZA
clean:
	rm -rf build/