# 1. DEFINICIÓN DE VARIABLES
# Usamos variables para que, si el día de mañana cambias de compilador,
# solo tengas que editar una línea.
CLANG = clang
CFLAGS = -O2 -g -target bpf

# 2. RUTAS DE ARCHIVOS
# Esto ayuda a que el Makefile sepa dónde buscar y dónde escribir.
SRC = src/bridge_kern.c
OBJ = build/bridge_kern.o

# 3. REGLA PRINCIPAL (Target 'all')
# Es lo que se ejecuta cuando escribes simplemente 'make'.
# Dice: "Para completar 'all', necesito que exista el archivo $(OBJ)".
all: $(OBJ)

# 4. REGLA DE COMPILACIÓN
# Aquí definimos CÓMO se crea el .o a partir del .c
# $@ se refiere al nombre del objetivo (el .o)
# $< se refiere a la primera dependencia (el .c)
$(OBJ): $(SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

# 5. REGLA DE LIMPIEZA
# Sirve para borrar los archivos compilados y empezar de cero.
# Se ejecuta con 'make clean'.
clean:
	rm -f $(OBJ)