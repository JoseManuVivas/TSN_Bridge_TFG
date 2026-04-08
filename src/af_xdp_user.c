/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
// #include <linux/ipv6.h>
#include <netinet/ip.h>
// #include <linux/icmpv6.h>
#include <netinet/ip_icmp.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX
#define MAX_SOCKS 2

static struct xdp_program *prog[MAX_SOCKS]; // un programa XDP por socket
int xsk_map_fd[MAX_SOCKS];
bool custom_xsk = false;

// Configuración de esta ejecución
struct config cfgs[MAX_SOCKS] = {
    [0] = {
        .ifname = "s1-eth1",
        .filename = "build/af_xdp_kern.o",
        .progname = "xdp_sock_prog",
        .attach_mode = XDP_MODE_SKB,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .xsk_bind_flags = XDP_COPY,
		.xsk_poll_mode = false
    },
    [1] = {
        .ifname = "s1-eth2",
        .filename = "build/af_xdp_kern.o",
        .progname = "xdp_sock_prog",
        .attach_mode = XDP_MODE_SKB,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .xsk_bind_flags = XDP_COPY,
		.xsk_poll_mode = false
    }
};

// Estructura que define la información de la UMEM
struct xsk_umem_info {
	// Los anillos son colas FIFO circulares que almacenan los offsets de los frames respecto la dirección de inicio de la UMEM
	// Puntero al siguiente índice de la Fill Queue: Productor. Donde el usuario escribe

	// Las Fill Queues son específicas de sockets. Estos serán los punteros a los anillos del primer socket que se cree
	struct xsk_ring_prod fq;
	// Puntero al siguiente índice de la Completion Queue: Consumidor. Donde el usuario lee para liberar buffers transmitidos
	struct xsk_ring_cons cq; 
	// Puntero a la UMEM, que es la memoria compartida entre el espacio de usuario y el kernel
	struct xsk_umem *umem;

	// Pool de frames libres
	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	pthread_mutex_t frame_lock; // mutex para proteger el acceso a la pila de frames libres

	// Dirección de inicio de la UMEM
	void *buffer;
};

// Estructura que define la información de un socket en cada interfaz
struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_cons cq;
	struct xsk_ring_prod fq;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint32_t outstanding_tx;

};

// Estructura para pasar argumentos a cada hilo que hará polling en un socket
struct thread_args {
    struct config *cfg;
    struct xsk_socket_info *xsk_in;
    struct xsk_socket_info *xsk_out;
};

static const char *__doc__ __attribute__((unused)) = "AF_XDP kernel bypass example\n";

static const struct option_wrapper __attribute__((unused))long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",	 required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

// atómica para que sea visible entre cores
static atomic_bool global_exit;

// Función para configurar la UMEM
static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{	
	// Estructura para almacenar información de la UMEM
	struct xsk_umem_info *umem;

	int ret;

	// Reservamos la memoria para la estructura de la UMEM. calloc es más seguro que malloc porque inicializa a 0.
	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	// Creamos la UMEM. Ahora, el Kernel conoce esta estructura y los anillos, en los que escribirá.	
	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		free(umem);
		return NULL;
	}

	// Guardamos la dirección de inicio de la UMEM en nuestra estructura para poder acceder a ella luego
	umem->buffer = buffer;

	// Inicializamos los frames libres
	// Asignamos los offsets de cada frame en el vector
	for (int i = 0; i < NUM_FRAMES; i++)
		umem->umem_frame_addr[i] = i * FRAME_SIZE;

	// Inicialmente todos los frames están disponibles
	umem->umem_frame_free = NUM_FRAMES;

	// Inicializamos el mutex
	pthread_mutex_init(&umem->frame_lock, NULL);

	return umem;
}

// Función para pasar offsets de frames desde la pila de la UMEM a la Fill Queue del socket
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	// Bloqueamos el mutex
	pthread_mutex_lock(&xsk->umem->frame_lock);
	// variable que representa el offset
	uint64_t frame;
	// Si no hay frames disponibles, devolvemos un valor inválido
	if (xsk->umem->umem_frame_free == 0) {
		pthread_mutex_unlock(&xsk->umem->frame_lock);
		return INVALID_UMEM_FRAME;
	}

	// Pre-decremento. Muy eficiente, porque al mismom tiempo disminuyemos en 1 el número de frames libres y obtenemos el índice del siguiente frame libre 
	// porque en el vector se indexa desde 0.
	frame = xsk->umem->umem_frame_addr[--xsk->umem->umem_frame_free];
	// Apuntamos un valor inválido para evitar que se vuelva a usar el mismo frame sin liberarlo.
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free] = INVALID_UMEM_FRAME;
	// Desbloqueamos el mutex
	pthread_mutex_unlock(&xsk->umem->frame_lock);

	return frame;
}

// Función para liberar un frame (meter su offset en la última posición de la pila)
// Se usa esta estructura para aprovecharse de la propiedad de localidad temporal.
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	// Bloqueamos el mutex
	pthread_mutex_lock(&xsk->umem->frame_lock);
	// Si no está llena la pila de frames libres (no debería)
	assert(xsk->umem->umem_frame_free < NUM_FRAMES);

	// Guarda el frame en la cima de la pila
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free++] = frame;
	// Desbloqueamos el mutex
	pthread_mutex_unlock(&xsk->umem->frame_lock);
}


// Función para obtener el número de frames disponibles
static uint64_t xsk_umem_free_frames(struct xsk_umem_info *umem)
{
	// Bloqueamos el mutex
	pthread_mutex_lock(&umem->frame_lock);
	// Devolvemos el número de frames disponibles
	uint64_t ret = umem->umem_frame_free;
	// Desbloqueamos el mutex
	pthread_mutex_unlock(&umem->frame_lock);
	// Devolvemos el número de frames disponibles
	return ret;
}

// Función para configurar el socket AF_XDP
static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem,
							bool esPrimero,
							int xsk_map_fd
						)
{
	// Preparamos la estructura de configuración
	struct xsk_socket_config xsk_cfg = {0};
	// Estructura final que devolveremos con toda la información del socket AF_XDP
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	// Reservamos memoria para la estructura del socket AF_XDP. calloc es más seguro que malloc porque inicializa a 0.
	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem; // Vinculamos formalmente la UMEM con el socket
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS; // Tamaño de la cola de recepción
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS; // Tamaño de la cola de transmisión
	xsk_cfg.xdp_flags = cfg->xdp_flags; // Asignamos los flgas de XDP según la configuración (SKB)
	xsk_cfg.bind_flags = cfg->xsk_bind_flags; // Asignamos los flags de bind según la configuración (copy)
	// Si hemos determinado que el programa XDP es personalizado, hay que indicarle a libxdp que no cargue el programa
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;

	
	// Caso para el socket de s1-eth1
	if (esPrimero) {
		ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
                     cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                     &xsk_info->tx, &xsk_cfg);
		// Asignamos los anillos
		xsk_info->fq = umem->fq;
		xsk_info->cq = umem->cq;
	
	} else {
		// Caso para el socket de s1-eth2
		// Activamos el flag de UMEM compartida:
		xsk_cfg.bind_flags |= XDP_SHARED_UMEM;
		ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
                     cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                     &xsk_info->tx, &xsk_info->fq, &xsk_info->cq, &xsk_cfg);
	}

	if (ret) {
		fprintf(stderr, "ERROR: Falló la creación del socket %s: %s\n", cfg->ifname, strerror(-ret));
		goto error_exit;
	}

	if (custom_xsk) {
		// Añadimos el descriptor del socket AF_XDP al mapa(cuyo descriptor ya tenemos). ¿En que posición? Pues en la
		// correspondiente al cfg->sk_if_queue, que es el índice de la cola de recepción que hemos configurado para este socket AF_XDP.
		// si se quisiera usar otro índice habría que usar la función bpf_map_update_elem() directamente.
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	} else {
		// Por si hubiera algún programa por defecto
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	// Reservamos espacio en la Fill Queue para escribir los offsets de los frames. Se asume que se tiene espacio
	ret = xsk_ring_prod__reserve(&xsk_info->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);
	
	// Si no se ha podido reservar el espacio, hay un error
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		// Esta función devuelve la dirección de memoria exacta del siguiente índice de la Fill Queue donde se escribe el offset.
		*xsk_ring_prod__fill_addr(&xsk_info->fq, idx++) =
			// Y esta función devuelve el offset del siguiente frame libre
			xsk_alloc_umem_frame(xsk_info);
	
	// Sincroniza el Producer con el Consumer para el Kernel.
	xsk_ring_prod__submit(&xsk_info->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	free(xsk_info);
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	// Un truquillo para despertar al Kernel e indicarle que ya tiene cosas para enviar en el TX ring
	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	// Obtenemos cuantos frames hay en la CQ disponibles para leer y colocamos el puntero donde nos toca seguir leyendo
	completed = xsk_ring_cons__peek(&xsk->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);
	
	// En caso de que haya frames en la CQ sabemos que ya han terminado de ser transmitidos, por lo que podemos meterlos en la pila de frames libres
	if (completed > 0) {
		for (int i = 0; i < completed; i++) {
		uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->cq, idx_cq++);	
		addr = addr & ~(FRAME_SIZE - 1);
		// Liberamos el frame
		xsk_free_umem_frame(xsk, addr);
		}
		
		// Indicamos al Kernel las consumiciones que hemos hecho, por lo que ya puede usar esas posiciones para producir							  
		xsk_ring_cons__release(&xsk->cq, completed);
		// Restamos (teniendo en cuenta que nunca pase de 0)
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

/* static uint16_t calc_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
} */

static bool process_packet(struct xsk_socket_info *xsk_in, struct xsk_socket_info *xsk_out, 
			   uint64_t addr, uint32_t len)
{
	// Obtenemos el puntero a la dirección de inicio del paquete
	uint8_t *pkt = xsk_umem__get_data(xsk_in->umem->buffer, addr);

	/* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	printf("Recibido paquete de longitud %u\n", len);

	// Bridge simple entre dos interfaces
	int ret;
	uint32_t tx_idx = 0;

	// Aritmética de punteros básica

	// DEBUG: Vamos a usar una forma más básica de calcular el tamaño de las cabeceras

	// Verificamos tamaño:
	if (len < sizeof(struct ethhdr))
		return false;

	struct ethhdr *eth = (struct ethhdr *) pkt;

	uint16_t proto = ntohs(eth->h_proto);

	// Verificamos primero los protocolos. Permitimos tambien ARP para aprendizaje
	if (proto != ETH_P_IP && proto != ETH_P_ARP)
		return false;

	printf("La cabecera Ethernet ocupa %ld bytes\n", sizeof(*eth));
	// struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
	if (proto == ETH_P_ARP) {
		// Para hacer menos verificaciones
		goto forward;
	} else {

		// Verificamos que el tamaño de la cabecera IPv4 sea correcto
		if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
			return false;

		// Cambiamos por IPv4
		struct iphdr *ipv4 = (struct iphdr *) (pkt + sizeof(struct ethhdr));

		if (ipv4->ihl < 5 || ipv4->ihl > 15) {
			printf("Tamaño de cabecera IPv4 no válido\n");
			return false;
		}

		/* if (ipv4->protocol != IPPROTO_ICMP) {
			printf("Es un paquete IPv4 pero no es ICMP\n");
			return false;
		} */

		printf("La cabecera IPv4 ocupa %d bytes\n", ipv4->ihl * 4);


		if (ipv4->protocol == IPPROTO_ICMP) {

			if (len < sizeof(struct ethhdr) + (uint32_t)ipv4->ihl * 4 + sizeof(struct icmphdr))
				return false;

			struct icmphdr *icmp = (struct icmphdr *) (pkt + sizeof(struct ethhdr) + ipv4->ihl * 4);
			if (icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY) {
				printf("Es un paquete ICMP pero no es pregunta o respuesta\n");
				printf("La cabecera ICMP ocupa %ld bytes\n", sizeof(*icmp));
				return false;
			}
		}

		// struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv4 + 1);

		// Comprobaciones básicas de seguridad. Verificamos que:
		// La cabecera IPv4 especifique que el protocolo concreto que maneja es ICMP (para pings)
		// Es un mensaje ECHO REQUEST

		// Guardamos el destino original (nosotros) en tmp_mac
		fflush(stdout);
	}

	// DEBUG: Quitamos todo esto
	
	// Eliminamos el código que intercambia cabeceras
	/* memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	// Copiamos el origen original en el nuevo destino (para devolverlo)
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	// Copiamos el destino original en el nuevo origen
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	memcpy(&tmp_ip, &ipv4->saddr, sizeof(tmp_ip));
	memcpy(&ipv4->saddr, &ipv4->daddr, sizeof(tmp_ip));
	memcpy(&ipv4->daddr, &tmp_ip, sizeof(tmp_ip)); */
	

	// DEBUG: De momento vamos a retirar el checksum
	/* csum_replace2(&icmp->checksum,
				htons(ICMP_ECHO << 8),
				htons(ICMP_ECHOREPLY << 8)); */

	// icmp->checksum = 0;

	/* Here we sent the packet out of the receive port. Note that
		* we allocate one entry and schedule it. Your design would be
		* faster if you do batch processing/transmission */
		
forward: 
	// Reservamos espacio para un paquete en el TX ring del socket de salida
	ret = xsk_ring_prod__reserve(&xsk_out->tx, 1, &tx_idx);
	if (ret != 1) {
		return false;
	}

	// Ahora sí, con Zero-copy dejamos la dirección del nuevo paquete y su longitud
	xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&xsk_out->tx, 1);

	printf("Se ha escrito correctamente en el TX Ring\n");
	fflush(stdout);

	// Aumentamos en uno el número de paquetes que están "en proceso de envío"
	xsk_out->outstanding_tx++; 
	printf( "RESISTIRÉ, ERGUIDO FRENTE A TODO!!\n");
	return true;

}

static void handle_receive_packets(struct xsk_socket_info *xsk_in, struct xsk_socket_info *xsk_out)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	// Función de Consumidor, que pregunta al RX del socket cuántos paquetes le ha dejado el Kernel y devuelve dicho número
	rcvd = xsk_ring_cons__peek(&xsk_in->rx, RX_BATCH_SIZE, &idx_rx);
	// Si no hay paquetes recibidos, simplemente salimos de la función. Esto sirve para el busy polling.
	if (!rcvd)
		return;

	// Obtenemos el número de frames libres. La función calcula el espacio físico libre real en el anillo FQ y lo compara con los frames que tiene 
	// el socket y que realmente se pueden usar para rellenar la FQ, que ha gastado offsets en los frames recibidos en el RX.
	stock_frames = xsk_prod_nb_free(&xsk_in->fq,
					xsk_umem_free_frames(xsk_in->umem));
	
	// Si tenemos frames disponibles para reponer la FQ...
	if (stock_frames > 0) {

		// Intentamos reservar ese número de posiciones en la FQ
		ret = xsk_ring_prod__reserve(&xsk_in->fq, stock_frames,
					     &idx_fq);

		// Esto en caso de que, por algún motivo extraño fallara xsk_prod_nb_free
		if (ret > 0) {
            // Rellenamos solo la cantidad que realmente pudimos reservar
            for (i = 0; i < ret; i++)
                *xsk_ring_prod__fill_addr(&xsk_in->fq, idx_fq++) = xsk_alloc_umem_frame(xsk_in);

            xsk_ring_prod__submit(&xsk_in->fq, ret);
        }
	
	}

	// Recorremos el RX ring y sus descriptores
	for (i = 0; i < rcvd; i++) {
		// Obtenemos la direccion (offset) donde empieza el paquete y su longitud
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk_in->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk_in->rx, idx_rx++)->len;

		// Si el paquete no se ha podido procesar por algún motivo, simplemente liberamos el frame, DROP del paquete
		if (!process_packet(xsk_in, xsk_out, addr, len)) {
			addr = addr & ~(FRAME_SIZE - 1);
			xsk_free_umem_frame(xsk_in, addr);
			printf("PRIMER PAQUETE LIBERADO\n");
		}

	}

	// Avanzamos el puntero de consumidor del Kernel, sirve para indicarle que ya hemos leído los frames del RX ring y el Kernel ya puede usarlos
	xsk_ring_cons__release(&xsk_in->rx, rcvd);

	printf("Transmisión completada!!\n");
	fflush(stdout);
	complete_tx(xsk_out);
	printf("Ring TX liberado\n");
  }

// Función que se ejecutará en cada hilo, que hace polling de un socket concreto
static void *rx_thread(void *arg)
{
    struct thread_args *targs = (struct thread_args *)arg;
    struct pollfd fds = {
        .fd     = xsk_socket__fd(targs->xsk_in->xsk),
        .events = POLLIN
    };

    while (!global_exit) {
        int timeout = targs->cfg->xsk_poll_mode ? -1 : 0;
        poll(&fds, 1, timeout);

        if (fds.revents & POLLIN)
            handle_receive_packets(targs->xsk_in, targs->xsk_out);
    }
    return NULL;
}

  // Función principal para detectar paquetes recibidos en el RX ring del socket y 
/* static void rx_and_process(struct config cfgs[],
			   struct xsk_socket_info *xsk_socket[])
{	
	// Estructura estándar de Linux para monitorizar descriptores de archivos.
	struct pollfd fds[MAX_SOCKS];
	int nfds = MAX_SOCKS;

	// Función de <string.h> para poner a 0 un número N de bytes.
	memset(fds, 0, sizeof(fds));

	// Obtenemos el descriptor de cada socket y los monitorizamos
	for (int i = 0; i < MAX_SOCKS; i++) {
		fds[i].fd = xsk_socket__fd(xsk_socket[i]->xsk);
		// El evento que esperaremos será el de datos de entrada.
		fds[i].events = POLLIN;
	}

	// Bucle principal del programa, mientras no se pulse Ctrl+C para salir, que hará que global_exit sea true y se salga del bucle.
	while(!global_exit) {

		int timeout = cfgs[0].xsk_poll_mode ? -1 : 0;

		poll(fds, nfds, timeout);

		for (int i = 0; i < MAX_SOCKS; i++) {
			// ¿Hay datos en este socket (i)?
			if (fds[i].revents & POLLIN) {
				// RECIBE de i, ENVÍA a (i ^ 1)
				// i=0 -> destino=1 | i=1 -> destino=0
				handle_receive_packets(xsk_socket[i], xsk_socket[i ^ 1]);
			}
    	}
	}
} */

/* #define NANOSEC_PER_SEC 1000000000 10^9 
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
} 

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
} */

// Rutina de captura de señal SIGINT, para salir del programa limpiamente al pulsar Ctrl+C
static void exit_application(int signal)
{
    for (int i = 0; i < MAX_SOCKS; i++) {
        if (prog[i]) {
            xdp_program__detach(prog[i], cfgs[i].ifindex, cfgs[i].attach_mode, 0);
            xdp_program__close(prog[i]);
        }
    }
    (void)signal;
    global_exit = true;
}

int main(int argc, char **argv)
{	
	void *packet_buffer; // dirección de inicio de la UMEM
	uint64_t packet_buffer_size; // tamaño de la UMEM
	// establecemos como infinito el límite de memoria que se puede bloquear para que no sea swapeada
	// por eso hay que ejecutar el programa con sudo
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	// estructura para manejar la UMEM
	struct xsk_umem_info *umem;

	// Definimos los dos sockets para el bridging
	// estructura para manejar el socket AF_XDP
	struct xsk_socket_info *xsk_socket[MAX_SOCKS];
	int err;
	// para mensajes de error
	char errmsg[1024];

	// Capturamos la señal para salir del programa limpiamente al pulsar Ctrl+C
	signal(SIGINT, exit_application);


	// Puntero al mapa xsks
	struct bpf_map *map;

	for (int i = 0; i < MAX_SOCKS; i++) {
		cfgs[i].ifindex = if_nametoindex(cfgs[i].ifname);
		if (cfgs[i].ifindex == 0) {
			fprintf(stderr, "ERR: La interfaz %s no existe\n", cfgs[i].ifname);
			return EXIT_FAIL;
		}
		if (cfgs[i].filename[0] != 0) {
			custom_xsk = true;
			// Esto en caso de que el bytecode para el programa XDP no se hay cargado todavía

			// Macro de libxdp para cargar el programa XDP. Crea una estructura de opciones.
				DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
					.open_filename = cfgs[i].filename,
				);

				// Para definir el programa XDP
				if (cfgs[i].progname[0] != 0)
					xdp_opts.prog_name = cfgs[i].progname;

		
				// Preparación del código para el Kernel
				prog[i] = xdp_program__create(&xdp_opts);

				// Gestión de errores al crear el programa XDP
				err = libxdp_get_error(prog[i]);
				if (err) {
					libxdp_strerror(err, errmsg, sizeof(errmsg));
					fprintf(stderr, "ERR: loading program: %s\n", errmsg);
					return err;
				}


			// Cargamos el programa XDP en la interfaz correspondiente
			err = xdp_program__attach(prog[i], cfgs[i].ifindex, cfgs[i].attach_mode, 0);
			if (err) {
				libxdp_strerror(err, errmsg, sizeof(errmsg));
				fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
					cfgs[i].ifname, errmsg, err);
				return err;
			}

				// Al haber creado el programa XDP, obtenemos el puntero al mapa xsks
			map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog[i]), "xsks_map");
			if (!map) {
				fprintf(stderr, "ERROR: mapa 'xsks_map' no encontrado\n");
				exit(EXIT_FAILURE);
			}
	
			// De puntero a mapa a FD
			xsk_map_fd[i] = bpf_map__fd(map);
			
			if (xsk_map_fd[i] < 0) {
				fprintf(stderr, "ERROR: no xsks map found: %s\n",
					strerror(xsk_map_fd[i]));
				exit(EXIT_FAILURE);
			}
		}
	}


	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 *
	 * NOTE: since kernel v5.11, eBPF maps allocations are not tracked
	 * through the process anymore. Now, eBPF maps are accounted to the
	 * current cgroup of which the process that created the map is part of
	 * (assuming the kernel was built with CONFIG_MEMCG).
	 *
	 * Therefore, you should ensure an appropriate memory.max setting on
	 * the cgroup (via sysfs, for example) instead of relying on rlimit.
	 */

	// Si da error es que no se ha podido establecer el límite de memoria para bloquear
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Reservamos para la UMEM 4096x4096 bytes de memoria
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

	// Reservamos la memoria alineada con el inicio de una página, exigencia del Kernel para UMEM.
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Inicializamos la UMEM
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	bool esPrimero = true;
	// Creamos los sockets AF_XDP
	for (int i = 0; i < MAX_SOCKS; i++) {
		xsk_socket[i] = xsk_configure_socket(&cfgs[i], umem, esPrimero, xsk_map_fd[i]);
		esPrimero = false;
		if (xsk_socket[i] == NULL) {
			fprintf(stderr, "ERROR: Can't create xsk socket \"%s\"\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* // Función principal de recepción y procesamiento de paquetes.
	rx_and_process(cfgs, xsk_socket); */

	// Creamos cada thread
	pthread_t threads[MAX_SOCKS];
	struct thread_args targs[MAX_SOCKS];

	// Definimos los argumentos de cada thread
	for (int i = 0; i < MAX_SOCKS; i++) {
		targs[i].cfg     = &cfgs[i];
		targs[i].xsk_in  = xsk_socket[i];
		targs[i].xsk_out = xsk_socket[i ^ 1];
		pthread_create(&threads[i], NULL, rx_thread, &targs[i]);
	}

	// Esperamos a que ambos threads terminen (cuando global_exit = true)
	for (int i = 0; i < MAX_SOCKS; i++)
		pthread_join(threads[i], NULL);

	// Limpiamos los sockets
	for (int i = 0; i < MAX_SOCKS; i++) {
		xsk_socket__delete(xsk_socket[i]->xsk);
		free(xsk_socket[i]);
	}
	// Destruimos el mutex
	pthread_mutex_destroy(&umem->frame_lock);
	xsk_umem__delete(umem->umem);
	free(umem);
	free(packet_buffer);

	return EXIT_OK;
}
