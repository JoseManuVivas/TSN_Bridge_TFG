from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSSwitch
from mininet.nodelib import LinuxBridge

# Esta es la pieza que crea las etiquetas VLAN. No la toques, 
# es la que hace que el Host 1 mande paquetes con "etiqueta 10".
class VLANHost( Host ):
    def config( self, vlan_id=100, ip='' ):
        r = super( VLANHost, self ).config( ip=ip )
        intf = self.defaultIntf()
        self.cmd( 'ifconfig %s inet 0' % intf )
        newName = '%s.%d' % ( intf, vlan_id )
        # Crea la VLAN y mapea las prioridades (importante para TSN)
        self.cmd( 'ip link add link %s name %s type vlan id %d' % ( intf, newName, vlan_id ) )
        self.cmd( 'ifconfig %s.%d inet %s' % ( intf, vlan_id, ip ) )
        intf.name = newName
        self.nameToIntf[ newName ] = intf
        return r

class MyTopology(Topo):
    def build(self):
        # 1. Creamos el Bridge (que para Mininet es un Switch)
        s1 = self.addSwitch('s1', cls=LinuxBridge) 

        # 2. Creamos dos Hosts con VLAN 10
        h1 = self.addHost('h1', ip='10.0.0.1/24') # Sin cls=VLANHost
        h2 = self.addHost('h2', ip='10.0.0.2/24')

        # 3. Los conectamos al Bridge
        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    topo = MyTopology()
    net = Mininet(topo, controller=None) # No queremos que aprenda MACs
    net.start()

    # Referencias a los nodos
    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')

    # Desactivar el aprendizaje y el forward del Kernel
    s1.cmd('sysctl net.ipv4.ip_forward=0')
    s1.cmd('ip link set s1 down') # Matamos el bridge de Linux para que no interfiera

    # MODO SEGURO: Desactivar TODAS las optimizaciones que rompen XDP
    # Se lo hacemos a los hosts Y a las interfaces del switch
    interfaces = ['h1-eth0', 'h2-eth0', 's1-eth1', 's1-eth2']
    print("*** Blindando interfaces contra Kernel Panics...")
    for intf in interfaces:
        # Buscamos en qué nodo está la interfaz para mandarle el comando
        node = h1 if 'h1' in intf else (h2 if 'h2' in intf else s1)
        node.cmd('ethtool -K %s tx off rx off gso off gro off lro off' % intf)
        node.cmd('ip link set %s promisc on' % intf)
    
    CLI(net) # Esto te deja una consola para que tú pruebes cosas
    net.stop()
