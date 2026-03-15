from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host

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
        s1 = self.addSwitch('s1')

        # 2. Creamos dos Hosts con VLAN 10
        h1 = self.addHost('h1', cls=VLANHost, vlan_id=10, ip='10.0.0.1/24')
        h2 = self.addHost('h2', cls=VLANHost, vlan_id=10, ip='10.0.0.2/24')

        # 3. Los conectamos al Bridge
        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    topo = MyTopology()
    net = Mininet(topo)
    net.start()
    
    # Aquí es donde el Bridge de Linux está funcionando por defecto.
    # El objetivo de tu TFG es "matar" el bridge de Linux y meter tu código.
    print("*** Red lista. Escribe 'pingall' para probar.")
    
    CLI(net) # Esto te deja una consola para que tú pruebes cosas
    net.stop()