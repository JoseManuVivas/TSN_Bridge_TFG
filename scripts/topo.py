from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.nodelib import LinuxBridge

class DualVLANHost(Host):
    """Host con dos interfaces VLAN: una en VLAN 1 y otra en VLAN 2."""
    def config(self, ip1='', ip2='', **params):
        super(DualVLANHost, self).config(**params)
        intf = self.defaultIntf()

        # Quitamos la IP de la interfaz física base
        self.cmd('ifconfig %s inet 0' % intf)

        # Creamos la interfaz VLAN 1
        self.cmd('ip link add link %s name %s.1 type vlan id 1' % (intf, intf))
        self.cmd('ip link set %s.1 up' % intf)
        self.cmd('ip addr add %s dev %s.1' % (ip1, intf))

        # Creamos la interfaz VLAN 2
        self.cmd('ip link add link %s name %s.2 type vlan id 2' % (intf, intf))
        self.cmd('ip link set %s.2 up' % intf)
        self.cmd('ip addr add %s dev %s.2' % (ip2, intf))

class MyTopology(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=LinuxBridge)

        # h1: VLAN 1 → 10.0.0.1, VLAN 2 → 10.0.1.1
        h1 = self.addHost('h1', cls=DualVLANHost,
                          ip1='10.0.0.1/24', ip2='10.0.1.1/24')
        # h2: VLAN 1 → 10.0.0.2, VLAN 2 → 10.0.1.2
        h2 = self.addHost('h2', cls=DualVLANHost,
                          ip1='10.0.0.2/24', ip2='10.0.1.2/24')

        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    topo = MyTopology()
    net = Mininet(topo, controller=None)
    net.start()

    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')

    # Desactivar el aprendizaje y el forward del Kernel
    s1.cmd('sysctl net.ipv4.ip_forward=0')

    # Desactivar todas las optimizaciones que rompen XDP
    interfaces = ['h1-eth0', 'h1-eth0.1', 'h1-eth0.2',
                  'h2-eth0', 'h2-eth0.1', 'h2-eth0.2',
                  's1-eth1', 's1-eth2']
    print("*** Blindando interfaces contra Kernel Panics...")
    for intf in interfaces:
        node = h1 if 'h1' in intf else (h2 if 'h2' in intf else s1)
        node.cmd('ethtool -K %s tx off rx off gso off gro off lro off txvlan off rxvlan off' % intf)
        node.cmd('ip link set %s promisc on' % intf)

    print("*** Topologia lista:")
    print("    h1-eth0.1 → 10.0.0.1/24  (VLAN 1, cola 0)")
    print("    h1-eth0.2 → 10.0.1.1/24  (VLAN 2, cola 1)")
    print("    h2-eth0.1 → 10.0.0.2/24  (VLAN 1, cola 0)")
    print("    h2-eth0.2 → 10.0.1.2/24  (VLAN 2, cola 1)")
    print("")
    print("    Para probar TAS:")
    print("    h1 ping 10.0.0.2   <- VLAN 1, cola 0")
    print("    h1 ping 10.0.1.2   <- VLAN 2, cola 1")

    CLI(net)
    net.stop()
