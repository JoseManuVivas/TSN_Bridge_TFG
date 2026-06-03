from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.nodelib import LinuxBridge

class PCPHost(Host):
    """Host con dos interfaces VLAN; egress-qos-map fuerza PCP=0 y PCP=1."""
    def config(self, ip0='', ip1='', **params):
        super().config(**params)
        intf = self.defaultIntf()

        self.cmd('ifconfig %s inet 0' % intf)

        # Interfaz VLAN 100 → PCP=0 forzado via egress-qos-map
        self.cmd('ip link add link %s name %s.100 type vlan id 100' % (intf, intf))
        self.cmd('ip link set %s.100 type vlan egress-qos-map 0:0' % intf)
        self.cmd('ip link set %s.100 up' % intf)
        self.cmd('ip addr add %s dev %s.100' % (ip0, intf))

        # Interfaz VLAN 101 → PCP=1 forzado via egress-qos-map
        self.cmd('ip link add link %s name %s.101 type vlan id 101' % (intf, intf))
        self.cmd('ip link set %s.101 type vlan egress-qos-map 0:1' % intf)
        self.cmd('ip link set %s.101 up' % intf)
        self.cmd('ip addr add %s dev %s.101' % (ip1, intf))

class MyTopology(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=LinuxBridge)

        h1 = self.addHost('h1', cls=PCPHost,
                          ip0='10.0.0.1/24', ip1='10.0.1.1/24')
        h2 = self.addHost('h2', cls=PCPHost,
                          ip0='10.0.0.2/24', ip1='10.0.1.2/24')

        self.addLink(h1, s1)
        self.addLink(h2, s1)

if __name__ == '__main__':
    topo = MyTopology()
    net = Mininet(topo, controller=None)
    net.start()

    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')

    s1.cmd('sysctl net.ipv4.ip_forward=0')

    interfaces = [
        'h1-eth0', 'h1-eth0.100', 'h1-eth0.101',
        'h2-eth0', 'h2-eth0.100', 'h2-eth0.101',
        's1-eth1', 's1-eth2',
    ]
    print("*** Blindando interfaces contra Kernel Panics...")
    for intf in interfaces:
        node = h1 if 'h1' in intf else (h2 if 'h2' in intf else s1)
        node.cmd('ethtool -K %s tx off rx off gso off gro off lro off txvlan off rxvlan off' % intf)
        node.cmd('ip link set %s promisc on' % intf)

    print("*** Topologia lista:")
    print("    h1-eth0.100 → 10.0.0.1/24  (PCP=0, cola 0, slot 9ms)")
    print("    h1-eth0.101 → 10.0.1.1/24  (PCP=1, cola 1, slot 1ms)")
    print("    h2-eth0.100 → 10.0.0.2/24  (PCP=0, cola 0)")
    print("    h2-eth0.101 → 10.0.1.2/24  (PCP=1, cola 1)")
    print("")
    print("    Para probar TAS (desde xterm h1):")
    print("      hping3 -1 -I h1-eth0.100 10.0.0.2 -i u700 -c 1000 > /tmp/pcp0.txt 2>&1 &")
    print("      hping3 -1 -I h1-eth0.101 10.0.1.2 -i u700 -c 1000 > /tmp/pcp1.txt 2>&1 &")
    print("      wait")
    print("    Luego: python3 scripts/analyze_latency.py")

    CLI(net)
    net.stop()
