#!/usr/bin/env python3
"""
Caso de uso: cadena de 3 bridges AF_XDP con TAS (IEEE 802.1Qbv)
Topologia: H1 - BR1(s1) - BR2(s2) - BR3(s3) - H2
Lee parametros desde usecase.xml
"""

import xml.etree.ElementTree as ET
import os
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.nodelib import LinuxBridge

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'usecase.xml')
BRIDGE_BIN  = os.path.join(os.path.dirname(__file__), '..', 'build', 'af_xdp_user')


def load_config(path):
    tree = ET.parse(path)
    root = tree.getroot()

    bridges = []
    for b in root.find('bridges').findall('bridge'):
        bridges.append({
            'id':        int(b.get('id')),
            'iface1':    b.get('iface1'),
            'iface2':    b.get('iface2'),
            'offset_ns': int(b.get('offset_ns')),
        })

    hosts = []
    for h in root.find('hosts').findall('host'):
        hosts.append({
            'name':      h.get('name'),
            'ip_vlan100': h.get('ip_vlan100'),
            'ip_vlan101': h.get('ip_vlan101'),
        })

    return bridges, hosts


class PCPHost(Host):
    """Host con dos interfaces VLAN; egress-qos-map fuerza PCP=0 y PCP=1."""
    def config(self, ip0='', ip1='', **params):
        super().config(**params)
        intf = self.defaultIntf()
        self.cmd('ifconfig %s inet 0' % intf)

        self.cmd('ip link add link %s name %s.100 type vlan id 100' % (intf, intf))
        self.cmd('ip link set %s.100 type vlan egress-qos-map 0:0' % intf)
        self.cmd('ip link set %s.100 up' % intf)
        self.cmd('ip addr add %s dev %s.100' % (ip0, intf))

        self.cmd('ip link add link %s name %s.101 type vlan id 101' % (intf, intf))
        self.cmd('ip link set %s.101 type vlan egress-qos-map 0:1' % intf)
        self.cmd('ip link set %s.101 up' % intf)
        self.cmd('ip addr add %s dev %s.101' % (ip1, intf))


class UsecaseTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', cls=PCPHost, ip0='10.0.0.1/24', ip1='10.0.1.1/24')
        h2 = self.addHost('h2', cls=PCPHost, ip0='10.0.0.2/24', ip1='10.0.1.2/24')

        s1 = self.addSwitch('s1', cls=LinuxBridge)
        s2 = self.addSwitch('s2', cls=LinuxBridge)
        s3 = self.addSwitch('s3', cls=LinuxBridge)

        # Cadena lineal: h1 - s1 - s2 - s3 - h2
        self.addLink(h1, s1)   # h1-eth0  <->  s1-eth1
        self.addLink(s1, s2)   # s1-eth2  <->  s2-eth1
        self.addLink(s2, s3)   # s2-eth2  <->  s3-eth1
        self.addLink(s3, h2)   # s3-eth2  <->  h2-eth0


def disable_offloads(net, nodes_intfs):
    print("*** Blindando interfaces contra Kernel Panics...")
    for node_name, intfs in nodes_intfs:
        node = net.get(node_name)
        for intf in intfs:
            node.cmd('ethtool -K %s tx off rx off gso off gro off lro off txvlan off rxvlan off' % intf)
            node.cmd('ip link set %s promisc on' % intf)


if __name__ == '__main__':
    bridges_cfg, hosts_cfg = load_config(CONFIG_FILE)

    topo = UsecaseTopo()
    net  = Mininet(topo, controller=None)
    net.start()

    for sw in ['s1', 's2', 's3']:
        net.get(sw).cmd('sysctl net.ipv4.ip_forward=0')

    disable_offloads(net, [
        ('h1', ['h1-eth0', 'h1-eth0.100', 'h1-eth0.101']),
        ('s1', ['s1-eth1', 's1-eth2']),
        ('s2', ['s2-eth1', 's2-eth2']),
        ('s3', ['s3-eth1', 's3-eth2']),
        ('h2', ['h2-eth0', 'h2-eth0.100', 'h2-eth0.101']),
    ])

    print("*** Topologia lista: H1 - BR1(s1) - BR2(s2) - BR3(s3) - H2")
    print("")
    print("*** Lanzar los bridges (uno por terminal, dentro de Mininet):")
    for b in bridges_cfg:
        print("    s%d: %s %s %s" % (
            b['id'],
            os.path.abspath(BRIDGE_BIN),
            b['iface1'],
            b['iface2'],
        ))
    print("")
    print("*** Trafico de prueba (desde xterm h1):")
    h1_ip100 = hosts_cfg[0]['ip_vlan100'].split('/')[0]  # sin mascara, destino = h2
    h2_ip100 = hosts_cfg[1]['ip_vlan100'].split('/')[0]
    h2_ip101 = hosts_cfg[1]['ip_vlan101'].split('/')[0]
    print("    hping3 -1 -I h1-eth0.100 %s -i u700 -c 1000 > /tmp/vlan100.txt 2>&1 &" % h2_ip100)
    print("    hping3 -1 -I h1-eth0.101 %s -i u700 -c 1000 > /tmp/vlan101.txt 2>&1 &" % h2_ip101)
    print("")
    print("*** Analisis de latencias:")
    print("    python3 scripts/analyze_latency.py")

    CLI(net)
    net.stop()
