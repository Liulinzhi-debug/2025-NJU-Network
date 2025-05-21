import os
import sys
import glob
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

script_deps = [ 'ethtool', 'arptables', 'iptables', 'traceroute' ]

def check_scripts():
    dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    
    for fname in glob.glob(os.path.join(dir, 'scripts/*.sh')):
        if not os.access(fname, os.X_OK):
            print(f'{fname} should be set executable by using `chmod +x $script_name`')
            sys.exit(1)

    for program in script_deps:
        found = False
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
                found = True
                break
        if not found:
            print(f'`{program}` is required but missing, install via `apt`')
            sys.exit(2)

class RouterTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        r1 = self.addHost('r1')
        r2 = self.addHost('r2')

        self.addLink(h1, r1)
        self.addLink(r1, r2)
        self.addLink(r2, h2)

if __name__ == '__main__':
    check_scripts()
    
    topo = RouterTopo()
    net = Mininet(topo=topo, controller=None)

    net.start()
    h1, h2, r1, r2 = net.get('h1', 'h2', 'r1', 'r2')

    h1.setIP('10.0.1.11/24', intf='h1-eth0')
    h2.setIP('10.0.3.33/24', intf='h2-eth0')

    r1.setIP('10.0.1.1/24', intf='r1-eth0')
    r1.setIP('10.0.2.1/24', intf='r1-eth1')

    r2.setIP('10.0.2.2/24', intf='r2-eth0')
    r2.setIP('10.0.3.1/24', intf='r2-eth1')

    h1.cmd('route add default gw 10.0.1.1')
    h2.cmd('route add default gw 10.0.3.1')
    r1.cmd('route add -net 10.0.3.0/24 gw 10.0.2.2 dev r1-eth1')
    r2.cmd('route add -net 10.0.1.0/24 gw 10.0.2.1 dev r2-eth0')

    for h in (h1, h2):
        h.cmd('./scripts/disable_offloading.sh')
        h.cmd('./scripts/disable_ipv6.sh')

    for r in (r1, r2):
        r.cmd('./scripts/disable_arp.sh')
        r.cmd('./scripts/disable_icmp.sh')
        r.cmd('./scripts/disable_ip_forward.sh')
        r.cmd('./scripts/disable_ipv6.sh')
        r.cmd('./router &')

    CLI(net)
    net.stop()