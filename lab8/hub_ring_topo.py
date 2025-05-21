#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class MyTopo(Topo):
    def build(self):
        # 添加 3 个 Hub 节点（使用 Host 类）和 2 个普通主机
        b1 = self.addHost('b1', cls=Host, ip='0.0.0.0')
        b2 = self.addHost('b2', cls=Host, ip='0.0.0.0')
        b3 = self.addHost('b3', cls=Host, ip='0.0.0.0')
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        # 添加链路：h1-b1, h2-b2, b1-b2, b2-b3, b3-b1
        self.addLink(h1, b1)
        self.addLink(h2, b2)
        self.addLink(b1, b2)
        self.addLink(b2, b3)
        self.addLink(b3, b1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = MyTopo()
    net = Mininet(topo=topo, controller=None)
    net.start()

    # 关闭 TCP 卸载和 IPv6
    info('*** 关闭 TCP offloading 和 IPv6\\n')
    for node in net.hosts:
        node.cmd('./scripts/disable_offloading.sh')
        node.cmd('./scripts/disable_ipv6.sh')

    # 在 b1, b2, b3 上启动 hub 程序（假设可执行文件 hub 在当前目录）
    info('*** 在 b1, b2, b3 上运行 hub 程序\\n')
    net.get('b1').cmd('./hub &')
    net.get('b2').cmd('./hub &')
    net.get('b3').cmd('./hub &')

    CLI(net)
    net.stop()
