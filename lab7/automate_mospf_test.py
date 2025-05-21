#!/usr/bin/env python3

"""
Mininet script to automate Mospf testing including link failure simulation.
Uses the exact same IP configuration and topology links as the provided topo.py.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info, error
import time
import sys
import os # Needed for os.geteuid()
import glob # Needed for check_scripts if you include it

# Assuming check_scripts and script_deps are defined elsewhere or removed if not needed
# For completeness, I'll include a simplified check_scripts or assume the user handles it.
# If you have the 'scripts/' directory and these dependencies are truly needed,
# you might want to copy the check_scripts function from your topo.py.
# For this automated script, I'll remove the check_scripts call for simplicity
# and focus on the topology and automation logic.

class MOSPFTopoExact(Topo):
    """
    Exact topology and link connections as the provided topo.py,
    but without IP configuration in build(). IPs are set later via cmd().
    """
    def build(self):
        # Add hosts and routers (using addHost as in the original topo.py)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        r1 = self.addHost('r1')
        r2 = self.addHost('r2')
        r3 = self.addHost('r3')
        r4 = self.addHost('r4')

        # Add links exactly as in the original topo.py
        # Interface names are assigned sequentially: eth0, eth1, eth2...
        self.addLink(h1, r1) # h1-eth0, r1-eth0
        self.addLink(r1, r2) # r1-eth1, r2-eth0
        self.addLink(r1, r3) # r1-eth2, r3-eth0
        self.addLink(r2, r4) # r2-eth1, r4-eth0 <--- This is the link we'll break
        self.addLink(r3, r4) # r3-eth1, r4-eth1
        self.addLink(r4, h2) # r4-eth2, h2-eth0


def run_mospf_test():
    "Create and run the Mospf network test script with exact topo.py config"
    setLogLevel('info') # Set Mininet logging level

    info('*** Creating topology (matching topo.py)\n')
    topo = MOSPFTopoExact() # Use the exact topology definition
    # controller=None is important as mospfd handles routing
    net = Mininet(topo=topo, controller=None)

    info('*** Starting network\n')
    net.start()

    # Get node references
    h1, h2, r1, r2, r3, r4 = net.get('h1', 'h2', 'r1', 'r2', 'r3', 'r4')

    # --- EXACT IP Configuration as in topo.py ---
    info('*** Configuring IPs exactly as in topo.py\n')
    h1.cmd('ifconfig h1-eth0 10.0.1.11/24')

    r1.cmd('ifconfig r1-eth0 10.0.1.1/24')
    r1.cmd('ifconfig r1-eth1 10.0.2.1/24')
    r1.cmd('ifconfig r1-eth2 10.0.3.1/24')

    r2.cmd('ifconfig r2-eth0 10.0.2.2/24')
    r2.cmd('ifconfig r2-eth1 10.0.4.2/24') # Link r2-r4 uses r2-eth1 and r4-eth0

    r3.cmd('ifconfig r3-eth0 10.0.3.3/24')
    r3.cmd('ifconfig r3-eth1 10.0.5.3/24')

    r4.cmd('ifconfig r4-eth0 10.0.4.4/24') # Link r2-r4 uses r2-eth1 and r4-eth0
    r4.cmd('ifconfig r4-eth1 10.0.5.4/24') # Link r3-r4 uses r3-eth1 and r4-eth1
    r4.cmd('ifconfig r4-eth2 10.0.6.4/24') # Link r4-h2 uses r4-eth2 and h2-eth0

    h2.cmd('ifconfig h2-eth0 10.0.6.22/24')

    # --- EXACT Default Routes as in topo.py ---
    info('*** Configuring default routes on hosts as in topo.py\n')
    h1.cmd('route add default gw 10.0.1.1')
    h2.cmd('route add default gw 10.0.6.4')

    # --- EXACT Disable Scripts as in topo.py ---
    # Make sure './scripts/' directory and the .sh files exist and are executable
    info('*** Disabling kernel features as in topo.py\n')
    for h in (h1, h2):
        h.cmd('./scripts/disable_offloading.sh')
        h.cmd('./scripts/disable_ipv6.sh')

    for r in (r1, r2, r3, r4):
        r.cmd('./scripts/disable_arp.sh')
        r.cmd('./scripts/disable_icmp.sh')
        r.cmd('./scripts/disable_ip_forward.sh')
        r.cmd('./scripts/disable_ipv6.sh')
    info('    Kernel features disabled on nodes.\n')


    info('*** Starting Mospfd processes on routers\n')
    # Start the Mospfd application on each router in the background
    # Make sure the 'mospfd' executable is in the directory where you run this script
    # You might need to add arguments here depending on how your mospfd needs them
    r1.cmd('./mospfd &')
    r2.cmd('./mospfd &')
    r3.cmd('./mospfd &')
    r4.cmd('./mospfd &')
    info('    Mospfd started on r1, r2, r3, r4 in the background.\n')


    # --- First Phase: Initial State ---
    # Increased sleep time as per your modified script
    info('*** Waiting 40 seconds for Mospfd convergence...\n')
    time.sleep(40) # Wait for OSPF Hellos, LSP exchange, SPF calculation

    info('*** Phase 1: Initial State Routing Tables:\n')
    # Uncomment these prints to see the routing tables
    # print("--- r1 route ---")
    # print(r1.cmd('route'))
    # print("--- r2 route ---")
    # print(r2.cmd('route'))
    # print("--- r3 route ---")
    # print(r3.cmd('route'))
    # print("--- r4 route ---")
    # print(r4.cmd('route'))

    info('*** Phase 1: Running h1 ping -c 4 h2 (via IP 10.0.6.22):\n')
    # Use h2's IP for ping (matching topo.py)
    print(h1.cmd('ping -c 4 10.0.6.22'))

    info('*** Phase 1: Running h1 traceroute h2 (via IP 10.0.6.22):\n')
    # Use h2's IP for traceroute (matching topo.py)
    # NOTE: traceroute might need to be installed on the Mininet VM image!
    # You might need to run `sudo apt-get update && sudo apt-get install -y traceroute` outside this script
    print(h1.cmd('traceroute 10.0.6.22'))


    # --- Second Phase: Link Failure ---
    info('*** Phase 2: Bringing link between r2 and r4 down...\n')
    # Use net.configLinkStatus(node1_name, node2_name, 'down')
    # This command works based on node names regardless of specific interface names
    net.configLinkStatus('r2', 'r4', 'down')
    info('    Link r2-r4 is down.\n')

    # Increased sleep time as per your modified script
    info('*** Waiting 40 seconds for Mospfd reconvergence after link failure...\n')
    time.sleep(40) # Wait for OSPF to detect failure, flood LSA, recalculate

    info('*** Phase 2: Routing Tables After Link Failure:\n')
    # Uncomment these prints to see the routing tables
    # print("--- r1 route (after r2-r4 down) ---")
    # print(r1.cmd('route'))
    # print("--- r2 route (after r2-r4 down) ---")
    # print(r2.cmd('route'))
    # print("--- r3 route (after r2-r4 down) ---")
    # print(r3.cmd('route'))
    # print("--- r4 route (after r2-r4 down) ---")
    # print(r4.cmd('route'))

    info('*** Phase 2: Running h1 ping -c 4 h2 (after r2-r4 down):\n')
    # Ping again - should use the alternate path (via r3)
    print(h1.cmd('ping -c 4 10.0.6.22'))

    info('*** Phase 2: Running h1 traceroute h2 (after r2-r4 down):\n')
    # Traceroute again - should show the path via r3
    print(h1.cmd('traceroute 10.0.6.22'))

    # --- Clean Up ---
    info('*** Test complete. Stopping network.\n')
    net.stop()

# --- Root Privilege Check ---
# Using the corrected check from our previous discussion
if __name__ == '__main__':
    if os.geteuid() != 0:
        error('This script requires root privileges. Run with sudo.\n')
        sys.exit(1)

    # Set logging level (info, debug, output)
    setLogLevel('info') # Or 'debug' for more detailed Mininet output

    # Note: If you uncomment the check_scripts() call, you'll need the function definition
    # from your topo.py and the 'scripts/' directory with executable files.
    # check_scripts() # Uncomment if you want the dependency checks

    run_mospf_test()