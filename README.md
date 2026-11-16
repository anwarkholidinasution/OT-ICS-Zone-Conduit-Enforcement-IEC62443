# OT-ICS-Zone-Conduit-Enforcement-IEC62443
ISA/IEC 62443 Zone &amp; Conduit enforcement lab using MikroTik RouterOS (hAP lite) and a pure-Python native Modbus TCP PLC simulator.

Purdue Model Conduit Enforcement on MikroTik RB941-2nD (hAP lite)ISA/IEC 62443 Zone & Conduit Enforcement Implementation Using a MikroTik Router and a Native Modbus TCP Simulator

1. IntroductionThe convergence of Information Technology (IT) and Operational Technology (OT) unlocks real-time data exchange, yet simultaneously exposes Industrial Control Systems (ICS) to a broader cyber threat landscape. Relying solely on conventional isolation methods such as pure air-gapping is no longer sufficient for modern industrial architectures.The ISA/IEC 62443 standard (specifically parts 3-2 and 3-3) establishes a cybersecurity methodology built on logical and physical segmentation through the concept of Zones and Conduits. This standalone Hardware-in-the-Loop (HIL) mini-lab project is designed to empirically demonstrate perimeter cybersecurity enforcement at the Industrial Ethernet level, validate conduit controls for the Modbus TCP industrial protocol, and test perimeter resilience against traffic anomalies and IP spoofing techniques.

2. Project ObjectivesBuild Purdue Model Segmentation: Segregate network roles into an Out-of-Band (OOB) Management zone, an Enterprise/IT Zone, and an OT Control Zone (SCADA & Level 1 PLC) using a single physical appliance.Develop a Native Modbus TCP PLC Simulator: Build a standalone field process controller emulation server using pure Python (low-level socket and struct modules) without relying on third-party libraries.Enforce IEC 62443 Conduit Rules: Configure a stateful inspection firewall to ensure Modbus TCP traffic (TCP Port 502) can only be initiated by authorized workstations (EWS/SCADA).Validate Boundary Resilience & Anti-Spoofing: Test the effectiveness of physical interface binding (in-interface), Reverse Path Filtering (RPF), and TCP state tracking against unauthorized access attempts from untrusted zones (unauthorized IT hosts).Integrate Security Audit Logging: Verify the generation of security log signatures ([OT-ALERT]) whenever a conduit boundary violation occurs.

3. Hardware & Software RequirementsHardwareIndustrial Router Appliance: 1x MikroTik RouterBOARD RB941-2nD (hAP lite)Workstation 1 (EWS / SCADA Client): Engineering Workstation / Technician LaptopWorkstation 2 (PLC Simulator): PC / Mini PC running the controller emulationTransmission Media: 3x UTP/STP RJ45 Patch Cables (Cat5e / Cat6)Software & EnvironmentNetwork Operating System: MikroTik RouterOS v6 / v7Router Management Utility: MikroTik Winbox (Windows x64)Runtime Environment: Python 3.10+ (Standard Library: socket, struct, time, threading)Terminal Shell: Windows PowerShell / Command Prompt

4. Network Topology & Interface AllocationPhysical PortInterface NamePurdue Model ZoneIP Allocation / SubnetFunction / Connected DevicePort 1ether1-MGMTOut-of-Band (OOB)192.168.88.1/24Router Winbox management accessPort 2ether2-ITEnterprise / IT Zone192.168.10.1/24External network segment / Rogue test hostPort 3ether3-OT-SCADAOT Zone (Bridge)192.168.20.1/24 (Gateway)Engineering Workstation (192.168.20.100)Port 4ether4-OT-PLCOT Zone (Bridge)192.168.20.1/24 (Gateway)Target PLC Simulator (192.168.20.10)

5. Step-by-Step ImplementationPhase 1: MikroTik Network & Firewall ConfigurationOpen Winbox and connect the admin laptop to Port 1 (ether1-MGMT).Rename the physical interfaces to reflect their Purdue Model zones:Code snippet/interface set [find default-name=ether1] name=ether1-MGMT
/interface set [find default-name=ether2] name=ether2-IT
/interface set [find default-name=ether3] name=ether3-OT-SCADA
/interface set [find default-name=ether4] name=ether4-OT-PLC
Create a local bridge for the OT Zone and assign Port 3 and Port 4 to it:Code snippet/interface bridge add name=bridge-OT
/interface bridge port add bridge=bridge-OT interface=ether3-OT-SCADA
/interface bridge port add bridge=bridge-OT interface=ether4-OT-PLC
Assign IP addresses to each zone interface:Code snippet/ip address add address=192.168.88.1/24 interface=ether1-MGMT network=192.168.88.0
/ip address add address=192.168.10.1/24 interface=ether2-IT network=192.168.10.0
/ip address add address=192.168.20.1/24 interface=bridge-OT network=192.168.20.0
Configure the conduit rules and security filters in the firewall:Code snippet# 1. Allow established & related connections
/ip firewall filter add chain=forward connection-state=established,related action=accept comment="ALLOW: Established and Related"

# 2. Authorized Conduit: EWS (192.168.20.100) to PLC (192.168.20.10) on Port 502
/ip firewall filter add chain=forward in-interface=bridge-OT out-interface=bridge-OT src-address=192.168.20.100 dst-address=192.168.20.10 protocol=tcp dst-port=502 action=accept comment="CONDUIT: EWS to PLC Modbus TCP"

# 3. Log Perimeter Violations from the IT Zone
/ip firewall filter add chain=forward in-interface=ether2-IT out-interface=bridge-OT protocol=tcp dst-port=502 action=log log-prefix="[OT-ALERT]" comment="LOG: Unauthorized IT Access to PLC"

# 4. Drop All Direct Traffic from IT Zone to OT Zone
/ip firewall filter add chain=forward in-interface=ether2-IT out-interface=bridge-OT action=drop comment="BLOCK: Direct IT to OT Traffic"
Phase 2: Developing the PLC Simulator Script (plc_sim.py)On the PLC Simulator PC (connected to Port 4), create plc_sim.py using pure Python to serve Modbus TCP requests on Port 502:Pythonimport socket
import struct
import threading
import time
import random

# Initial Process Register Values (40001: Pressure, 40002: Temperature, 40003: Flow Rate)
holding_registers = [1500, 250, 50]

def update_process_variables():
    """Simulate dynamic industrial process variations"""
    global holding_registers
    while True:
        holding_registers[0] = 1500 + random.randint(-15, 15)  # Pressure: 1485 - 1515 psi
        holding_registers[1] = 250 + random.randint(-4, 4)     # Temperature: 246 - 254 C
        holding_registers[2] = 50 + random.randint(-2, 2)      # Flow Rate: 48 - 52 m3/h
        time.sleep(2)

def handle_client(conn, addr):
    print(f"[INFO] Active communication session from: {addr[0]}:{addr[1]}")
    while True:
        try:
            header = conn.recv(7)
            if not header or len(header) < 7:
                break

            # Unpack MBAP Header: Transaction ID, Protocol ID, Length, Unit ID
            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
            pdu = conn.recv(length - 1)
            fc = pdu[0]

            # Function Code 03: Read Holding Registers
            if fc == 3:
                start_addr, reg_count = struct.unpack(">HH", pdu[1:5])
                byte_count = reg_count * 2

                # Construct Response PDU
                response_pdu = struct.pack(">BB", fc, byte_count)
                for i in range(start_addr, start_addr + reg_count):
                    val = holding_registers[i] if i < len(holding_registers) else 0
                    response_pdu += struct.pack(">H", val)

                # Construct Response MBAP Header
                response_length = len(response_pdu) + 1
                response_header = struct.pack(">HHHB", trans_id, proto_id, response_length, unit_id)

                conn.sendall(response_header + response_pdu)
        except Exception:
            break
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 502))
    server.listen(5)
    print("[*] PLC Simulator active. Listening on TCP Port 502...")

    # Start background thread for process variable updates
    t_process = threading.Thread(target=update_process_variables, daemon=True)
    t_process.start()

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    start_server()
Run the script in PowerShell with Administrator privileges (required to bind to privileged Port 502):PowerShellpython plc_sim.py
Phase 3: PLC PC Endpoint ConfigurationAssign a static IP address to the physical network adapter on the PLC PC via an Administrator PowerShell prompt:PowerShellnetsh interface ipv4 set address name="Ethernet" static 192.168.20.10 255.255.255.0 192.168.20.1
Phase 4: Developing the EWS Client Script (test_modbus.py)On the EWS PC (connected to Port 3), configure its static IP address:PowerShellnetsh interface ipv4 set address name="Ethernet" static 192.168.20.100 255.255.255.0 192.168.20.1
Create test_modbus.py to test reading registers across the conduit:Pythonimport socket
import struct

target_ip = "192.168.20.10"
port = 502

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect((target_ip, port))

# Modbus TCP Request: FC 03 (Read 3 Holding Registers: Pressure, Temperature, Flow)
# TransID=1, ProtoID=0, Len=6, UnitID=1, FC=3, Start=0, Count=3
request = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 3)
s.sendall(request)

response = s.recv(1024)
s.close()

# Extract MBAP and PDU
trans_id, proto_id, length, unit_id, fc, byte_count = struct.unpack(">HHHBBB", response[:9])
registers = struct.unpack(f">{byte_count//2}H", response[9:9+byte_count])

print(f"[*] PLC Response from {target_ip}:")
print(f"    - Pressure    (40001): {registers[0]} psi")
print(f"    - Temperature (40002): {registers[1]} deg C")
print(f"    - Flow Rate   (40003): {registers[2]} m3/h")

6. Testing, Results & Empirical ValidationScenario 1: Authorized Conduit VerificationCondition: EWS PC connected to ether3-OT-SCADA with IP 192.168.20.100.Execution: python test_modbus.pyOutput:Plaintext[*] PLC Response from 192.168.20.10:
    - Pressure    (40001): 1487 psi
    - Temperature (40002): 246 deg C
    - Flow Rate   (40003): 51 m3/h
Status: PASSED. Process telemetry data is accurately read through the authorized conduit path.Scenario 2: Penetration Test from Enterprise/IT Zone (Unauthorized Ingress)Condition: Ethernet cable moved to ether2-IT with an IT segment IP configuration (192.168.10.50/24, Gateway 192.168.10.1).Execution: python test_modbus.pyOutput:PlaintextTimeoutError: timed out
RouterOS Log Evidence: Recorded in Winbox under Log:Plaintext[OT-ALERT] forward: in:ether2-IT out:bridge-OT, proto TCP (SYN), 192.168.10.50:xxxxx->192.168.20.10:502
Status: PASSED. The TCP SYN packet is immediately dropped at the router perimeter and triggers the security alert log signature.Scenario 3: IP Spoofing Attack AnalysisThreat Scenario: What if an attacker in the IT Zone (ether2-IT) manually configures the static IP 192.168.20.100 to impersonate the authorized Engineering Workstation?Defense Mechanisms:In-Interface Enforcement: The conduit permit rule explicitly binds traffic to in-interface=bridge-OT. Because the spoofed packet enters via ether2-IT, the permit rule is bypassed and the packet falls through to the drop rule.Reverse Path Filtering (RPF): When enabled (rp-filter=strict), the router detects an asymmetric route (subnet 192.168.20.0/24 belongs to bridge-OT, not ether2-IT) and discards the packet at the kernel level before firewall evaluation.TCP Three-Way Handshake Breakdown: Even if a forged SYN packet were to reach the PLC, the PLC's SYN-ACK reply would be routed to the legitimate IP owner on bridge-OT. The attacker in the IT Zone never receives the SYN-ACK, preventing a TCP session from ever completing.

7. Lessons Learned & Advanced Hardening RecommendationsImportance of Physical Interface Validation: Industrial network security cannot rely solely on Layer 3 header inspection (Source/Destination IP). Binding rules to physical ingress interfaces (in-interface) is a foundational defense against IP spoofing.Deep Packet Inspection (DPI) Gap: Layer 3/4 firewall filters operate in a binary manner—allowing or blocking all traffic on TCP Port 502. To achieve higher ISA/IEC 62443 Security Levels (SL-2 / SL-3), deploy an industrial firewall capable of DPI to granularly inspect and filter Modbus Function Codes (e.g., permitting FC 03 Read Holding Registers while blocking FC 05/06/16 Write commands).Layer 2 Local Port Hardening: To mitigate insider threats or attackers with physical access to local OT switch ports, enable Static ARP (arp=reply-only) on bridge-OT alongside Bridge Port Isolation / Horizon to restrict unauthorized lateral movement at Layer 2.
