# OT/ICS Zone & Conduit Enforcement (ISA/IEC 62443)

![Standard](https://img.shields.io/badge/Standard-ISA%2FIEC%2062443-blue)
![Hardware](https://img.shields.io/badge/Router-MikroTik%20RB941--2nD-orange)
![Protocol](https://img.shields.io/badge/Protocol-Modbus%20TCP%20(Port%20502)-green)
![Python](https://img.shields.io/badge/Python-3.10%2B%20(Stdlib%20Only)-yellow)

**Purdue Model Zone & Conduit Enforcement Lab using MikroTik RouterOS (hAP lite) and a Pure-Python Native Modbus TCP PLC Simulator.**

---

## 1. Introduction

The convergence of Information Technology (IT) and Operational Technology (OT) unlocks real-time data exchange, yet simultaneously exposes Industrial Control Systems (ICS) to a broader cyber threat landscape. Relying solely on conventional isolation methods such as pure air-gapping is no longer sufficient for modern industrial architectures.

The **ISA/IEC 62443** standard (specifically Parts 3-2 and 3-3) establishes a cybersecurity methodology built on logical and physical segmentation through the concept of **Zones** and **Conduits**. This standalone Hardware-in-the-Loop (HIL) mini-lab project is designed to empirically:
* Demonstrate perimeter cybersecurity enforcement at the Industrial Ethernet level.
* Validate stateful conduit controls for the **Modbus TCP** industrial protocol (`TCP/502`).
* Test perimeter resilience against traffic anomalies and **IP spoofing** techniques.

---

## 2. Project Objectives

1. **Build Purdue Model Segmentation:** Segregate network roles into an Out-of-Band (OOB) Management zone, an Enterprise/IT Zone, and an OT Control Zone (SCADA & Level 1 PLC) using a single physical appliance.
2. **Develop a Native Modbus TCP PLC Simulator:** Build a standalone field process controller emulation server using pure Python (low-level `socket` and `struct` modules) without relying on third-party libraries.
3. **Enforce IEC 62443 Conduit Rules:** Configure a stateful inspection firewall to ensure Modbus TCP traffic (`TCP/502`) can only be initiated by authorized workstations (`EWS/SCADA`).
4. **Validate Boundary Resilience & Anti-Spoofing:** Test the effectiveness of physical interface binding (`in-interface`), Reverse Path Filtering (`rp-filter`), and TCP state tracking against unauthorized access attempts from untrusted zones (unauthorized IT hosts).
5. **Integrate Security Audit Logging:** Verify the generation of security log signatures (`[OT-ALERT]`) whenever a conduit boundary violation occurs.

---

## 3. Architecture & Network Topology

```text
+-----------------------------------------------------------------------+
|                   MikroTik RB941-2nD (RouterOS)                       |
|                                                                       |
|  [ether1-MGMT]        [ether2-IT]               [bridge-OT]           |
|  192.168.88.1/24      192.168.10.1/24         192.168.20.1/24         |
|  (OOB Admin)          (Enterprise Zone)      /               \        |
+-------|--------------------|----------------/-----------------\-------+
        |                    |               /                   \
        v                    v              v                     v
  +-----------+       +-------------+   [ether3-OT-SCADA]   [ether4-OT-PLC]
  | Admin PC  |       | Rogue Host  |         |                   |
  | (Winbox)  |       | 192.168.10.x|         v                   v
  +-----------+       +-------------+   +-----------+       +-----------+
                                        | EWS/SCADA | ====> | PLC Sim   |
                                        | .20.100   |  502  | .20.10    |
                                        +-----------+       +-----------+
                                          (Level 2)           (Level 1)
                                          [==== Authorized Conduit ====]
```

### Interface & Subnet Allocation

| Physical Port | Interface Name | Purdue Model Zone | IP Allocation / Subnet | Function / Connected Device |
| :--- | :--- | :--- | :--- | :--- |
| **Port 1** | `ether1-MGMT` | Out-of-Band (OOB) | `192.168.88.1/24` | Router Winbox management access |
| **Port 2** | `ether2-IT` | Enterprise / IT Zone | `192.168.10.1/24` | External network segment / Rogue test host |
| **Port 3** | `ether3-OT-SCADA` | OT Zone (`bridge-OT`) | `192.168.20.1/24` (Gateway) | Engineering Workstation (`192.168.20.100`) |
| **Port 4** | `ether4-OT-PLC` | OT Zone (`bridge-OT`) | `192.168.20.1/24` (Gateway) | Target PLC Simulator (`192.168.20.10`) |

---

## 4. Hardware & Software Requirements

### Hardware
* **Industrial Router Appliance:** 1x MikroTik RouterBOARD RB941-2nD (hAP lite)
* **Workstation 1 (EWS / SCADA Client):** Engineering Workstation / Technician Laptop
* **Workstation 2 (PLC Simulator):** PC / Mini PC running the controller emulation
* **Transmission Media:** 3x UTP/STP RJ45 Patch Cables (Cat5e / Cat6)

### Software & Environment
* **Network Operating System:** MikroTik RouterOS v6 / v7
* **Router Management Utility:** MikroTik Winbox (Windows x64)
* **Runtime Environment:** Python 3.10+ (Standard Library: `socket`, `struct`, `time`, `threading`, `random`)
* **Terminal Shell:** Windows PowerShell / Command Prompt (Administrator privileges required to bind `TCP/502`)

---

## 5. Step-by-Step Implementation

### Phase 1: MikroTik Network & Firewall Configuration

Open Winbox and connect the admin laptop to **Port 1 (`ether1-MGMT`)**, then run the following commands in the RouterOS Terminal:

1. **Rename the physical interfaces to reflect their Purdue Model zones:**
   ```routeros
   /interface set [find default-name=ether1] name=ether1-MGMT
   /interface set [find default-name=ether2] name=ether2-IT
   /interface set [find default-name=ether3] name=ether3-OT-SCADA
   /interface set [find default-name=ether4] name=ether4-OT-PLC
   ```

2. **Create a local bridge for the OT Zone and enable bridge IP firewall inspection:**
   > **Note:** Enabling `use-ip-firewall=yes` allows Layer 3 firewall rules to inspect and enforce conduits on traffic traversing between bridged ports (`ether3-OT-SCADA` and `ether4-OT-PLC`).
   ```routeros
   /interface bridge add name=bridge-OT
   /interface bridge port add bridge=bridge-OT interface=ether3-OT-SCADA
   /interface bridge port add bridge=bridge-OT interface=ether4-OT-PLC
   /interface bridge settings set use-ip-firewall=yes
   ```

3. **Assign IP addresses to each zone interface:**
   ```routeros
   /ip address add address=192.168.88.1/24 interface=ether1-MGMT network=192.168.88.0
   /ip address add address=192.168.10.1/24 interface=ether2-IT network=192.168.10.0
   /ip address add address=192.168.20.1/24 interface=bridge-OT network=192.168.20.0
   ```

4. **Configure the conduit rules, security filters, and strict Reverse Path Filtering:**
   ```routeros
   # Enable strict Reverse Path Filtering (Anti-Spoofing)
   /ip settings set rp-filter=strict

   # 1. Allow established & related connections
   /ip firewall filter add chain=forward connection-state=established,related action=accept comment="ALLOW: Established and Related"

   # 2. Authorized Conduit: EWS (192.168.20.100) to PLC (192.168.20.10) on Port 502
   /ip firewall filter add chain=forward in-interface=bridge-OT out-interface=bridge-OT src-address=192.168.20.100 dst-address=192.168.20.10 protocol=tcp dst-port=502 action=accept comment="CONDUIT: EWS to PLC Modbus TCP"

   # 3. Log Perimeter Violations from the IT Zone
   /ip firewall filter add chain=forward in-interface=ether2-IT out-interface=bridge-OT protocol=tcp dst-port=502 action=log log-prefix="[OT-ALERT]" comment="LOG: Unauthorized IT Access to PLC"

   # 4. Drop All Direct Traffic from IT Zone to OT Zone
   /ip firewall filter add chain=forward in-interface=ether2-IT out-interface=bridge-OT action=drop comment="BLOCK: Direct IT to OT Traffic"
   ```

---

### Phase 2: PLC Endpoint Setup & Simulator Script (`plc_sim.py`)

On the **PLC Simulator PC** (connected to **Port 4 / `ether4-OT-PLC`**), assign a static IP address via an Administrator PowerShell prompt:

```powershell
netsh interface ipv4 set address name="Ethernet" static 192.168.20.10 255.255.255.0 192.168.20.1
```

Create `plc_sim.py` using pure Python to serve Modbus TCP requests on Port 502:

```python
import socket
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
            if not pdu:
                break
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
```

Run the script in PowerShell with **Administrator privileges** (required to bind to privileged Port 502):

```powershell
python plc_sim.py
```

---

### Phase 3: EWS Client Setup & Polling Script (`test_modbus.py`)

On the **EWS PC** (connected to **Port 3 / `ether3-OT-SCADA`**), configure its static IP address:

```powershell
netsh interface ipv4 set address name="Ethernet" static 192.168.20.100 255.255.255.0 192.168.20.1
```

Create `test_modbus.py` to test reading registers across the conduit:

```python
import socket
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
```

---

## 6. Testing, Results & Empirical Validation

| Test Case | Source Zone / Interface | Source IP | Expected Behavior | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1:** Authorized Conduit | `bridge-OT` (`ether3-OT-SCADA`) | `192.168.20.100` | Permitted via Conduit; returns live register values | **PASSED** |
| **Scenario 2:** IT Zone Penetration | `ether2-IT` | `192.168.10.50` | Dropped at perimeter; triggers `[OT-ALERT]` log | **PASSED** |
| **Scenario 3:** IP Spoofing Attack | `ether2-IT` | `192.168.20.100` (Spoofed) | Blocked by `in-interface` binding & strict RPF | **PASSED** |

### Scenario 1: Authorized Conduit Verification
* **Condition:** EWS PC connected to `ether3-OT-SCADA` with IP `192.168.20.100`.
* **Execution:** `python test_modbus.py`
* **Output:**
  ```text
  [*] PLC Response from 192.168.20.10:
      - Pressure    (40001): 1487 psi
      - Temperature (40002): 246 deg C
      - Flow Rate   (40003): 51 m3/h
  ```
* **Result:** **PASSED.** Process telemetry data is accurately read through the authorized conduit path.

### Scenario 2: Penetration Test from Enterprise/IT Zone (Unauthorized Ingress)
* **Condition:** Ethernet cable moved to `ether2-IT` with an IT segment IP configuration (`192.168.10.50/24`, Gateway `192.168.10.1`).
* **Execution:** `python test_modbus.py`
* **Output:**
  ```text
  TimeoutError: timed out
  ```
* **RouterOS Log Evidence (Winbox -> Log):**
  ```text
  [OT-ALERT] forward: in:ether2-IT out:bridge-OT, proto TCP (SYN), 192.168.10.50:xxxxx->192.168.20.10:502
  ```
* **Result:** **PASSED.** The TCP SYN packet is immediately dropped at the router perimeter and triggers the security alert log signature.

### Scenario 3: IP Spoofing Attack Analysis
* **Threat Scenario:** What if an attacker in the IT Zone (`ether2-IT`) manually configures the static IP `192.168.20.100` to impersonate the authorized Engineering Workstation?
* **Defense Mechanisms:**
  1. **In-Interface Enforcement:** The conduit permit rule explicitly binds traffic to `in-interface=bridge-OT`. Because the spoofed packet enters via `ether2-IT`, the permit rule is bypassed and the packet falls through to the drop rule.
  2. **Reverse Path Filtering (RPF):** When enabled (`rp-filter=strict`), the router detects an asymmetric route (subnet `192.168.20.0/24` belongs to `bridge-OT`, not `ether2-IT`) and discards the packet at the kernel level before firewall evaluation.
  3. **TCP Three-Way Handshake Breakdown:** Even if a forged `SYN` packet were to reach the PLC, the PLC's `SYN-ACK` reply would be routed to the legitimate IP owner on `bridge-OT`. The attacker in the IT Zone never receives the `SYN-ACK`, preventing a TCP session from ever completing.

---

## 7. Lessons Learned & Advanced Hardening Recommendations

* **Importance of Physical Interface Validation:** Industrial network security cannot rely solely on Layer 3 header inspection (Source/Destination IP). Binding rules to physical ingress interfaces (`in-interface`) is a foundational defense against IP spoofing.
* **Deep Packet Inspection (DPI) Gap:** Layer 3/4 firewall filters operate in a binary manner—allowing or blocking all traffic on TCP Port 502. To achieve higher **ISA/IEC 62443 Security Levels (SL-2 / SL-3)**, deploy an industrial firewall capable of DPI to granularly inspect and filter Modbus Function Codes (e.g., permitting `FC 03` Read Holding Registers while blocking `FC 05/06/16` Write commands).
* **Layer 2 Local Port Hardening:** To mitigate insider threats or attackers with physical access to local OT switch ports, enable **Static ARP** (`arp=reply-only`) on `bridge-OT` alongside **Bridge Port Isolation / Horizon** to restrict unauthorized lateral movement at Layer 2.
