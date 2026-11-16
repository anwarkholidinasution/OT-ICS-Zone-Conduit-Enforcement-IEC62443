import socket
import struct
import threading
import time
import random

# Definisi Nilai Awal Register Proses (40001: Tekanan, 40002: Suhu, 40003: Flow Rate)
holding_registers = [1500, 250, 50]

def update_process_variables():
    """Simulasi variasi dinamika proses industri"""
    global holding_registers
    while True:
        holding_registers[0] = 1500 + random.randint(-15, 15)  # Tekanan: 1485 - 1515 psi
        holding_registers[1] = 250 + random.randint(-4, 4)     # Suhu: 246 - 254 C
        holding_registers[2] = 50 + random.randint(-2, 2)      # Flow Rate: 48 - 52 m3/h
        time.sleep(2)

def handle_client(conn, addr):
    print(f"[INFO] Sesi komunikasi aktif dari: {addr[0]}:{addr[1]}")
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

                # Susun PDU Balasan
                response_pdu = struct.pack(">BB", fc, byte_count)
                for i in range(start_addr, start_addr + reg_count):
                    val = holding_registers[i] if i < len(holding_registers) else 0
                    response_pdu += struct.pack(">H", val)

                # Susun MBAP Header Balasan
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
    print("[*] PLC Simulator aktif. Mendengarkan pada TCP Port 502...")

    # Jalankan thread pembaruan nilai proses
    t_process = threading.Thread(target=update_process_variables, daemon=True)
    t_process.start()

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    start_server()