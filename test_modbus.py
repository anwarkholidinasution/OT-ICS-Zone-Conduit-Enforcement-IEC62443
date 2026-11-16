import socket
import struct

target_ip = "192.168.20.10"
port = 502

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect((target_ip, port))

# Modbus TCP Request: FC 03 (Read 3 Holding Registers: Tekanan, Suhu, Flow)
# TransID=1, ProtoID=0, Len=6, UnitID=1, FC=3, Start=0, Count=3
request = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 3)
s.sendall(request)

response = s.recv(1024)
s.close()

# Ekstraksi MBAP dan PDU
trans_id, proto_id, length, unit_id, fc, byte_count = struct.unpack(">HHHBBB", response[:9])
registers = struct.unpack(f">{byte_count//2}H", response[9:9+byte_count])

print(f"[*] Respon PLC {target_ip}:")
print(f"    - Tekanan   (40001): {registers[0]} psi")
print(f"    - Suhu      (40002): {registers[1]} deg C")
print(f"    - Flow Rate (40003): {registers[2]} m3/h")