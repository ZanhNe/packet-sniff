from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    """
    Hàm này sẽ được gọi cho mỗi gói tin bắt được.
    """

    # Kiểm tra xem gói tin có lớp IP không (bỏ qua các gói tin Lớp 2)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Kiểm tra xem gói tin là TCP hay UDP
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"[TCP] {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")

        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"[UDP] {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

        else:
            # Các giao thức khác bên trong IP (ví dụ: ICMP)
            print(f"[IP] {ip_src} -> {ip_dst} (Protocol: {packet[IP].proto})")

def main():
    print("Đang bắt đầu bắt gói tin... (Nhấn Ctrl+C để dừng)")
    # Lắng nghe 20 gói tin, sau đó gọi hàm process_packet cho mỗi gói
    sniff(count=20, prn=process_packet, store=False) 

    # Nếu muốn nó chạy mãi mãi, dùng:
    # sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()