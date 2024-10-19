from scapy.all import sniff, get_if_list, DHCP, BOOTP
from scapy.layers.inet import IP, TCP, UDP
import os
from datetime import datetime

LOG_DOSYA_YOLU = ""

def paket_renklendir(pkt, engelli=False):
    if engelli:
        return '\033[91m' + str(pkt.summary()) + '\033[0m' 
    elif TCP in pkt:
        return '\033[94m' + str(pkt.summary()) + '\033[0m' 
    elif UDP in pkt:
        if DHCP in pkt:
            return '\033[95m' + str(pkt.summary()) + '\033[0m'  
        return '\033[92m' + str(pkt.summary()) + '\033[0m'  
    else:
        return '\033[91m' + str(pkt.summary()) + '\033[0m'  

def dhcp_analiz(pkt):
    if DHCP in pkt:
        detaylar = "\nDHCP Paket Detayları:\n"
        dhcp_opsiyonlar = pkt[DHCP].options
        for opt in dhcp_opsiyonlar:
            if isinstance(opt, tuple):
                detaylar += f"{opt[0]}: {opt[1]}\n"
            else:
                detaylar += f"{opt}\n"
        print(detaylar)
        return detaylar

def log_kaydet(islem, sebep, pkt, paket_turu, port):
    zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_adi = "Bilinmiyor"
    if paket_turu == 'TCP':
        port_adi = "TCP Port"
    elif paket_turu == 'UDP':
        port_adi = "UDP Port"
    elif paket_turu == 'DHCP':
        port_adi = "DHCP"
    log_kaydi = f"{zaman} - {islem} - {sebep} - Engellenen Paket: {pkt.summary()} - Paket Türü: {paket_turu} - Port: {port} - Port Adı: {port_adi}\n"
    with open(LOG_DOSYA_YOLU, "a") as log_dosyasi:
        log_dosyasi.write(log_kaydi)

def paket_yakala(pkt):
    protokol = None
    port = None
    islem = None
    sebep = None

    if IP in pkt:
        protokol = pkt[IP].proto

    if TCP in pkt:
        port = pkt[TCP].sport
        protokol = 'TCP'
    elif UDP in pkt:
        port = pkt[UDP].sport
        protokol = 'UDP'
        if DHCP in pkt:
            protokol = 'DHCP'

    tehdit_tcp_portlar = [21, 23, 25, 80, 110, 143, 443, 445, 3389]
    tehdit_udp_portlar = [53, 67, 68, 137, 138, 139]

    if protokol == 'TCP' and port in tehdit_tcp_portlar:
        islem = "Engellendi"
        sebep = "Tehlikeli TCP portu"
        os.system(f"sudo iptables -A INPUT -p tcp --sport {port} -j DROP")
        print(paket_renklendir(pkt, engelli=True))
        print(f"Tehdit: {sebep}")
    elif protokol == 'UDP' and port in tehdit_udp_portlar:
        islem = "Engellendi"
        sebep = "Tehlikeli UDP portu"
        os.system(f"sudo iptables -A INPUT -p udp --sport {port} -j DROP")
        print(paket_renklendir(pkt, engelli=True))
        print(f"Tehdit: {sebep}")
    elif protokol == 'DHCP':
        islem = "Engellendi"
        sebep = "Tehlikeli DHCP paketi"
        dhcp_analiz(pkt)
        os.system("sudo iptables -A INPUT -p udp --dport 67 -j DROP")
        print(paket_renklendir(pkt, engelli=True))
        print(f"Tehdit: {sebep}")

    if islem:
        log_kaydet(islem, sebep, pkt, protokol, port)
    else:
        print(paket_renklendir(pkt))
        print(f"Protokol: {protokol}")
        print(f"Port: {port}")
        print(pkt.show(dump=True))

def kullanici_girdisi():
    global LOG_DOSYA_YOLU

    arayuzler = get_if_list()
    print("Kullanmak istediğiniz ağ arayüzünü seçin:")
    for i, arayuz in enumerate(arayuzler):
        print(f"{i + 1}. {arayuz}")
    
    secilen_arayuz = int(input("Seçiminiz (sayı girin): ")) - 1
    if secilen_arayuz < 0 or secilen_arayuz >= len(arayuzler):
        print("Geçersiz seçim!")
        return None, None

    arayuz = arayuzler[secilen_arayuz]

    LOG_DOSYA_YOLU = input("Log dosyasının kaydedileceği yolu girin (örn: /home/user/log.txt): ")
    if not LOG_DOSYA_YOLU:
        print("Geçersiz dosya yolu!")
        return None, None

    return arayuz, LOG_DOSYA_YOLU

def main():
    arayuz, log_dosyasi_yolu = kullanici_girdisi()
    if arayuz and log_dosyasi_yolu:
        print(f"{arayuz} arayüzünde dinleniyor...")
        sniff(iface=arayuz, prn=paket_yakala, store=False)
    else:
        print("Program sonlandırıldı.")

if __name__ == "__main__":
    main()

