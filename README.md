# python-firewall
Basic firewall with scapy and iptables

# Ağ Paket Analiz Aracı / Network Packet Analysis Tool

Bu proje, belirli ağ paketlerini yakalayıp analiz eden bir Python uygulamasıdır. Uygulama, tehlikeli TCP ve UDP portlarını izler ve bu portlardan gelen paketleri engeller. Ayrıca, DHCP paketlerini analiz ederek potansiyel tehditleri tespit eder.

This project is a Python application that captures and analyzes specific network packets. The application monitors dangerous TCP and UDP ports and blocks packets coming from these ports. It also analyzes DHCP packets to detect potential threats.

## Özellikler / Features

- **Ağ Arayüzü Seçimi**: Kullanıcı, dinlemek istediği ağ arayüzünü seçebilir.
- **Paket Renk Kodlama**: Farklı protokollere göre paketler renk kodlarıyla gösterilir.
- **Tehlikeli Port Engelleme**: Belirlenen tehlikeli TCP ve UDP portlarından gelen paketler otomatik olarak engellenir.
- **DHCP Paket Analizi**: DHCP paketleri detaylı bir şekilde analiz edilerek kullanıcıya sunulur.
- **Log Kaydı**: Engellenen paketler ve nedenleri log dosyasına kaydedilir.

- **Network Interface Selection**: Users can select the network interface they want to listen to.
- **Packet Color Coding**: Packets are displayed with color codes based on different protocols.
- **Dangerous Port Blocking**: Packets coming from specified dangerous TCP and UDP ports are automatically blocked.
- **DHCP Packet Analysis**: DHCP packets are analyzed in detail and presented to the user.
- **Log Recording**: Blocked packets and their reasons are recorded in a log file.

## Gereksinimler / Requirements

- Python 3.x
- Scapy kütüphanesi
- Yönetici (sudo) izinleri

- Python 3.x
- Scapy library
- Administrator (sudo) permissions

## Kurulum / Installation

1. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install scapy

   
1. Install required libaries:
   ```bash
   pip install scapy
