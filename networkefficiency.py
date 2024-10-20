import tkinter as tk
from tkinter import messagebox
import psutil
import subprocess
import time
import platform
import re
import socket  
from scapy.all import sniff  


def hesapla_verimlilik(bw, latency, packet_loss, congestion):
    return (bw * 0.4) + ((100 - latency) * 0.3) + ((100 - packet_loss) * 0.2) + ((100 - congestion) * 0.1)


def get_latency(host="8.8.8.8"):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        output = subprocess.check_output(f"ping {param} 4 {host}", shell=True, universal_newlines=True)
        print("Gecikme Çıktısı:", output)
        
        match = re.search(r'Average = (\d+)ms', output)
        if match:
            latency = float(match.group(1))
            return latency
    except Exception as e:
        print(f"Gecikme değeri alınamadı: {e}")
    return None


def get_packet_loss(host="8.8.8.8"):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        output = subprocess.check_output(f"ping {param} 4 {host}", shell=True, universal_newlines=True)
        print("Paket Kaybı Çıktısı:", output)
        
        match = re.search(r'Lost = (\d+) \((\d+)% loss\)', output)
        if match:
            loss = float(match.group(2))
            return loss
    except Exception as e:
        print(f"Paket kaybı değeri alınamadı: {e}")
    return None


def get_bandwidth():
    try:
        net1 = psutil.net_io_counters()
        time.sleep(1) 
        net2 = psutil.net_io_counters()
        sent_bytes_per_sec = (net2.bytes_sent - net1.bytes_sent) / 1024  
        recv_bytes_per_sec = (net2.bytes_recv - net1.bytes_recv) / 1024  
        total_bandwidth = sent_bytes_per_sec + recv_bytes_per_sec
        return total_bandwidth
    except Exception as e:
        print(f"Bant genişliği alınamadı: {e}")
        return None

# Tıkanıklık oranını hesaplama
def get_congestion():
    try:
        net1 = psutil.net_io_counters()
        time.sleep(1)  
        net2 = psutil.net_io_counters()

        sent_bytes = net2.bytes_sent - net1.bytes_sent
        recv_bytes = net2.bytes_recv - net1.bytes_recv

        total_bytes = sent_bytes + recv_bytes
        total_bandwidth = (total_bytes / 1024)  

        congestion = (total_bandwidth / 1024) * 100  
        congestion = min(congestion, 100)  

        return congestion
    except Exception as e:
        print(f"Tıkanıklık oranı alınamadı: {e}")
        return None


def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


packet_count = 0


def packet_callback(packet):
    global packet_count
    packet_count += 1  

    protocol = packet.proto  
    src_ip = packet[1].src  
    dst_ip = packet[1].dst  
    label_packet_info.config(text=f"Protokol: {protocol}, Kaynak IP: {src_ip}, Hedef IP: {dst_ip}")
    label_packet_count.config(text=f"Dinlenen Paket Sayısı: {packet_count}")  # Paket sayısını göster


def start_sniffing():
    global packet_count
    packet_count = 0  
    label_packet_info.config(text="Paketleri dinlemeye başlıyor...")
    label_packet_count.config(text="Dinlenen Paket Sayısı: 0") 
    sniff(prn=packet_callback, filter="ip", store=0, timeout=10)  


def hesapla_ve_dinle():
    bandwidth = get_bandwidth()
    latency = get_latency()
    packet_loss = get_packet_loss()
    congestion = get_congestion()
    local_ip = get_local_ip()

    if latency is None or packet_loss is None or bandwidth is None or congestion is None:
        messagebox.showerror("Hata", "Bazı ağ verileri alınamadı, terminali kontrol edin.")
        return

    verimlilik = hesapla_verimlilik(bandwidth, latency, packet_loss, congestion)

    label_bw.config(text=f"Bant Genişliği Kullanımı: {bandwidth:.2f} KB/s")
    label_latency.config(text=f"Gecikme (Latency): {latency:.2f} ms")
    label_packet_loss.config(text=f"Paket Kaybı: {packet_loss:.2f} %")
    label_congestion.config(text=f"Tıkanıklık Skoru: {congestion:.2f} %")
    label_verimlilik.config(text=f"Ağ Verimliliği: {verimlilik:.2f} %")
    label_local_ip.config(text=f"Kendi IP Adresiniz: {local_ip}")

    
    start_sniffing()


root = tk.Tk()
root.title("Gerçek Zamanlı Ağ Verimliliği Hesaplama")


label_bw = tk.Label(root, text="Bant Genişliği Kullanımı: -")
label_bw.pack(pady=5)

label_latency = tk.Label(root, text="Gecikme (Latency): -")
label_latency.pack(pady=5)

label_packet_loss = tk.Label(root, text="Paket Kaybı: -")
label_packet_loss.pack(pady=5)

label_congestion = tk.Label(root, text="Tıkanıklık Skoru: -")
label_congestion.pack(pady=5)

label_verimlilik = tk.Label(root, text="Ağ Verimliliği: -")
label_verimlilik.pack(pady=10)

label_local_ip = tk.Label(root, text="Kendi IP Adresiniz: -")
label_local_ip.pack(pady=5)

label_packet_info = tk.Label(root, text="Dinlenen Paket Bilgisi: -")
label_packet_info.pack(pady=5)

label_packet_count = tk.Label(root, text="Dinlenen Paket Sayısı: 0")  
label_packet_count.pack(pady=5)


hesapla_dinle_button = tk.Button(root, text="Ağ Verimliliğini Hesapla ve Dinlemeyi Başlat", command=hesapla_ve_dinle)
hesapla_dinle_button.pack(pady=20)


root.mainloop()
