import tkinter as tk
from scapy.all import *
import sqlite3

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("800x600")  # Set initial window size

        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.packet_listbox = tk.Listbox(self.root, width=120, height=30)  # Set initial listbox size
        self.packet_listbox.pack(pady=10)

        self.stop_sniffing_flag = False

        self.create_db_table()

    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_sniffing_flag = False
        self.sniff_packets()

    def stop_sniffing(self):
        self.stop_sniffing_flag = True
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        if not self.stop_sniffing_flag:
            packet = sniff(count=1)
            self.packet_callback(packet[0])
            self.root.after(100, self.sniff_packets)  # Call sniff_packets again after 100 milliseconds

    def packet_callback(self, packet):
        if IP in packet:
            packet_info = f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst} | Protocol: {packet[IP].proto}"
            self.packet_listbox.insert(tk.END, packet_info)
            self.insert_into_db(packet_info)

    def create_db_table(self):
        conn = sqlite3.connect("packet_info.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, packet_info TEXT)''')
        conn.commit()
        conn.close()

    def insert_into_db(self, packet_info):
        conn = sqlite3.connect("packet_info.db")
        c = conn.cursor()
        c.execute('''INSERT INTO packets (packet_info) VALUES (?)''', (packet_info,))
        conn.commit()
        conn.close()

def main():
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
