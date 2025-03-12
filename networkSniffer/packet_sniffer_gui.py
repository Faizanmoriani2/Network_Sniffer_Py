import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import Counter
import threading
import requests
import csv
from tkinter import filedialog

class EnhancedPacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Network Packet Sniffer")
        self.root.geometry("800x600")
        self.root.configure(bg="#1e1e1e")

        # Initialize packet data
        self.packets = []
        self.packet_count = 0
        self.protocol_counter = Counter()
        self.sniffing = False

        # Title
        title_label = tk.Label(
            self.root,
            text="Enhanced Network Packet Sniffer",
            font=("Arial", 16, "bold"),
            fg="white",
            bg="#1e1e1e",
        )
        title_label.pack(pady=10)

        # Controls Frame
        controls_frame = tk.Frame(self.root, bg="#1e1e1e")
        controls_frame.pack(pady=10)

        # Filters
        self.filter_label = tk.Label(controls_frame, text="Protocol Filter:", font=("Arial", 10), fg="white", bg="#1e1e1e")
        self.filter_label.grid(row=0, column=0, padx=5)
        self.filter_entry = tk.Entry(controls_frame, width=15)
        self.filter_entry.grid(row=0, column=1, padx=5)

        self.packet_limit_label = tk.Label(controls_frame, text="Packet Limit:", font=("Arial", 10), fg="white", bg="#1e1e1e")
        self.packet_limit_label.grid(row=0, column=2, padx=5)
        self.packet_limit_entry = tk.Entry(controls_frame, width=10)
        self.packet_limit_entry.grid(row=0, column=3, padx=5)

        # Start/Stop Buttons
        self.start_button = tk.Button(controls_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4caf50", fg="white")
        self.start_button.grid(row=0, column=4, padx=10)
        self.stop_button = tk.Button(controls_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white")
        self.stop_button.grid(row=0, column=5, padx=10)

        # Search Bar
        self.search_label = tk.Label(controls_frame, text="Search (IP/Protocol):", font=("Arial", 10), fg="white", bg="#1e1e1e")
        self.search_label.grid(row=1, column=0, padx=5)
        self.search_entry = tk.Entry(controls_frame, width=20)
        self.search_entry.grid(row=1, column=1, padx=5)
        self.search_button = tk.Button(controls_frame, text="Search", command=self.search_packets, bg="#2196f3", fg="white")
        self.search_button.grid(row=1, column=2, padx=10)

        # Save and Clear Buttons
        self.save_pcap_button = tk.Button(controls_frame, text="Save as PCAP", command=self.save_as_pcap, bg="#607d8b", fg="white")
        self.save_pcap_button.grid(row=1, column=3, padx=10)

        self.clear_button = tk.Button(controls_frame, text="Clear Packets", command=self.clear_packets, bg="#9c27b0", fg="white")
        self.clear_button.grid(row=1, column=4, padx=10)

        # Packet Display Table
        self.packet_tree = ttk.Treeview(self.root, columns=("No", "Source", "Destination", "Protocol"), show="headings")
        self.packet_tree.heading("No", text="No")
        self.packet_tree.heading("Source", text="Source (IP + Location)")
        self.packet_tree.heading("Destination", text="Destination (IP + Location)")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        # Bind click event
        self.packet_tree.bind("<Double-1>", self.show_packet_details)

        # Style
        style = ttk.Style()
        style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e", rowheight=25)
        style.map("Treeview", background=[("selected", "#1a73e8")], foreground=[("selected", "white")])

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def sniff_packets(self):
        def packet_callback(packet):
            if not self.sniffing:
                return

            self.packet_count += 1
            src_ip = packet.getlayer(IP).src if packet.haslayer(IP) else "N/A"
            dst_ip = packet.getlayer(IP).dst if packet.haslayer(IP) else "N/A"
            protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet.getlayer(IP).proto, "Other") if packet.haslayer(IP) else "Other"

            src_location = self.get_ip_geolocation(src_ip)
            dst_location = self.get_ip_geolocation(dst_ip)

            self.packets.append(packet)
            self.packet_tree.insert("", "end", values=(self.packet_count, f"{src_ip} ({src_location})", f"{dst_ip} ({dst_location})", protocol))

            if self.packet_limit_entry.get().isdigit() and len(self.packets) >= int(self.packet_limit_entry.get()):
                self.stop_sniffing()

        sniff(prn=packet_callback, store=False, filter=self.filter_entry.get() if self.filter_entry.get() else None)

    def search_packets(self):
        query = self.search_entry.get().lower()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        for i, packet in enumerate(self.packets, start=1):
            src_ip = packet.getlayer(IP).src if packet.haslayer(IP) else "N/A"
            dst_ip = packet.getlayer(IP).dst if packet.haslayer(IP) else "N/A"
            protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet.getlayer(IP).proto, "Other") if packet.haslayer(IP) else "Other"

            if query in src_ip.lower() or query in dst_ip.lower() or query in protocol.lower():
                self.packet_tree.insert("", "end", values=(i, src_ip, dst_ip, protocol))

    def save_as_pcap(self):
        from scapy.utils import wrpcap

        try:
            wrpcap("captured_packets.pcap", self.packets)
            messagebox.showinfo("Save Successful", "Packets saved as 'captured_packets.pcap'.")
        except Exception as e:
            messagebox.showerror("Save Failed", f"An error occurred: {e}")

    def clear_packets(self):
        self.packets.clear()
        self.packet_count = 0
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        messagebox.showinfo("Clear Successful", "All captured packets have been cleared.")

    def show_packet_details(self, event):
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        index = int(self.packet_tree.item(selected_item)["values"][0]) - 1
        packet = self.packets[index]

        details_window = tk.Toplevel(self.root)
        details_window.title("Packet Details")
        details_window.geometry("800x600")

        # Create a Treeview for displaying details
        tree = ttk.Treeview(details_window, columns=("Field", "Value"), show="headings")
        tree.heading("Field", text="Field")
        tree.heading("Value", text="Value")
        tree.column("Field", anchor=tk.W, width=200)
        tree.column("Value", anchor=tk.W, width=580)
        tree.pack(fill=tk.BOTH, expand=True)

        # Helper to add rows
        def add_row(field, value):
            tree.insert("", tk.END, values=(field, value))

        # Basic Packet Summary
        add_row("Summary", packet.summary())

        # Ethernet Layer (if present)
        if packet.haslayer("Ethernet"):
            eth_layer = packet.getlayer("Ethernet")
            add_row("Ethernet Source MAC", eth_layer.src)
            add_row("Ethernet Destination MAC", eth_layer.dst)
            add_row("Ethernet Type", eth_layer.type)

        # IP Layer (if present)
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            add_row("IP Source", ip_layer.src)
            add_row("IP Destination", ip_layer.dst)
            add_row("IP Protocol", ip_layer.proto)
            add_row("IP TTL (Time To Live)", ip_layer.ttl)

        # TCP Layer (if present)
        if packet.haslayer("TCP"):
            tcp_layer = packet.getlayer("TCP")
            add_row("TCP Source Port", tcp_layer.sport)
            add_row("TCP Destination Port", tcp_layer.dport)
            add_row("TCP Sequence Number", tcp_layer.seq)
            add_row("TCP Acknowledgment Number", tcp_layer.ack)
            add_row("TCP Flags", tcp_layer.flags)

        # UDP Layer (if present)
        if packet.haslayer("UDP"):
            udp_layer = packet.getlayer("UDP")
            add_row("UDP Source Port", udp_layer.sport)
            add_row("UDP Destination Port", udp_layer.dport)

        # DNS Layer (if present)
        if packet.haslayer("DNS"):
            dns_layer = packet.getlayer("DNS")
            add_row("DNS Query Name", dns_layer.qd.qname.decode('utf-8') if dns_layer.qd else "N/A")
            add_row("DNS Query Type", dns_layer.qd.qtype if dns_layer.qd else "N/A")
            add_row("DNS Answer", dns_layer.an.rdata if dns_layer.an else "N/A")

        # HTTP Layer (if present in Raw Data)
        if packet.haslayer("Raw"):
            raw_data = packet.getlayer("Raw").load
            if b"HTTP" in raw_data:
                try:
                    http_data = raw_data.decode("utf-8", errors="ignore")
                    add_row("HTTP Data", http_data)
                except Exception as e:
                    add_row("HTTP Data", f"Failed to decode HTTP data: {str(e)}")

        # TLS/SSL Layer (if present)
        if packet.haslayer("TLS"):
            tls_layer = packet.getlayer("TLS")
            add_row("TLS Protocol Version", tls_layer.version)
            add_row("TLS Handshake Type", tls_layer.type)
            add_row("TLS Length", len(tls_layer))

        # ARP Layer (if present)
        if packet.haslayer("ARP"):
            arp_layer = packet.getlayer("ARP")
            add_row("ARP Source MAC", arp_layer.hwsrc)
            add_row("ARP Destination MAC", arp_layer.hwdst)
            add_row("ARP Protocol Type", arp_layer.ptype)

        # ICMP Layer (if present)
        if packet.haslayer("ICMP"):
            icmp_layer = packet.getlayer("ICMP")
            add_row("ICMP Type", icmp_layer.type)
            add_row("ICMP Code", icmp_layer.code)

        # Raw Payload Size
        payload_size = len(packet.payload)
        add_row("Payload Size (bytes)", payload_size)

        # Function to export data to CSV
        def export_to_csv():
            file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if file_path:
                # Open the file and write the rows
                with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Field", "Value"])  # Write header row
                    for item in tree.get_children():
                        field, value = tree.item(item)["values"]
                        writer.writerow([field, value])
                tk.messagebox.showinfo("Export Successful", "Packet details have been saved to CSV!")

        # Add Export and Close Buttons
        export_button = tk.Button(details_window, text="Export to CSV", command=export_to_csv)
        export_button.pack(pady=5)

        close_button = tk.Button(details_window, text="Close", command=details_window.destroy)
        close_button.pack(pady=10)

    def get_ip_geolocation(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                return f"{data['city']}, {data['country']}"
            return "Unknown Location"
        except Exception as e:
            return "Error Fetching Location"


# Start the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedPacketSnifferApp(root)
    root.mainloop()
