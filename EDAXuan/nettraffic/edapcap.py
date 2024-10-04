import nest_asyncio
import pyshark
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
import subprocess

# Cho phép nhiều event loop chạy đồng thời
import pandas as pd
from datetime import datetime, timedelta
import pytz
import matplotlib.pyplot as plt
import seaborn as sns
import re
import geoip2.database
import folium
import numpy as np
# from typing import List, Set,Tuple
import networkx as nx
import json
import ipaddress
import nest_asyncio
from concurrent.futures import ThreadPoolExecutor
nest_asyncio.apply()



df = pd.DataFrame()
def process_csv(filepcapcsv: str,filepcap:str):
    # Đọc dữ liệu từ file CSV đầu vào
    # global df 
    df1 = pd.read_csv(filepcapcsv)
    df=pd.DataFrame()
    # Xử lý các cột cần thiết
    # df = pd.DataFrame()
    df['Flow ID'] = df1['Flow ID']
    df['Timestamp'] = df1['Timestamp']
    df['Source IP'] = df1['Src IP']
    df['Destination IP'] = df1['Dst IP']
    df['Source Port'] = df1['Src Port']
    df['Destination Port'] = df1['Dst Port']

    # Chuyển đổi múi giờ cho cột 'Timestamp', đưa về dạng UTC
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%m/%Y %I:%M:%S %p')
    # df['Timestamp'] = df['Timestamp'].dt.tz_localize('Asia/Ho_Chi_Minh')
    # df['Timestamp'] = df['Timestamp'].dt.tz_convert('UTC')

    # Ánh xạ giao thức dựa trên số
    protocol_map = {
        0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP", 5: "ST", 6: "TCP",
        8: "EGP", 9: "IGP", 17: "UDP", 27: "RDP", 41: "IPv6", 43: "IPv6-Route",
        44: "IPv6-Frag", 46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
        59: "IPv6-NoNxt", 60: "IPv6-Opts", 88: "EIGRP", 89: "OSPF", 132: "SCTP",
        137: "MPLS-in-IP"
    }

    def map_protocol(protocol_number):
        return protocol_map.get(protocol_number, f"Unknown {protocol_number}")

    df['Protocol'] = df1['Protocol'].apply(map_protocol)

    # Xác định giao thức tầng ứng dụng
    tcp_ports = {
        80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH', 25: 'SMTP', 110: 'POP3',
        143: 'IMAP', 23: 'Telnet', 53: 'DNS', 3306: 'MySQL', 5432: 'PostgreSQL',
        3389: 'RDP', 389: 'LDAP', 445: 'SMB', 1433: 'MSSQL', 139: 'NetBIOS',
        179: 'BGP', 2049: 'NFS', 995: 'POP3S', 993: 'IMAPS', 465: 'SMTPS', 9418: 'Git',
        514: 'Syslog', 8080: 'HTTP (Alternative)', 8443: 'HTTPS (Alternative)',
        902: 'VMware ESXi', 903: 'VMware ESXi', 1723: 'PPTP', 3128: 'Proxy', 
        8888: 'Web services', 5900: 'VNC', 873: 'rsync', 5985: 'WinRM (HTTP)',
        5986: 'WinRM (HTTPS)', 5222: 'XMPP (Client to Server)', 5223: 'XMPP (Client to Server - SSL)',
        6667: 'IRC', 8081: 'HTTP (Alternative)', 8000: 'HTTP (Alternative)',
        1812: 'RADIUS Authentication', 1813: 'RADIUS Accounting', 3268: 'Global Catalog (LDAP)',
        3269: 'Global Catalog (LDAP SSL)', 11211: 'Memcached', 27017: 'MongoDB',
        25565: 'Minecraft', 6379: 'Redis', 9100: 'JetDirect', 5000: 'Flask/Django Development Server',
        9090: 'Prometheus', 2181: 'Zookeeper', 8060: 'Roku', 9419: 'GitLab', 9933: 'SmartFoxServer',
        27015: 'Source Engine Games', 8086: 'InfluxDB', 9092: 'Apache Kafka', 1127: 'MS SQL-S',
        1521: 'Oracle Database', 27000: 'FlexLM', 2222: 'EtherNet/IP', 17500: 'Dropbox',
        27018: 'Azure Cosmos DB', 1883: 'MQTT', 7443: 'VMware Horizon', 9443: 'VMware vSphere',
        4840: 'OPC UA', 5984: 'CouchDB', 25672: 'RabbitMQ', 50070: 'Hadoop', 18080: 'MinIO',
        4000: 'BitTorrent', 7001: 'WebLogic', 8082: 'Kibana', 2048: 'Kerberos', 8500: 'ColdFusion',
        2182: 'Zookeeper (Alternative)', 10000: 'Webmin', 27019: 'MongoDB Shard', 6969: 'BitTorrent Tracker',
        465: 'SMTP over SSL', 2525: 'SMTP (Alternative)', 9411: 'Zipkin', 5988: 'WBEM (HTTP)', 
        5989: 'WBEM (HTTPS)', 5433: 'PostgreSQL (Alternative)', 2221: 'EtherNet/IP (Alternative)', 
        3690: 'SVN (Subversion)', 9999: 'Jupyter Notebook', 15000: 'Aerospike', 25565: 'Minecraft',
        9091: 'Deluge WebUI', 8332: 'Bitcoin', 9101: 'Bacula Director'
}


    udp_ports = {
        53: 'DNS', 67: 'DHCP/BOOTP', 68: 'DHCP/BOOTP', 123: 'NTP', 161: 'SNMP', 162: 'SNMP Trap',
        69: 'TFTP', 514: 'Syslog', 1812: 'RADIUS Authentication', 1813: 'RADIUS Accounting',
        520: 'RIP', 5060: 'VoIP (SIP)', 500: 'IKE', 4500: 'NAT-T', 33434: 'Traceroute',
        1434: 'MSSQL Monitor', 1194: 'OpenVPN', 1701: 'L2TP', 1900: 'SSDP (UPnP)',
        5353: 'mDNS (Bonjour)', 4789: 'VXLAN', 88: 'Kerberos', 137: 'NetBIOS Name Service',
        138: 'NetBIOS Datagram Service', 995: 'POP3S', 5061: 'VoIP (SIP-TLS)',
        3478: 'STUN', 3479: 'Google Voice/Hangouts', 6081: 'Geneve', 20000: 'DNP3', 6000: 'X11',
        27031: 'Steam Game Server', 27960: 'Quake III Arena Server', 45000: 'WireGuard',
        5350: 'NAT-PMP', 52311: 'IBM BigFix', 111: 'Portmap/RPC', 5355: 'LLMNR',
        3702: 'WS-Discovery', 47808: 'BACnet', 5004: 'RTP', 5005: 'RTCP', 8815: 'Tenda Router',
        30120: 'FiveM', 27000: 'FlexLM', 12345: 'NetBus', 3799: 'RADIUS CoA', 17185: 'Viber',
        2989: 'FreeSWITCH', 523: 'IBM-DB2', 10891: 'Jabber', 2427: 'MGCP (VoIP)',
        2727: 'MGCP (Alternative VoIP)', 5632: 'pcAnywhere', 64738: 'Mumble', 19302: 'Google Talk (STUN)',
        3784: 'Ventrilo', 1234: 'VLC Media Player', 9987: 'TeamSpeak 3', 51820: 'WireGuard',
        10001: 'Foscam'
}


    def determine_application_protocol(row):
        global filecsv
        protocol = row['Protocol']
        src_port = row['Source Port']
        dst_port = row['Destination Port']

        if protocol == 'TCP':
            return tcp_ports.get(src_port) or tcp_ports.get(dst_port) or f'Unknown TCP'
        elif protocol == 'UDP':
            return udp_ports.get(src_port) or udp_ports.get(dst_port) or f'Unknown UDP'
        else:
            return f'Non-Application'

    df['Application Protocol'] = df.apply(determine_application_protocol, axis=1)

    # Thêm các cột cần thiết khác
    df['Time_Delta'] = df1['Flow Duration']
    df['Totlen Pkts'] = df1['TotLen Fwd Pkts'] + df1['TotLen Bwd Pkts']
    df['Tot Fwd Pkts'] = df1['Tot Fwd Pkts']
    df['Tot Bwd Pkts'] = df1['Tot Bwd Pkts']
    df['TotLen Fwd Pkts'] = df1['TotLen Fwd Pkts']
    df['TotLen Bwd Pkts'] = df1['TotLen Bwd Pkts']
    df['Tot Pkts'] = df1['Tot Fwd Pkts'] + df1['Tot Bwd Pkts']

    # Đảm bảo cột 'Totlen Pkts' chứa giá trị số và thay NaN bằng 0
    df['Totlen Pkts'] = pd.to_numeric(df['Totlen Pkts'], errors='coerce').fillna(0)

    # Sắp xếp dữ liệu theo thời gian tăng dần
    df = df.sort_values(by="Timestamp", ascending=True)
    # df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df['Timestamp'] = df['Timestamp'].dt.tz_localize(None)  # Loại bỏ phần đuôi múi giờ
    df['Timestamp'] = df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M:%S')
    # Thay thế NaN bằng giá trị mong muốn (ví dụ: 0)
    df.fillna(0, inplace=True)

# Xử lí phần payload cho từng flow
    # Function to format payload into a readable string
# hàm cũ
    # def format_readable(data):
    #     return ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)

    # # Function to extract key information from a packet
    # def get_packet_key(packet):
    #     try:
    #         src_ip = packet.ip.src
    #         dst_ip = packet.ip.dst
    #         if 'TCP' in packet:
    #             return (src_ip, dst_ip, int(packet.tcp.srcport), int(packet.tcp.dstport), 'TCP', int(packet.tcp.seq))
    #         elif 'UDP' in packet:
    #             return (src_ip, dst_ip, int(packet.udp.srcport), int(packet.udp.dstport), 'UDP', 0)
    #     except AttributeError:
    #         return None

    # # Function to cache all packets from the pcap file
    # def cache_packets(pcap_file):
    #     capture = pyshark.FileCapture(pcap_file, display_filter='tcp or udp', include_raw=True, use_json=True)
    #     packet_cache = []

    #     for packet in capture:
    #         key = get_packet_key(packet)
    #         if key:
    #             # packet_time = (packet.sniff_time - timedelta(hours=7)).timestamp()  # Adjust to UTC
    #             packet_time = (packet.sniff_time).timestamp()  # Adjust to UTC
    #             packet_cache.append((key, packet_time, packet.get_raw_packet()))
    #             # print(packet.sniff_time)

    #     capture.close()
    #     return packet_cache

    # # Function to find payloads based on CSV row information and cached packets
    # def extract_payload_from_row(row, packet_cache):
    #     try:
    #         start_timestamp = datetime.strptime(row['Timestamp'], '%Y/%m/%d %H:%M:%S').timestamp()
    #     except ValueError:
    #         return "Invalid timestamp"

    #     time_delta = float(row['Time_Delta']) / 10**6 + 1.0
    #     end_timestamp = start_timestamp + time_delta

    #     src_ip, dst_ip = row['Source IP'], row['Destination IP']
    #     src_port, dst_port = int(row['Source Port']), int(row['Destination Port'])

    #     client_to_server_payloads = []
    #     server_to_client_payloads = []
    #     packets_to_remove = []

    #     for idx, (key, packet_time, payload) in enumerate(packet_cache):
    #         p_src_ip, p_dst_ip, p_src_port, p_dst_port,protocol, _ = key
    #         print(f"CSV Timestamp: {start_timestamp}, Packet Time: {packet_time}, Time Delta: {time_delta}")

    #         if (src_ip == p_src_ip and dst_ip == p_dst_ip and src_port == p_src_port and dst_port == p_dst_port) and (start_timestamp <= packet_time <= end_timestamp):
    #             if (p_src_ip, p_src_port) == (src_ip, src_port):
    #                 client_to_server_payloads.append(payload)
    #             else:
    #                 server_to_client_payloads.append(payload)

    #             # Mark this packet for removal since it satisfies the current row
    #             packets_to_remove.append(idx)

    #      # Remove the packets that have already been processed
    #     for idx in sorted(packets_to_remove, reverse=True):
    #         if idx < len(packet_cache):
    #             del packet_cache[idx]

    #     if not client_to_server_payloads and not server_to_client_payloads:
    #         return "No payload found for the flow"

    #     client_payload = format_readable(b''.join(client_to_server_payloads))
    #     server_payload = format_readable(b''.join(server_to_client_payloads))

    #     return f"Client to Server:\n{client_payload}\nServer to Client:\n{server_payload}"

    # # Function to handle payload extraction for parallel execution
    # def extract_payload_for_row(row, packet_cache):
    #     return extract_payload_from_row(row, packet_cache)

    # # Main function to process the CSV and append the payloads
    # def process_csv_and_add_payloads(pcap_file):
    #     # Cache all packets from the pcap file
    #     packet_cache = cache_packets(pcap_file)
    #     # # Extract payloads for each row in the CSV
    #     # df['Payload'] = df.apply(lambda row: extract_payload_from_row(row, packet_cache), axis=1)
    #     # Create a ThreadPoolExecutor for parallel execution
    #     with ThreadPoolExecutor() as executor:
    #         # Use the executor to apply `extract_payload_for_row` in parallel
    #         results = list(executor.map(lambda row: extract_payload_for_row(row, packet_cache), [row for _, row in df.iterrows()]))

    #     if len(results) != len(df):
    #         raise ValueError("Mismatch between the number of results and DataFrame rows")
    #     # Add the results as a new column to the DataFrame
    #     df['Payload'] = results
    # # Process the CSV and add payloads
    # process_csv_and_add_payloads(filepcap)


    # Hàm mới của Sang


    # Function to format payload into a readable string
    def format_readable(data):
        """Chuyển đổi dữ liệu bytes thành chuỗi dễ đọc (các ký tự hiển thị được)."""
        return ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)

    # Function to extract TCP and UDP payloads from a PCAP file
    def extract_payloads(pcap_file):
        """Sử dụng TShark để trích xuất payload từ gói tin TCP và UDP."""
        tshark_cmd = [
            'tshark',
            '-r', pcap_file,                # Đọc file PCAP
            '-T', 'fields',                 # Chỉ trích xuất các trường
            '-e', 'ip.src',                 # Địa chỉ IP nguồn
            '-e', 'ip.dst',                 # Địa chỉ IP đích
            '-e', 'tcp.srcport',            # Cổng nguồn TCP
            '-e', 'tcp.dstport',            # Cổng đích TCP
            '-e', 'udp.srcport',            # Cổng nguồn UDP
            '-e', 'udp.dstport',            # Cổng đích UDP
            '-e', 'tcp.payload',            # Payload TCP
            '-e', 'udp.payload',            # Payload UDP
            '-e', 'frame.time_epoch',       # Thời gian gói tin
            '-E', 'separator=,'             # Sử dụng dấu phẩy để phân tách
        ]

        try:
            # Chạy lệnh TShark và thu thập kết quả
            tshark_output = subprocess.check_output(tshark_cmd).decode('utf-8')

            tcp_payloads = []
            udp_payloads = []

            # Phân tích kết quả từ TShark
            for line in tshark_output.splitlines():
                parts = line.split(',')
                if len(parts) < 9:
                    continue

                p_src_ip, p_dst_ip, tcp_src_port, tcp_dst_port, udp_src_port, udp_dst_port, tcp_payload, udp_payload, packet_time = parts

                # Nếu có TCP payload
                if tcp_payload:
                    payload_bytes = bytes.fromhex(tcp_payload)
                    readable_payload = format_readable(payload_bytes)
                    tcp_payloads.append((p_src_ip, p_dst_ip, tcp_src_port, tcp_dst_port, readable_payload, packet_time))

                # Nếu có UDP payload
                if udp_payload:
                    payload_bytes = bytes.fromhex(udp_payload)
                    readable_payload = format_readable(payload_bytes)
                    udp_payloads.append((p_src_ip, p_dst_ip, udp_src_port, udp_dst_port, readable_payload, packet_time))
            print(f"tcp payload: {tcp_payloads}")
            print(f" udp payload: {udp_payloads}")
            return tcp_payloads, udp_payloads

        except subprocess.CalledProcessError as e:
            print(f"Error running TShark: {e}")
            return [], []

    # Function to match flow from CSV with TCP/UDP payloads
    def match_payloads(flow_row, tcp_payloads, udp_payloads):
        try:
            # Chuyển đổi thời gian với định dạng: "1/21/2022 12:11:53 AM" và cộng thêm 7 tiếng
            print(f"Converting timestamp: {flow_row['Timestamp']}")  # In timestamp để kiểm tra
            start_timestamp = datetime.strptime(flow_row['Timestamp'], '%Y/%m/%d %H:%M:%S').timestamp()
        except ValueError:
            print(f"Invalid timestamp: {flow_row['Timestamp']}")
            return "Invalid timestamp"

        # Tính toán thời gian kết thúc của flow dựa trên Time_Delta
        time_delta = float(flow_row['Time_Delta']) / 10**6 + 1.0
        end_timestamp = start_timestamp + time_delta


        src_ip, dst_ip = flow_row['Source IP'], flow_row['Destination IP']
        src_port, dst_port = int(flow_row['Source Port']), int(flow_row['Destination Port'])
        protocol = flow_row['Protocol']

        if protocol == 'TCP':
            matching_packets = [pkt for pkt in tcp_payloads if pkt[0] == src_ip and pkt[1] == dst_ip and pkt[2] == str(src_port) and pkt[3] == str(dst_port) and start_timestamp <= float(pkt[5]) <= end_timestamp]
        elif protocol == 'UDP':
            matching_packets = [pkt for pkt in udp_payloads if pkt[0] == src_ip and pkt[1] == dst_ip and pkt[2] == str(src_port) and pkt[3] == str(dst_port) and start_timestamp <= float(pkt[5]) <= end_timestamp]
        else:
            return "Unsupported protocol"

        if not matching_packets:
            return "No payload found for the flow"

        # Ghép nối payload từ tất cả các gói tin thuộc flow
        flow_payload = ''.join([pkt[4] for pkt in matching_packets])
        return flow_payload

    # Function to process the CSV and append the payloads
    def process_csv_and_add_payloads(pcap_file):
        # Load the CSV into a DataFrame, chỉ lấy các cột cần thiết
        # df = pd.read_csv(csv_file, usecols=['Flow ID', 'Timestamp', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Time_Delta'])

        # Trích xuất payload từ file PCAP
        tcp_payloads, udp_payloads = extract_payloads(pcap_file)

        # Match payload với từng dòng flow trong file CSV
        df['Payload'] = df.apply(lambda row: match_payloads(row, tcp_payloads, udp_payloads), axis=1)
        
        ## Test thôi
        # # Ghi nội dung của cột 'Payload' ra file text
        # with open('payload_output.txt', 'w') as file:
        #     for payload in df['Payload']:
        #         file.write(str(payload) + '\n')  # Ghi mỗi payload trên một dòng


        # Lưu DataFrame mới có chứa payload vào file CSV
        # df.to_csv('traffic4_with_payload.csv', index=False)

        # In nội dung DataFrame để kiểm tra
        # print(df[['Flow ID', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Payload']])

    # File paths
    # pcap_file = 'traffictest4.pcap'  # Đặt tên file PCAP của bạn
    # csv_file = 'traffictest4.pcap_Flow_processed.csv'    # Đặt tên file CSV của bạn

    # Process the CSV và thêm payload vào
    process_csv_and_add_payloads(filepcap)

    # Đặt tên file CSV mới và lưu file
    # filecsvlastresult = filepcapcsv.replace('.csv', '_processed.csv')
    # df.to_csv(filecsvlastresult, index=False)
    return df


# Lọc bỏ các dòng có địa chỉ MAC trong `source_ip` hoặc `destination_ip`
# hàm này ít dùng do cơ bản là Ip rồi
def is_ip_only_old(ip):
    # Kiểm tra xem địa chỉ IP có chứa địa chỉ MAC hay không
    ip_pattern = re.compile(r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    
    return bool(ip_pattern.fullmatch(ip))
    
    

"""
    Network
"""

# M1 Ip World Map 
def is_public_ip(ip):
    """Kiểm tra nếu IP là public"""
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def replace_private_ip(ip):
    """Trả về None nếu là private IP, ngược lại trả về IP"""
    if not is_public_ip(ip):
        return None
    return ip

def generate_ip_map(df):   
    # Lọc các địa chỉ IP hợp lệ
    filtered_df = df[df['Source IP'].apply(is_ip_only) & df['Destination IP'].apply(is_ip_only)]
    
    # Thay thế các private IP bằng None
    filtered_df['Source IP'] = filtered_df['Source IP'].apply(replace_private_ip)
    filtered_df['Destination IP'] = filtered_df['Destination IP'].apply(replace_private_ip)
    
    # Lấy các cặp IP duy nhất và đổi tên cột
    ip_pairs = filtered_df[['Source IP', 'Destination IP']].drop_duplicates()
    ip_pairs = ip_pairs.rename(columns={'Source IP': 'sourceIP', 'Destination IP': 'destinationIP'})
    
    # Chuẩn hóa thứ tự IP để tránh các cặp IP lặp ngược, bỏ qua các giá trị None
    def normalize_ip_order(row):
        if row['sourceIP'] is None or row['destinationIP'] is None:
            return row['sourceIP'], row['destinationIP']  # Giữ nguyên nếu có None
        return min(row['sourceIP'], row['destinationIP']), max(row['sourceIP'], row['destinationIP'])
    
    ip_pairs['sourceIP'], ip_pairs['destinationIP'] = zip(*ip_pairs.apply(normalize_ip_order, axis=1))
    
    # Loại bỏ các cặp mà một hoặc cả hai IP là None, và kiểm tra sự trùng lặp
    non_null_pairs = ip_pairs.dropna()

    def is_pair_valid(row):
        if pd.isna(row['sourceIP']) and pd.isna(row['destinationIP']):
            return False  # Loại bỏ cặp mà cả hai giá trị đều là None
        if pd.isna(row['sourceIP']) or pd.isna(row['destinationIP']):
            # Kiểm tra nếu cặp đã tồn tại với cả hai IP không phải None
            if row['sourceIP'] in non_null_pairs['sourceIP'].values or row['destinationIP'] in non_null_pairs['destinationIP'].values:
                return False  # Bỏ cặp này
        return True
    
    # Lọc các cặp không hợp lệ
    ip_pairs = ip_pairs[ip_pairs.apply(is_pair_valid, axis=1)]
    
    # Thay thế None bằng 'NULL' trước khi lưu vào cơ sở dữ liệu
    ip_pairs = ip_pairs.fillna('NULL')
    
    # Loại bỏ các cặp IP trùng lặp sau khi chuẩn hóa thứ tự
    ip_pairs = ip_pairs.drop_duplicates()


    return ip_pairs

# M2. Netgraph
# def generate_network_graph(df):
    # filtered_df = df[df['Source IP'].apply(is_ip_only_old) & df['Destination IP'].apply(is_ip_only_old)]
    # ip_pairs =filtered_df[['Source IP', 'Destination IP']].drop_duplicates()
    # ip_pairs = set(ip_pairs.itertuples(index=False, name=None))

    # # Tạo một đồ thị
    # G = nx.Graph()

    # # Thêm các cạnh (edge) vào đồ thị từ các cặp IP
    # G.add_edges_from(ip_pairs)

    # # Tạo danh sách nodes và edges để trả về
    # nodes = [{"id": node} for node in G.nodes()]
    # edges = [{"source": source, "target": target} for source, target in G.edges()]

    # # Dữ liệu trả về dưới dạng JSON
    # graph_data = {
    #     "nodes": nodes,
    #     "edges": edges
    # }

    # # Trả về JSON dưới dạng chuỗi
    # return graph_data

# Hàm kiểm tra IP hợp lệ
def is_ip_only(ip):
    return isinstance(ip, str) and len(ip.split('.')) == 4

# Hàm xác định server dựa trên địa chỉ IP


def identify_server(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)  # Kiểm tra định dạng IP
    except ValueError:
        return 'Invalid IP address'
    
    # Google DNS
    if ip in ['8.8.8.8', '8.8.4.4']:
        return 'Google DNS'
    # Cloudflare DNS
    elif ip in ['1.1.1.1', '1.0.0.1']:
        return 'Cloudflare DNS'
    
    # Kiểm tra từng dải IP
    server_ip_ranges = {
    'Google DNS': ['8.8.8.8', '8.8.4.4'],
    'Cloudflare DNS': ['1.1.1.1', '1.0.0.1'],
    'Google': [
        '8.8.4.0/24', '8.8.8.0/24', '8.34.208.0/20', '8.35.192.0/20', '23.236.48.0/20', 
        '23.251.128.0/19', '34.0.0.0/15', '34.2.0.0/16', '34.3.0.0/23', '34.3.3.0/24', 
        '34.3.4.0/24', '34.3.8.0/21', '34.3.16.0/20', '34.3.32.0/19', '34.3.64.0/18', 
        '34.4.0.0/14', '34.8.0.0/13', '34.32.0.0/11', '34.64.0.0/10', '34.128.0.0/10', 
        '35.184.0.0/13', '35.192.0.0/14', '35.196.0.0/15', '35.198.0.0/16', 
        '35.199.0.0/17', '35.199.128.0/18', '35.200.0.0/13', '35.208.0.0/12', 
        '35.224.0.0/12', '35.240.0.0/13', '57.140.192.0/18', '64.15.112.0/20', 
        '64.233.160.0/19', '66.22.228.0/23', '66.102.0.0/20', '66.249.64.0/19', 
        '70.32.128.0/19', '72.14.192.0/18', '74.125.0.0/16', '104.154.0.0/15', 
        '104.196.0.0/14', '104.237.160.0/19', '107.167.160.0/19', '107.178.192.0/18', 
        '108.59.80.0/20', '108.170.192.0/18', '108.177.0.0/17', '130.211.0.0/16', 
        '136.22.160.0/20', '136.22.176.0/21', '136.22.184.0/23', '136.22.186.0/24', 
        '136.124.0.0/15', '142.250.0.0/15', '146.148.0.0/17', '152.65.208.0/22', 
        '152.65.214.0/23', '152.65.218.0/23', '152.65.222.0/23', '152.65.224.0/19', 
        '162.120.128.0/17', '162.216.148.0/22', '162.222.176.0/21', '172.110.32.0/21', 
        '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16', '173.255.112.0/20', 
        '192.158.28.0/22', '192.178.0.0/15', '193.186.4.0/24', '199.36.154.0/23', 
        '199.36.156.0/24', '199.192.112.0/22', '199.223.232.0/21', '207.223.160.0/20', 
        '208.65.152.0/22', '208.68.108.0/22', '208.81.188.0/22', '208.117.224.0/19', 
        '209.85.128.0/17', '216.58.192.0/19', '216.73.80.0/20', '216.239.32.0/19',
        '35.190.0.0/17', '35.191.0.0/16', '130.211.0.0/16', '108.177.8.0/24'  # New IP ranges
    ],  
    'Amazon': [
        '13.0.0.0/8', '54.239.0.0/16', '52.94.0.0/16', '18.0.0.0/8', 
        '52.95.0.0/16', '52.92.0.0/15', '52.94.0.0/15', '18.208.0.0/13', 
        '54.244.0.0/16', '52.32.0.0/11', '99.82.0.0/16', '52.119.0.0/16'  # New IP ranges
    ],
    'AWS': [
        '52.0.0.0/8', '3.0.0.0/8', '18.0.0.0/8', 
        '3.128.0.0/9', '52.119.0.0/16', '99.83.0.0/16'  # New AWS IP ranges
    ],  
    'Apple': ['17.0.0.0/8'],  
    'Ubuntu': ['91.189.0.0/16','54.171.0.0/16'],  
    'GitHub': ['185.199.0.0/16', '140.82.112.0/20'],  
    'Microsoft': [
        '40.76.0.0/14', '104.215.0.0/16', '13.104.0.0/14', '13.107.0.0/16',
        '52.244.0.0/16', '13.68.0.0/16', '52.229.0.0/16', '40.90.0.0/16'  # New Microsoft IP ranges
    ],  
    'Facebook': [
        '31.13.24.0/21', '66.220.144.0/20', '69.63.176.0/20', 
        '157.240.0.0/16', '129.134.0.0/16', '204.15.20.0/22'  # New Facebook IP ranges
    ],  
    'Oracle': [
        '137.254.0.0/16', '156.151.0.0/16', 
        '138.1.0.0/16', '148.64.0.0/16', '152.67.0.0/16'  # New Oracle IP ranges
    ],  
    'Cloudflare': [
        '104.16.0.0/12', '172.64.0.0/13', '198.41.128.0/17', '190.93.240.0/20', 
        '141.101.64.0/18', '188.114.96.0/20', '197.234.240.0/22'  # New Cloudflare ranges
    ],
    'Nemox':
    ['83.137.0.0/16'],
    'Stone':
    ['211.216.0.0/16'],
    'Linux': ['223.130.0.0/16'],
    }
    
    # Kiểm tra từng server với dải IP tương ứng
    for server, ip_ranges in server_ip_ranges.items():
        for ip_range in ip_ranges:
            if ip_obj in ipaddress.ip_network(ip_range):
                return server
    
    return 'Unknown Server'
# M2
# Hàm generate_network_graph
def generate_network_graph(df):
    # Lọc các cặp IP từ DataFrame
    filtered_df = df[df['Source IP'].apply(is_ip_only) & df['Destination IP'].apply(is_ip_only)]
    
    # Tạo cặp IP với thông tin server và label
    ip_pairs = filtered_df[['Source IP', 'Destination IP', 'Label']].drop_duplicates()

    # Tạo danh sách netgraph, chỉ giữ các kết nối với Source và Destination IP không phải là 'Unknown Server'
    # Tạo danh sách netgraph, loại bỏ các kết nối có nhãn 'Normaly' và liên quan tới các IP public
    netgraph = [{"source": row['Source IP'], "target": row['Destination IP'], "label": row['Label']} 
                for _, row in ip_pairs.iterrows() 
                if not ((row['Label'] == 'Normal' and (identify_server(row['Source IP']) != 'Unknown Server' or identify_server(row['Destination IP']) != 'Unknown Server'))
                        and ((row['Label'] == 'Normal' and (is_public_ip(row['Source IP']) != 'Unknown Server' and is_public_ip(row['Destination IP']) != 'Unknown Server'))))]

    # Tạo danh sách nettable với source, target, server, label, chỉ giữ các server hợp lệ cho cả Source và Destination
    nettable = [{"source": row['Source IP'], 
                 "target": row['Destination IP'],
                 "nameserver": identify_server(row['Source IP']) if is_public_ip(row['Source IP']) 
                 else identify_server(row['Destination IP']),
                 "label": row['Label']} 
                for _, row in ip_pairs.iterrows() 
                if (is_public_ip(row['Source IP']) and not is_public_ip(row['Destination IP'] )) or
                   (not is_public_ip(row['Source IP']) and is_public_ip(row['Destination IP']))]

    # Dữ liệu trả về
    result = {
        "netgraph": netgraph,
        "nettable": nettable
    }

    return result



    

# Phân tích hướng truyền dữ liệu giữa các IP và trả về DataFrame với thông tin chi tiết.
def classify_ip(ip):
    """Phân loại địa chỉ IP là Private hoặc Public."""
    if ip.startswith('10.') or ip.startswith('192.168.'):
        return 'Private'
    else:
        return 'Public'

def analyze_ip_flows(df):
    # Áp dụng phân loại cho các cột 'Source IP' và 'Destination IP'
    df['Source IP Class'] = df['Source IP'].apply(classify_ip)
    df['Destination IP Class'] = df['Destination IP'].apply(classify_ip)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    # Nhóm dữ liệu theo giờ
    df['Hour'] = df['Timestamp'].dt.floor('h')

    # Tạo danh sách kết quả với thông tin cần thiết
    nodes = set()
    edges = []

    for hour, group in df.groupby('Hour'):
        for index, row in group.iterrows():
            if row['Tot Fwd Pkts'] > 0 and row['Tot Bwd Pkts'] > 0:
                direction = 2
                direction_type = 'upward + backward'
            elif row['Tot Fwd Pkts'] > 0:
                direction = 1
                direction_type = 'upward'
            elif row['Tot Bwd Pkts'] > 0:
                direction = 1
                direction_type = 'backward'
            else:
                direction = 0
                direction_type = 'none'
            
            # Thêm Source IP và Destination IP vào tập hợp nodes
            nodes.add(row['Source IP'])
            nodes.add(row['Destination IP'])
            
            # Tạo cạnh cho Flow giữa Source IP và Destination IP
            edge = {
                'source': row['Source IP'],
                'target': row['Destination IP'],
                'direction': direction,
                'direction_type': direction_type,
                'flow': f"{row['Source IP']} -> {row['Destination IP']}" if direction_type == 'upward' else 
                        (f"{row['Destination IP']} -> {row['Source IP']}" if direction_type == 'backward' else 
                        f"{row['Source IP']} <-> {row['Destination IP']}")
            }
            edges.append(edge)

    # Chuyển đổi nodes từ set sang danh sách các dictionary
    nodes = [{"id": node} for node in nodes]

    # Dữ liệu trả về dưới dạng JSON
    graph_data = {
        "nodes": nodes,
        "edges": edges
    }

    return graph_data

"""Time analysis"""
def num_event(df):
    # Giả sử hàm này đếm số lượng hàng trong DataFrame df
    return df.shape[0]
    
# tab2/M1/ Vẽ biểu đồ đường thể hiện tổng số lượng event traffic theo thời gian., d, h, min
def plot_traffic_trend(df, time_sign='h', start_time=None, end_time=None):
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Lọc dữ liệu dựa trên khoảng thời gian start_time và end_time
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]

    # Resample dữ liệu dựa trên time_sign ('h' cho theo giờ, 'd' cho theo ngày)
    traffic_counts = df_filter.resample(time_sign, on='Timestamp').size()
    
    # Chuẩn bị dữ liệu để trả về
    result = [{'name': ts.strftime('%Y/%m/%d' if time_sign == 'D' else '%Y/%m/%d %H:%M'), 'pv': count} 
              for ts, count in traffic_counts.items()]
    
    return result


# Vẽ biểu đồ đường thể hiện sự thay đổi của tổng đại lương (IP_Bytes, duration) dạng số theo thời gian.
def plot_time_sum_column_trend(df, column, time_sign='h', start_time=None, end_time=None):
    # Lọc dữ liệu trong khoảng thời gian nhất định nếu có

    df = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Nhóm dữ liệu theo ngày, giờ, phút và tính tổng số Totlen Pkts
    time_column = df.resample(time_sign, on='Timestamp')[column].sum()
    
    # Chuẩn bị dữ liệu để trả về
    result = [{'name': ts.strftime('%Y/%m/%d' if time_sign == 'd' else '%Y/%m/%d %H'), 'pv': value} 
              for ts, value in time_column.items()]
     # Chuyển đổi kết quả thành JSON
    json_compatible_result = jsonable_encoder(result)

    # Trả về JSON response
    return json_compatible_result

# tab 3/m1
def count_artifacts(df):
    """
    Đếm số lượng IP nguồn khác nhau, IP đích khác nhau và tổng số IP khác nhau tham gia vào mạng.
    Tính range: giá trị nhỏ nhất (min) và lớn nhất (max) của Packet size
    - Tuple chứa số lượng IP nguồn khác nhau, IP đích khác nhau và tổng số IP khác nhau.
    """
    # Đếm số lượng IP nguồn khác nhau
    unique_source_ips = df['Source IP'].nunique()

    # Đếm số lượng IP đích khác nhau
    unique_destination_ips = df['Destination IP'].nunique()

    # Đếm tổng số IP khác nhau tham gia vào mạng
    all_ips = pd.concat([df['Source IP'], df['Destination IP']]).unique()
    total_unique_ips = len(all_ips)
    df['Totlen Pkts'] = pd.to_numeric(df['Totlen Pkts'], errors='coerce').astype('Int64')
    min_packet_size = int(df['Totlen Pkts'].min())
    max_packet_size = int(df['Totlen Pkts'].max())
    mean_packet_size = int(df['Totlen Pkts'].mean())
    # Trả về mảng chứa các đối tượng với các thuộc tính
    result = {
        'unique_source_ips': int(unique_source_ips),
        'unique_destination_ips': int(unique_destination_ips),
        'total_unique_ips': int(total_unique_ips),
        'min_packet_size': min_packet_size,
        'max_packet_size': max_packet_size,
        'mean_packet_size': mean_packet_size
    }

    return result

# Tab3/M2 Hàm để vẽ biểu đồ phân phối cho các cột số trong DataFrame return json
def plot_totlen_pkts_distribution(df, num_bins=8, start_time=None, end_time=None):
    """
    Tạo các bin từ dữ liệu cột và đếm số lần xuất hiện trong mỗi bin theo khoảng thời gian    
    Returns:
    str: Chuỗi JSON chứa danh sách các bin và số lần xuất hiện trong mỗi bin.
    """
    # Convert start_time and end_time to Timestamps if they are not already
    start_time = pd.to_datetime(start_time)
    end_time = pd.to_datetime(end_time)
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    mask = (df['Timestamp'] >= pd.to_datetime(start_time)) & (df['Timestamp'] <= pd.to_datetime(end_time))
    filtered_data = df.loc[mask, "Totlen Pkts"]
    
    # Xác định giá trị min và max từ dữ liệu đã lọc
    min_value = int(filtered_data.min())
    max_value = int(filtered_data.max())

    # Tạo các bin với khoảng giá trị dựa trên số lượng bin
    bins = np.linspace(min_value, max_value, num_bins + 1)
    bin_counts = np.histogram(filtered_data, bins=bins)[0]

    # Tạo cấu trúc dữ liệu dạng JSON
    data = []

    for i in range(num_bins):
        # Tạo chuỗi name có dạng "min-max"
        bin_name = f"{int(bins[i])}-{int(bins[i+1])}"
        data.append({
            "name": bin_name,
            "uv": int(bin_counts[i])
        })

    return data


 # Vẽ biểu đồ barchart thể hiện phân phối của Source / Destination address.
def plot_address_distribution_barchart(df, start_time, end_time, column='Source IP'):
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    # Bước 1: Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= pd.to_datetime(start_time)) & (df['Timestamp'] <= pd.to_datetime(end_time))]

    # Bước 2: Tính tần suất của từng giá trị trong cột
    source_distribution = df_filter[column].value_counts()

    # Bước 3: Tạo cấu trúc dữ liệu dạng JSON
    data = []

    for name, count in source_distribution.items():
        data.append({
            "name": name,
            "uv": count
        })

    # Chuyển đổi thành chuỗi JSON
    # json_data = json.dumps(data, indent=4)
    return data

# tab 3_M5
# Biểu đồ cột cặp IP source>destination theo total length
def plot_top_ip_pairs_by_frame_len(df, start_time, end_time):
    """
    Lọc dữ liệu theo khoảng thời gian, nhóm theo cặp Source IP và Destination IP, tính tổng `Totlen Pkts`,
    và trả về dữ liệu dưới dạng JSON với `name` là cặp IP và `uv` là tổng `Totlen Pkts`.
    
    Parameters:
    df (pd.DataFrame): DataFrame chứa dữ liệu.
    top (int): Số lượng cặp IP hàng đầu để trả về.
    start_time (datetime): Thời gian bắt đầu để lọc dữ liệu.
    end_time (datetime): Thời gian kết thúc để lọc dữ liệu.
    
    Returns:
    str: Chuỗi JSON chứa các cặp IP và tổng `Totlen Pkts`.
    """
    # Bước 1: Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]

    # Bước 2: Nhóm dữ liệu theo cặp Source IP và Destination IP và tính tổng Totlen Pkts
    grouped_data = df_filter.groupby(["Source IP", "Destination IP"])["Totlen Pkts"].sum().sort_values(ascending=False)

    # Bước 3: Chuyển đổi Series thành DataFrame
    sorted_df = grouped_data.reset_index()

    # Bước 4: Tạo cột mới kết hợp Source IP và Destination IP
    sorted_df["Ip_pair"] = sorted_df["Source IP"] + " -> " + sorted_df["Destination IP"]

    # Bước 6: Tạo cấu trúc dữ liệu JSON
    data = []

    for _, row in sorted_df.iterrows():
        data.append({
            "name": row["Ip_pair"],
            "uv": row["Totlen Pkts"]
        })

    # Chuyển đổi thành chuỗi JSON
    return data


"""Tab 4"""

# M1: Thông tin chung
def summarize_column(df):
    # Loại bỏ các giá trị NaN trong cột (nếu có)
    df = df.dropna(subset=["Time_Delta"])
    df["Time_Delta"] = pd.to_timedelta(df["Time_Delta"]).dt.total_seconds()
    # Tính toán các thống kê cơ bản
    average_duration = df["Time_Delta"].mean()  # Giá trị trung bình (tính bằng giây)
    max_duration = df["Time_Delta"].max()  # Giá trị lớn nhất (tính bằng giây)
    min_duration = df["Time_Delta"].min()  # Giá trị nhỏ nhất (tính bằng giây)

    # Kiểm tra nếu min_duration nhỏ hơn 0 thì đặt lại thành 0
    if min_duration < 0:
        min_duration = 0.0

    # Đếm số lượng giá trị duy nhất trong các cột khác
    num_unique_source_ports = df['Source Port'].nunique()
    num_unique_dst_ports = df['Destination Port'].nunique()
    num_unique_protocol = df['Protocol'].nunique()
    num_unique_application_protocol = df[df['Application Protocol'] != 'Non-Application']['Application Protocol'].nunique()

    # Tạo cấu trúc dữ liệu JSON
    summary = {
        "average_duration": float(round(average_duration, 3)),
        "max_duration": float(round(max_duration, 3)),
        "min_duration": float(round(min_duration, 3)),
        "num_unique_source_ports": int(num_unique_source_ports),
        "num_unique_dst_ports": int(num_unique_dst_ports),
        "num_unique_protocol": int(num_unique_protocol),
        "num_unique_application_protocol": int(num_unique_application_protocol)
    }
    return summary

#Biểu đồ tròn distribution của protocol
def plot_protocol_pie_chart(df, start_time=None, end_time=None):
    # Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Đếm số lượng các giá trị xuất hiện trong cột và lấy top giá trị xuất hiện nhiều nhất
    value_counts = df_filter["Protocol"].value_counts()
    
    # Tạo cấu trúc dữ liệu JSON
    data = []

    for name, value in value_counts.items():
        data.append({
            "name": name,
            "value": value
        })

    return data

# M3,4: Biểu đồ phân bố theo cột không phải dạng số theo top
def plot_column_distribution_barchart(df, start_time=None, end_time=None, column='Source Port'):
    
    # Bước 1: Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]

    # Bước 2: Tính tần suất của từng giá trị trong cột và lấy top giá trị xuất hiện nhiều nhất
    source_distribution = df_filter[column].value_counts()

    # Tạo cấu trúc dữ liệu JSON
    data = []

    for name, uv in source_distribution.items():
        data.append({
            "name": name,
            "uv": uv
        })

    return data
# tab4/M5
def plot_pkts_traffic_trend(df, column, time_sign='h', start_time=None, end_time=None):
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    # start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else df['Timestamp'].min()
    # end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else df['Timestamp'].max()
    if start_time is None:
        start_time = df['Timestamp'].min()
    if end_time is None:
        end_time = df['Timestamp'].max()
    # Lọc dữ liệu dựa trên khoảng thời gian start_time và end_time
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Resample dữ liệu dựa trên time_sign ('h' cho theo giờ, 'd' cho theo ngày)
    traffic_bytes = df_filter.resample(time_sign, on='Timestamp')[column].sum()
    
    # Chuẩn bị dữ liệu để trả về
    result = [{'name': ts.strftime('%Y-%m-%d' if time_sign == 'D' else '%Y-%m-%d %H:%M'), 'pv': count} 
              for ts, count in traffic_bytes.items()]
    
    return result
# bảng hiện thông tin chi tiết
def detail_log(df):
    return df

# Tab alert
def alert_general(df):
        # Lọc các sự kiện có Label = 'Anomaly'
    anomaly_df = df[df['Label'] == 'Anomaly']
        # Kiểm tra nếu anomaly_df là mảng rỗng
    if anomaly_df.empty:
        return []
    # Bước 1: Đếm số lượng sự kiện (alerts) có Label = 'Anomaly'
    alert_count = anomaly_df.shape[0]  # Số hàng có nhãn 'Anomaly'
    # Bước 2: Lấy tất cả IP từ cột 'Source IP' và 'Destination IP' và đếm số lượng IP duy nhất
    all_ips = pd.concat([anomaly_df['Source IP'], anomaly_df['Destination IP']]).unique()
    unique_ip_count = len(all_ips)
    # Trả về kết quả dưới dạng mảng
    return [str(alert_count),str(unique_ip_count)]

def bar_alert_categories(df):
    # Đếm số lượng theo nhãn Label
    label_counts = df['Label'].value_counts()
    # print (f"label_counts:{label_counts}")
    # Chuyển đổi thành dạng danh sách với cặp name-uv
    result = [{"name": label, "uv": str(count)} for label, count in label_counts.items()]
    return result

def bar_alert_generating_hosts(df):
    # Lọc các sự kiện có Label = 'Anomaly'
    anomaly_df = df[df['Label'] == 'Anomaly']
    
    # Kiểm tra nếu anomaly_df là mảng rỗng
    if anomaly_df.empty:
        return []
    
    # Lấy tất cả IP từ cột 'Source IP' và 'Destination IP'
    source_ips = anomaly_df['Source IP']
    destination_ips = anomaly_df['Destination IP']
    
    # Tạo một DataFrame chứa cả 'Source IP' và 'Destination IP' để dễ dàng tính toán
    ip_df = pd.concat([source_ips, destination_ips], axis=0)
    
    # Lọc ra các IP public
    public_ips = ip_df[ip_df.apply(is_public_ip)]
    
    # Đếm số sự kiện (alerts) liên quan đến mỗi IP public
    ip_counts = public_ips.value_counts()
    
    # Chuyển đổi thành danh sách các từ điển có định dạng như bạn muốn
    result_list = [{'name': ip,'uv': str(count)} for ip,count in ip_counts.items()]
    
    return result_list

def bar_alert_receiving_hosts(df):
    # Lọc các sự kiện có Label = 'Anomaly'
    anomaly_df = df[df['Label'] == 'Anomaly']
    
    # Kiểm tra nếu anomaly_df là mảng rỗng
    if anomaly_df.empty:
        return []
    
    # Lấy tất cả IP từ cột 'Source IP' và 'Destination IP'
    source_ips = anomaly_df['Source IP']
    destination_ips = anomaly_df['Destination IP']
    
    # Tạo một DataFrame chứa cả 'Source IP' và 'Destination IP' để dễ dàng tính toán
    ip_df = pd.concat([source_ips, destination_ips], axis=0)
    
    # Lọc ra các IP public
    private_ips = ip_df[ip_df.apply(lambda ip: not is_public_ip(ip))]
    
    # Đếm số sự kiện (alerts) liên quan đến mỗi IP public
    ip_counts = private_ips.value_counts()
    
    # Chuyển đổi thành danh sách các từ điển có định dạng như bạn muốn
    result_list = [{'name': ip,'uv': str(count)} for ip,count  in ip_counts.items()]
    
    return result_list

def pie_alert_generating_protocol(df):
    # Chuyển cột 'Application Protocol' thành chuỗi
    df['Application Protocol'] = df['Application Protocol'].fillna('').astype(str)
    anomaly_df = df[df['Label'] == 'Anomaly']
        # Kiểm tra nếu anomaly_df là mảng rỗng
    if anomaly_df.empty:
        return [] 
    # Lấy tất cả IP từ cột 'Source IP' và 'Destination IP'
    alert_protocol = anomaly_df['Application Protocol'].value_counts()
    alert_protocol = [{"name": label, "uv": str(count)} for label, count in alert_protocol.items()]
    return alert_protocol
    


