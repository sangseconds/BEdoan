import nest_asyncio
import pyshark
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

# Cho phép nhiều event loop chạy đồng thời
import pandas as pd
from datetime import datetime
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


df = pd.DataFrame()
def process_csv(filepcap: str):
    # Đọc dữ liệu từ file CSV đầu vào
    global df 
    df1 = pd.read_csv(filepcap)

    # Xử lý các cột cần thiết
    # df = pd.DataFrame()
    df['Flow ID'] = df1['Flow ID']
    df['Timestamp'] = df1['Timestamp']
    df['Source IP'] = df1['Src IP']
    df['Destination IP'] = df1['Dst IP']
    df['Source Port'] = df1['Src Port']
    df['Destination Port'] = df1['Dst Port']

    # Chuyển đổi múi giờ cho cột 'Timestamp'
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
    # Đặt tên file CSV mới và lưu file
    filecsv = filepcap.replace('.csv', '_processed.csv')
    df.to_csv(filecsv, index=False)
    return df


# Lọc bỏ các dòng có địa chỉ MAC trong `source_ip` hoặc `destination_ip`
# hàm này ít dùng do cơ bản là Ip rồi
def is_ip_only(ip):
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
def generate_network_graph(df):
    
    
    filtered_df = df[df['Source IP'].apply(is_ip_only) & df['Destination IP'].apply(is_ip_only)]
    ip_pairs =filtered_df[['Source IP', 'Destination IP']].drop_duplicates()
    ip_pairs = set(ip_pairs.itertuples(index=False, name=None))

    # Tạo một đồ thị
    G = nx.Graph()

    # Thêm các cạnh (edge) vào đồ thị từ các cặp IP
    G.add_edges_from(ip_pairs)

    # Tạo danh sách nodes và edges để trả về
    nodes = [{"id": node} for node in G.nodes()]
    edges = [{"source": source, "target": target} for source, target in G.edges()]

    # Dữ liệu trả về dưới dạng JSON
    graph_data = {
        "nodes": nodes,
        "edges": edges
    }

    # Trả về JSON dưới dạng chuỗi
    return graph_data


    

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
def plot_address_distribution_barchart(df, top, start_time, end_time, column='Source IP'):
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    # Bước 1: Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= pd.to_datetime(start_time)) & (df['Timestamp'] <= pd.to_datetime(end_time))]

    # Bước 2: Tính tần suất của từng giá trị trong cột
    source_distribution = df_filter[column].value_counts().head(top)

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
def plot_top_ip_pairs_by_frame_len(df, top, start_time, end_time):
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

    # Bước 5: Chọn top N cặp IP hàng đầu
    top_sorted_df = sorted_df.head(top)

    # Bước 6: Tạo cấu trúc dữ liệu JSON
    data = []

    for _, row in top_sorted_df.iterrows():
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
def plot_column_distribution_barchart(df, top, start_time=None, end_time=None, column='Source Port'):
    
    # Bước 1: Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]

    # Bước 2: Tính tần suất của từng giá trị trong cột và lấy top giá trị xuất hiện nhiều nhất
    source_distribution = df_filter[column].value_counts().head(top)

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

