from logparser.Drain import LogParser
import pandas as pd
import matplotlib.pyplot as plt
import os

# input_dir = './example/' # The input directory of log file
# log_file="dnsmasq.log"
def process_log_files_dns(input_dir: str, log_file: str, year: int = 2022):
    output_dir = './dns'
    
    # Kiểm tra và tạo thư mục đầu ra nếu chưa tồn tại
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Định nghĩa định dạng log và regex tiền xử lý
    log_format = '<Month> <Day> <Time> <Process>: <Content>'
    regex = [r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)']  # Proctitle field
    st = 0.5  # Similarity threshold
    depth = 4  # Depth of all leaf nodes

    # Tạo đối tượng LogParser và xử lý log
    parser = LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex)
    parser.parse(log_file)

    # Đường dẫn tới file kết quả
    structured_log_path = os.path.join(output_dir, f"{log_file}_structured.csv")
    templates_log_path = os.path.join(output_dir, f"{log_file}_templates.csv")

    # Đọc và xử lý dữ liệu từ file structured log
    structured_log_df = pd.read_csv(structured_log_path)

    # Thêm năm mặc định và chuyển đổi sang định dạng datetime
    structured_log_df['Timestamp'] = pd.to_datetime(
        f'{year} ' + structured_log_df['Month'] + ' ' + structured_log_df['Day'].astype(str) + ' ' + structured_log_df['Time'],
        format='%Y %b %d %H:%M:%S'
    )
    structured_log_df['Timestamp'] = structured_log_df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M:%S')
    structured_log_df = structured_log_df.drop(columns=['Month', 'Day', 'Time'])


    # Ghi lại file structured log sau khi xử lý
    structured_log_df.to_csv(structured_log_path, index=False)

    # Đọc dữ liệu từ file templates log
    templates_log_df = pd.read_csv(templates_log_path)

    return structured_log_df, templates_log_df

# Template của sự kiện dạng biểu đồ
def plot_event_distribution(df, output_file='result.png'):
    # Tạo bảng phân bố các sự kiện
    event_distribution = df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    # Vẽ biểu đồ
    plt.figure(figsize=(10, 6))
    event_distribution.set_index('EventTemplate')['Occurrences'].plot(kind='bar')
    plt.title('Distribution of DNS Event Types (Filtered by Time)')
    plt.xlabel('Event Template')
    plt.ylabel('Occurrences')
    plt.xticks(rotation=90)
    plt.grid(True)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
# output_file = plot_event_distribution(templates_log_df, output_file='result.png')


# Số lượng sự kiện theo thời gian
def plot_event_counts(df, time_unit='D', title='Number of DNS Events', xlabel='Time', ylabel='Number of Events', start_time=None, end_time=None, output_file='result.png'):
    # Lọc dữ liệu theo khoảng thời gian
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Đếm số lượng sự kiện theo đơn vị thời gian
    event_counts = df_filter.resample(time_unit, on='Timestamp').size()
    
    # Vẽ biểu đồ
    plt.figure(figsize=(10, 6))
    event_counts.plot(kind='line')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
    
    # Trả về tên file đã lưu
    return output_file
# # hàm tính số lượng sự kiện theo ngày
# output_file = plot_event_counts(structured_log_df, time_unit='D', title='Total Number of DNS Events per Day', xlabel='Date', start_time=start_time, end_time=end_time, output_file='result.png')
# # Sử dụng hàm để tính số lượng sự kiện theo giờ
# output_file = plot_event_counts(structured_log_df, time_unit='h', title='Total Number of DNS Events per Day', xlabel='Date', start_time=start_time, end_time=end_time, output_file='result.png')

#M3
# Phân bố các sự kiện theo IP nguồn
def plot_ip_distribution(df, start_time=None, end_time=None):
    start_time = pd.to_datetime(start_time)
    end_time = pd.to_datetime(end_time)
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    # Lọc dữ liệu theo khoảng thời gian
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()
    # print(df_filter['Timestamp'])
    # Trích xuất địa chỉ IP từ cột Content
    df_filter['Source IP'] = df_filter['Content'].str.extract(r'(\d+\.\d+\.\d+\.\d+)')
    # print(df_filter['Source IP'])

    # Kiểm tra xem có địa chỉ IP nào được trích xuất không
    if df_filter['Source IP'].dropna().empty:
        return {"message": "No valid IP addresses found in the data."}

    # Đếm số lần xuất hiện của các địa chỉ IP
    ip_distribution = df_filter['Source IP'].value_counts().reset_index()
    ip_distribution.columns = ['name', 'uv']

    # Trả về dữ liệu dưới dạng JSON
    result = ip_distribution.to_dict(orient='records')
    return result
# output_file = plot_ip_distribution(structured_log_df, start_time=start_time, end_time=end_time, output_file='result.png')       
  
    
# vẽ biểu đồ phân bố các loại yêu cầu DNS.
# Phân bố các loại yêu cầu DNS
def plot_dns_query_distribution(df, start_time=None, end_time=None):
    start_time = pd.to_datetime(start_time)
    end_time = pd.to_datetime(end_time)
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    # Lọc dữ liệu theo khoảng thời gian
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()
    
    # Thêm cột Query Type
    df_filter['Query Type'] = df_filter['Content'].str.extract(r'query\[(\w+)\]')

    # Kiểm tra các giá trị trong cột Query Type
    query_counts = df_filter['Query Type'].value_counts().reset_index()
    query_counts.columns = ['name', 'uv']

    # Trả về dữ liệu dưới dạng JSON
    result = query_counts.to_dict(orient='records')
    return result
# output_file = plot_dns_query_distribution(structured_log_df,start_time=start_time, end_time=end_time, output_file='result.png')


# Sự thay đổi trong các mẫu sự kiện theo thời gian
def plot_event_templates_over_time(df, start_time=None, end_time=None, output_file='result.png'):
    start_time = pd.to_datetime(start_time)
    end_time = pd.to_datetime(end_time)
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    plt.figure(figsize=(10, 6))
    df_filter.groupby([df_filter['Timestamp'].dt.date, 'EventTemplate']).size().unstack().plot(kind='line', stacked=False, figsize=(12, 8))
    plt.title('Change in Event Templates Over Time')
    plt.xlabel('Date')
    plt.ylabel('Number of Events')
    plt.legend(loc='upper right', bbox_to_anchor=(1.2, 1))
    plt.grid(True)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
    # Trả về tên file đã lưu
    return output_file
# output_file = plot_event_templates_over_time(structured_log_df, start_time=start_time, end_time=end_time, output_file='result.png')

# bảng hiện thông tin chi tiết
def detail_log(df):
    return df[['LineId','Timestamp','Process','Content','EventTemplate']]

# Alert
# Tab alert
def log_alert_general(df):
    sum_count = df.shape[0]  # Số hàng có nhãn 'Anomaly'
    # Trả về kết quả dưới dạng mảng
    # Chuyển cột 'Anomaly' thành chuỗi
    # df['Anomaly'] = df['Anomaly'].fillna('').astype(str)
    # Lọc các sự kiện có Label = 'Anomaly'
    anomaly_df = df[df['Anomaly'] == 'Anomaly']
        # Kiểm tra nếu anomaly_df là mảng rỗng
    if anomaly_df.empty:
        alert_count = 0
    # Bước 1: Đếm số lượng sự kiện (alerts) có Label = 'Anomaly'
    alert_count = anomaly_df.shape[0]  # Số hàng có nhãn 'Anomaly'
    # Trả về kết quả dưới dạng mảng
    return [str(sum_count), str(alert_count)]

def log_bar_alert_categories(df):
    # Chuyển cột 'Anomaly' thành chuỗi
    # Đếm số lượng theo nhãn Label
    label_counts = df['Anomaly'].value_counts()
    # Chuyển đổi thành dạng danh sách với cặp name-uv
    result = [{"name": label, "uv": str(count)} for label, count in label_counts.items()]
    return result