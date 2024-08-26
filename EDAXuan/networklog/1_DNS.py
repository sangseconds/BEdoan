from logparser.Drain import LogParser
import pandas as pd
import matplotlib.pyplot as plt

input_dir = './example/' # The input directory of log file
output_dir = './dns'  # The output directory of parsing results
log_file = 'dnsmasq.log'  # The input log file name
log_format = 'type=<Type> msg=audit(<Timestamp>): <Content>'
 # Define log format to split message fields
# Regular expression list for optional preprocessing (default: [])
# Danh sách biểu thức chính quy cho tiền xử lý tùy chọn (mặc định: [])
regex = [
    r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)'  # I  # Proctitle field
]
st = 0.5  # Similarity threshold
depth = 4  # Depth of all leaf nodes

parser = LogParser(log_format, indir=input_dir, outdir=output_dir,  depth=depth, st=st, rex=regex)
parser.parse(log_file)

structured_log_df = pd.read_csv('./dns/dnsmasq.log_structured.csv')
templates_log_df = pd.read_csv('./dns/dnsmasq.log_templates.csv')

# Thêm năm mặc định là 2022 vào trước khi chuyển đổi dữ liệu thành định dạng datetime
structured_log_df['Timestamp'] = pd.to_datetime(
    '2022 ' + structured_log_df['Month'] + ' ' + structured_log_df['Day'].astype(str) + ' ' + structured_log_df['Time'],
    format='%Y %b %d %H:%M:%S'
)

# test
start_time = structured_log_df['Timestamp'].iloc[0]
end_time = structured_log_df['Timestamp'].iloc[-1]
print(start_time)
print(end_time)
# Hai chuỗi thời gian
# start_time = '2022-01-21 12:21:42'
# end_time = '2022-01-24 05:56:31'

# # Chuyển đổi các chuỗi thành kiểu datetime
# start_time = pd.to_datetime(start_time, format='%Y-%m-%d %H:%M:%S')
# end_time = pd.to_datetime(end_time, format='%Y-%m-%d %H:%M:%S')

# template dạng bảng
# tạo bảng và vẽ biểu đồ phân bố các loại sự kiện DNS chưa lọc theo thời gian
def table_event_distribution(df):

    event_distribution = df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    return event_distribution
template_df = table_event_distribution(templates_log_df)

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

# Phân bố các sự kiện theo IP nguồn
def plot_ip_distribution(df, start_time=None, end_time=None, output_file='result.png'):

    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()

    # Bước 2: Trích xuất địa chỉ IP từ cột Content
    df_filter['Source IP'] = df_filter['Content'].str.extract(r'(\d+\.\d+\.\d+\.\d+)')

    # Kiểm tra xem có địa chỉ IP nào được trích xuất không
    if not df_filter['Source IP'].dropna().empty:
        plt.figure(figsize=(10, 6))
        df_filter['Source IP'].value_counts().head(10).plot(kind='bar')
        plt.title('Top 10 Source IPs by Number of DNS Events')
        plt.xlabel('Source IP')
        plt.ylabel('Number of Events')
        plt.xticks(rotation=45)
        plt.grid(True)
        # Lưu biểu đồ thành file ảnh
        plt.savefig(output_file)
        plt.show()
    else:
        print("No valid IP addresses found in the data.")
    # Trả về tên file đã lưu
    return output_file
# output_file = plot_ip_distribution(structured_log_df, start_time=start_time, end_time=end_time, output_file='result.png')       
  
    
# vẽ biểu đồ phân bố các loại yêu cầu DNS.
def plot_dns_query_distribution(df,start_time=None, end_time=None, output_file='result.png'):
    
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()
    # Thêm cột Query Type
    df_filter['Query Type'] = df_filter['Content'].str.extract(r'query\[(\w+)\]')

    # Kiểm tra các giá trị trong cột Query Type
    query_counts = df_filter['Query Type'].value_counts()
    print(query_counts)

    # Vẽ biểu đồ các loại yêu cầu DNS phổ biến
    plt.figure(figsize=(10, 6))
    query_counts.plot(kind='bar')
    plt.title('Distribution of DNS Query Types')
    plt.xlabel('Query Type')
    plt.ylabel('Number of Queries')
    plt.xticks(rotation=45)
    plt.grid(True)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
    # Trả về tên file đã lưu
    return output_file
# output_file = plot_dns_query_distribution(structured_log_df,start_time=start_time, end_time=end_time, output_file='result.png')


# Sự thay đổi trong các mẫu sự kiện theo thời gian
def plot_event_templates_over_time(df, start_time=None, end_time=None, output_file='result.png'):
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

# template dạng bảng
# template_df = table_event_distribution(templates_log_df)
# # # Template của sự kiện dạng biểu đồ
# output_file = plot_event_distribution(templates_log_df, output_file='result.png')

# # hàm tính số lượng sự kiện theo ngày
# output_file = plot_event_counts(structured_log_df, time_unit='D', title='Total Number of DNS Events per Day', xlabel='Date', start_time=start_time, end_time=end_time, output_file='result.png')
# # Sử dụng hàm để tính số lượng sự kiện theo giờ
# output_file = plot_event_counts(structured_log_df, time_unit='h', title='Total Number of DNS Events per Day', xlabel='Date', start_time=start_time, end_time=end_time, output_file='result.png')

# # Phân bố các sự kiện theo IP nguồn
# output_file = plot_ip_distribution(structured_log_df, start_time=start_time, end_time=end_time, output_file='result.png')

# # vẽ biểu đồ phân bố các loại yêu cầu DNS.
# output_file = plot_dns_query_distribution(structured_log_df,start_time=start_time, end_time=end_time, output_file='result.png')

# # Sự thay đổi trong các mẫu sự kiện theo thời gian
# output_file = plot_event_templates_over_time(structured_log_df, start_time=start_time, end_time=end_time, output_file='result.png')
# # Hiện thông tin chi tiết bảng
# detail_table = detail_log(structured_log_df)