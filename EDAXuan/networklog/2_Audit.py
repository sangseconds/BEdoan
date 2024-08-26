from logparser.Drain import LogParser
import pandas as pd
import matplotlib.pyplot as plt
import re


input_dir = './example' # The input directory of log file
output_dir = './audit/'  # The output directory of parsing results
log_file = 'audit.log'  # The input log file name
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

# Load the CSV file
df = pd.read_csv('./audit/audit.log_structured.csv')

# Function to extract key-value pairs from the content
def parse_content(content):
    # Regular expression to match key-value pairs (e.g., 'pid=1716', 'op=PAM:session_open')
    pattern = r'(\w+(?:-\w+)?=[^\s]+|op=[^\s]+)'
    
    # Find all matches
    matches = re.findall(pattern, content)

    
    # Convert matches into a dictionary
    content_dict = {}
    for match in matches:
        key_value = match.split('=', 1)  # Split only on the first '='
        if len(key_value) == 2:
            content_dict[key_value[0]] = key_value[1]
    
    return content_dict  # Ensure the function returns the dictionary

# Apply the function to the "Content" column
parsed_data = df['Content'].apply(parse_content)

# Convert the list of dictionaries to a DataFrame
parsed_df = pd.json_normalize(parsed_data)

# Combine the new columns with the original DataFrame, excluding the 'Content', 'EventId', 'EventTemplate', and 'ParameterList' columns
df_combined = pd.concat([df.drop(columns=['Content', 'EventId', 'EventTemplate', 'ParameterList']), parsed_df], axis=1)

# Extract Unix timestamp
df_combined['Timestamp'] = df_combined['Timestamp'].str.extract(r'\((\d+\.\d+):\d+\)')[0]

df_combined['Timestamp'] = pd.to_numeric(df_combined['Timestamp'], errors='coerce')
# Convert to datetime UTC
df_combined['Timestamp'] = pd.to_datetime(df_combined['Timestamp'], unit='s', utc=True)
# Round seconds
df_combined['Timestamp'] = df_combined['Timestamp'].dt.round('s')
# Remove timezone information by formatting the Timestamp column
df_combined['Timestamp'] = df_combined['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
df_combined['Timestamp'] = pd.to_datetime(df_combined['Timestamp'])

df_combined['msg'] = df_combined['msg'].str.replace("'", "")
df_combined['res'] = df_combined['res'].str.replace("'", "")
df_combined['acct'] = df_combined['acct'].str.replace('"', "")
# Save the processed data to a new CSV file
df_combined.to_csv('./audit/intranet_server/audit.log_processed.csv', index=False)

df = pd.read_csv('./audit/audit.log_processed.csv')
templates_log_df = pd.read_csv('./audit/audit.log_templates.csv')
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
# test
# start_time = df['Timestamp'].iloc[0]
# end_time = df['Timestamp'].iloc[-1]
# print(start_time)
# print(end_time)
# Hai chuỗi thời gian
start_time = pd.to_datetime('2022-01-21 01:17:01')
end_time = pd.to_datetime('2022-01-24 22:17:02')

def table_event_distribution(df):

    event_distribution = df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    return event_distribution

def plot_event_counts(df, time_unit='D', title='Number of Audit Events', xlabel='Time', ylabel='Number of Events',start_time=None, end_time=None, output_file='result.png'):
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    event_counts = df_filter.resample(time_unit, on='Timestamp').size()
    # vẽ
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

def bar_column_distribution(df,column,title='Distribution of Event Type', xlabel='Event Type', ylabel='Count', top = 10, start_time=None, end_time=None, output_file='result.png'):
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    # Phân phối các loại sự kiện
    column_counts = df[column].value_counts().head(top)
    
    # Vẽ biểu đồ
    plt.figure(figsize=(10, 6))
    column_counts.plot(kind='bar', color='skyblue')
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
    # Trả về tên file đã lưu
    return output_file

def plot_account_activity_over_time(df, account, time_unit='h', start_time=None, end_time=None, output_file='result.png'):
    # Đảm bảo cột 'Timestamp' là kiểu datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Lọc dữ liệu trong khoảng thời gian mong muốn
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Đặt 'Timestamp' làm chỉ mục
    df_filter = df_filter.set_index('Timestamp')

    # Lọc dữ liệu cho một tài khoản cụ thể và resample
    account_time_series = df_filter[df_filter['acct'] == account].resample(time_unit).size()
    
    # Vẽ biểu đồ
    plt.figure(figsize=(12, 6))
    account_time_series.plot(kind='line', color='purple')
    plt.title(f'Activity Over Time for Account: {account}')
    plt.xlabel('Time')
    plt.ylabel('Number of Events')
    plt.grid(True)
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()
    # Trả về tên file đã lưu
    return output_file

def table_column_distribution(df,column="exe",start_time=None, end_time = None, output_file='result.png'):

    column_distribution = df[column].value_counts()

    return column_distribution

# Phân loại sự kiện thành công hay thất bại
# Function to classify events
# Function to classify a single event
def classify_event(row):
    res_value = str(row['res']).lower() if 'res' in row and pd.notna(row['res']) else None
    success_value = str(row['success']).lower() if 'success' in row and pd.notna(row['success']) else None
    
    if (res_value in ['success', '1']) or (success_value == 'yes'):
        return 'Success'
    elif (res_value in ['fail', '0']) or (success_value == 'no'):
        return 'Fail'
    else:
        return 'Unknown'

# Function to filter data and plot classification results
def classify_and_plot(df, start_time=None, end_time=None, output_file='result.png'):
    # Đảm bảo cột 'Timestamp' là kiểu datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Lọc dữ liệu trong khoảng thời gian mong muốn
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()
    
    # Apply classification to each row
    df_filter['Event_Classification'] = df_filter.apply(classify_event, axis=1)
    
    # Count the classifications
    event_distribution = df_filter['Event_Classification'].value_counts()
    
    # Plotting the pie chart
    plt.figure(figsize=(8, 8))
    event_distribution.plot(kind='pie', autopct='%1.1f%%', startangle=90, colors=['lightgreen', 'lightcoral', 'lightgrey'])
    plt.title('Event Classification: Success vs Fail vs Unknown')
    plt.ylabel('')  # Hide the y-label
    # Lưu biểu đồ thành file ảnh
    plt.savefig(output_file)
    plt.show()

    # Trả về tên file đã lưu
    return output_file


# hàm chạy code
# Template dạng bảng
template_df = table_event_distribution(templates_log_df)

# Sử dụng hàm để tính số lượng sự kiện theo ngày
output_file = plot_event_counts(df, time_unit='D', title='Total Number of DNS Events per Day', xlabel='Dates',start_time=start_time, end_time= end_time, output_file='result.png')
# theo giờ
output_file = plot_event_counts(df, time_unit='h', title='Total Number of DNS Events per hour', xlabel='Hour',start_time=start_time, end_time= end_time, output_file='result.png')

# Phân phối của Event Type
bar_column_distribution(df,'Type', title=' Distribution of Event Type', xlabel='Event Type', ylabel='Count', top = df['Type'].nunique(), start_time=start_time, end_time=end_time, output_file='result.png')
# Phân phối của Account
bar_column_distribution(df,'acct', title='Distribution of Account activity', xlabel='Account', ylabel='Count', top = df['acct'].nunique(), start_time=start_time, end_time=end_time, output_file='result.png')
# Phân phối của Pid
bar_column_distribution(df,'pid', title='Distribution of Process ID Activity', xlabel='PID', ylabel='Count', top =10, start_time=start_time, end_time=end_time, output_file='result.png')
# Phân phối của uid
bar_column_distribution(df,'uid', title='Distribution of User ID Activity', xlabel='User ID', ylabel='Count', top =10, start_time=start_time, end_time=end_time, output_file='result.png')

# Vẽ biểu đồ hoạt động theo thời gian cho một tài khoản cụ thể
output_file = plot_account_activity_over_time(df, account='root', time_unit='h', start_time=start_time, end_time=end_time, output_file='result.png')

# Ví dụ sử dụng hàm để tạo bảng phân bố exe
# Tạo biểu đồ phân phối của exe
output_file =bar_column_distribution(df,'exe', title='Distribution of EXE command', xlabel='Exe Command', ylabel='Count', top =10, start_time=start_time, end_time=end_time, output_file='result.png')

# Phân loại event thành công hay thất bại
output_file = classify_and_plot(df, start_time=start_time, end_time=end_time, output_file='result.png')
