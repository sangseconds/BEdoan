from logparser.Drain import LogParser
import pandas as pd
import matplotlib.pyplot as plt
import re


# input_dir = "./EDAXuan/networklog/example"
# output_dir = './audit/'  # The output directory of parsing results
# log_file = 'audit.log'  # The input log file name
import re
import pandas as pd
from logparser.Drain import LogParser

def process_log_files_audit(input_dir = "./EDAXuan/networklog/example", log_file= 'audit.log'):
    output_dir = './audit/'  # The output directory of parsing results
    log_format = 'type=<Type> msg=audit(<Timestamp>): <Content>'
    regex = [r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)']  # Regular expression list for optional preprocessing
    st = 0.5  # Similarity threshold
    depth = 4  # Depth of all leaf nodes

    # Initialize LogParser with provided parameters
    parser = LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex)
    parser.parse(log_file)

    # Load the CSV file
    structured_csv_path = f'{output_dir}/{log_file}_structured.csv'
    df = pd.read_csv(structured_csv_path)

    # Function to extract key-value pairs from the content
    def parse_content(content):
        # Regular expression to match key-value pairs
        pattern = r'(\w+(?:-\w+)?=[^\s]+|op=[^\s]+)'
        matches = re.findall(pattern, content)
        
        # Convert matches into a dictionary
        content_dict = {}
        for match in matches:
            key_value = match.split('=', 1)
            if len(key_value) == 2:
                content_dict[key_value[0]] = key_value[1]
        
        return content_dict

    # Apply the function to the "Content" column
    parsed_data = df['Content'].apply(parse_content)

    # Convert the list of dictionaries to a DataFrame
    parsed_df = pd.json_normalize(parsed_data)

    # Combine the new columns with the original DataFrame
    df_combined = pd.concat([df.drop(columns=['Content', 'EventId', 'EventTemplate', 'ParameterList']), parsed_df], axis=1)

    # Extract Unix timestamp and convert to datetime
    df_combined['Timestamp'] = df_combined['Timestamp'].str.extract(r'\((\d+\.\d+):\d+\)')[0]
    df_combined['Timestamp'] = pd.to_numeric(df_combined['Timestamp'], errors='coerce')
    df_combined['Timestamp'] = pd.to_datetime(df_combined['Timestamp'], unit='s', utc=True)
    df_combined['Timestamp'] = df_combined['Timestamp'].dt.round('s')
    df_combined['Timestamp'] = df_combined['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    df_combined['Timestamp'] = pd.to_datetime(df_combined['Timestamp'])
    df_combined['Timestamp'] = df_combined['Timestamp'].dt.strftime('%Y/%m/%d %H:%M:%S')
    # print ("xuan")
    # print(df_combined['Timestamp'])

    # Clean specific columns
    df_combined['msg'] = df_combined['msg'].str.replace("'", "")
    df_combined['res'] = df_combined['res'].str.replace("'", "")
    df_combined['acct'] = df_combined['acct'].str.replace('"', "")
    # Thêm cột 'id' với giá trị từ 1 đến số dòng của df
    df_combined['id'] = range(1, len(df_combined) + 1)
    # Save the processed data to a new CSV file
    processed_log_file = f'{output_dir}/{log_file}_processed.csv'
    # hai dòng code tiếp theo thừa
    # df_combined.to_csv(processed_log_file, index=False)
    # # Load and return processed data and templates log data
    # df = pd.read_csv(processed_log_file)
    templates_log_df = pd.read_csv(f'{output_dir}/{log_file}_templates.csv')

    return df_combined, templates_log_df

def bar_column_distribution(df, column: str,start_time=None, end_time=None):
    # Chuyển đổi thời gian từ chuỗi sang datetime nếu có
    start_time_dt = pd.to_datetime(start_time) if start_time else df['Timestamp'].min()
    end_time_dt = pd.to_datetime(end_time) if end_time else df['Timestamp'].max()
    df['Timestamp']=pd.to_datetime(df['Timestamp'])
    
    # Lọc DataFrame theo khoảng thời gian
    # df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    df_filter = df.loc[(df['Timestamp'] >= start_time_dt) & (df['Timestamp'] <= end_time_dt)]
    # Phân phối các loại sự kiện
    column_counts = df_filter[column].value_counts()
    
    # Chuyển đổi kết quả thành danh sách các từ điển với 'name' và 'uv'
    result = [{'name': name, 'uv': count} for name, count in column_counts.items()]
    
    return result


def plot_account_activity_over_time(df: pd.DataFrame, account: str = '', time_sign: str = 'h', start_time= None, end_time=None):
    # Đảm bảo cột 'Timestamp' là kiểu datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Chuyển đổi thời gian từ chuỗi sang datetime nếu có
    start_time_dt = pd.to_datetime(start_time) if start_time else df['Timestamp'].min()
    end_time_dt = pd.to_datetime(end_time) if end_time else df['Timestamp'].max()

    # Lọc dữ liệu trong khoảng thời gian mong muốn
    df_filter = df.loc[(df['Timestamp'] >= start_time_dt) & (df['Timestamp'] <= end_time_dt)]
    # df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    
    # Đặt 'Timestamp' làm chỉ mục
    df_filter = df_filter.set_index('Timestamp')

    # Lọc dữ liệu cho một tài khoản cụ thể và resample
    account_time_series = df_filter[df_filter['acct'] == account].resample(time_sign).size()
    
    # Chuyển đổi thành mảng các từ điển với 'name' (timestamp) và 'pv' (event count)
    result = [{'name': timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'pv': count} for timestamp, count in account_time_series.items()]
    
    return result

# def table_column_distribution(df,column="exe"):

#     column_distribution = df[column].value_counts()

#     return column_distribution

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
def classify_and_plot(df: pd.DataFrame, start_time=None, end_time=None):
    # Đảm bảo cột 'Timestamp' là kiểu datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Chuyển đổi thời gian từ chuỗi sang datetime nếu có
    start_time_dt = pd.to_datetime(start_time) if start_time else df['Timestamp'].min()
    end_time_dt = pd.to_datetime(end_time) if end_time else df['Timestamp'].max()

    # Lọc dữ liệu trong khoảng thời gian mong muốn
    df_filter = df.loc[(df['Timestamp'] >= start_time_dt) & (df['Timestamp'] <= end_time_dt)].copy()
    # df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)].copy()
    
    # Áp dụng phân loại sự kiện cho từng hàng
    df_filter['Event_Classification'] = df_filter.apply(classify_event, axis=1)
    
    # Đếm số lượng các loại phân loại sự kiện
    event_distribution = df_filter['Event_Classification'].value_counts()
    
    # Chuyển đổi kết quả thành danh sách các từ điển với 'name' và 'value'
    result = [{'name': classification, 'value': count} for classification, count in event_distribution.items()]
    return result


