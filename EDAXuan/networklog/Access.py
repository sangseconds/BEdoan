from logparser.Drain import LogParser
import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np
from datetime import datetime

# input_dir = "./EDAXuan/networklog/example"
# output_dir = './audit/'  # The output directory of parsing results
# log_file = 'audit.log'  # The input log file name


def process_log_files_access(input_dir = "./EDAXuan/networklog/example", log_file= 'accesstest.log'):
    # def logparse_access(input_dir = "./", log_file= 'access.log'):
    output_dir = './apache/'  # The output directory of parsing results
    log_format = '<Client_IP> <l> <u> <Timestamp> <MuiGio> "<Request>" <Status_Code> <Response_Bytes> "<Refer>" <Content>'
    regex = [r'(\d{1,3}\.){3}\d{1,3}(:\d+)?']  # Adjusted regex for IP addresses
    st = 0.8  # Similarity threshold
    depth = 4  # Depth of all leaf nodes
    # Initialize LogParser with provided parameters
    parser = LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex)
    parser.parse(log_file)
    structured_csv_path = f'{output_dir}/{log_file}_structured.csv'
    df = pd.read_csv(structured_csv_path) 
    # Chuyển đổi cột 'Time' về dạng Y/M/D H:min:se và bỏ ký tự '[' ở đầu
    df['Timestamp'] = pd.to_datetime(df['Timestamp'].str[1:], format='%d/%b/%Y:%H:%M:%S')
    df['Timestamp'] = df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M:%S')
    # Sử dụng regex để tách cột 'Request' thành ba cột: Method, Path, Version
    df[['Method', 'Path', 'Version']] = df['Request'].str.extract(r'(\w+)\s+([^\s]+)\s+(HTTP/\d\.\d)', expand=True)
    df["User_Agent"] = df["Content"]
    # Bỏ các cột 'l', 'u', và 'MuiGio'
    df = df.drop(columns=['l', 'u', 'MuiGio','Request','EventTemplate','ParameterList','EventId','Content'], errors='ignore')
    
    df.to_csv(structured_csv_path, index=False)
    # Hiển thị DataFrame sau khi thực hiện các thay đổi
    templates_log_df = pd.read_csv(f'{output_dir}/{log_file}_templates.csv')
    return df, templates_log_df

# Tab3/M2 Hàm để vẽ biểu đồ phân phối Response_Bytes theo khoảng
def plot_response_bytes_distribution(df, num_bins=8, start_time=None, end_time=None):
    """
    Tạo các bin từ dữ liệu cột và đếm số lần xuất hiện trong mỗi bin theo khoảng thời gian    
    Returns:
    str: Chuỗi JSON chứa danh sách các bin và số lần xuất hiện trong mỗi bin.
    """
    # Convert start_time and end_time to Timestamps if they are not already
    start_time = pd.to_datetime(start_time)
    end_time = pd.to_datetime(end_time)
    # df['Timestamp']=pd.to_datetime(df['Timestamp'])
    mask = (df['Timestamp'] >= pd.to_datetime(start_time)) & (df['Timestamp'] <= pd.to_datetime(end_time))
    filtered_data = df.loc[mask, "Response_Bytes"]
    
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

# M5
def get_method_status_counts(df: pd.DataFrame, start_time=None, end_time=None):

    # Lọc DataFrame theo khoảng thời gian
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    # Tạo bảng đếm số lượng cho mỗi cặp 'Method' và 'Status_Code'
    count_data = df_filter.groupby(['Method', 'Status_Code']).size().unstack().fillna(0).astype(int)
    
    # Chuyển đổi count_data thành định dạng mong muốn
    result = []
    for status_code in count_data.columns:
        status_dict = {'status_code': str(status_code)}
        for method in count_data.index:
            status_dict[method] = int(count_data.at[method, status_code])
        result.append(status_dict)   
    return result

# M7,8,9
def pie_column_distribution(df: pd.DataFrame, column, start_time=None, end_time=None):

    # Lọc DataFrame theo khoảng thời gian
    df_filter = df.loc[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]
    # Phân phối các loại sự kiện
    column_counts = df_filter[column].value_counts()
    
    # Chuyển đổi kết quả thành danh sách các từ điển với 'name' và 'uv'
    result = [{'name': name, 'value': count} for name, count in column_counts.items()]
    return result

def plot_log_trend(df, time_sign='h', start_time=None, end_time=None):

    # Lọc dữ liệu dựa trên khoảng thời gian start_time và end_time
    df_filter = df[(df['Timestamp'] >= start_time) & (df['Timestamp'] <= end_time)]

    # Resample dữ liệu dựa trên time_sign ('h' cho theo giờ, 'd' cho theo ngày)
    traffic_counts = df_filter.resample(time_sign, on='Timestamp').size()
    
    # Chuẩn bị dữ liệu để trả về
    result = [{'name': ts.strftime('%Y/%m/%d' if time_sign == 'D' else '%Y/%m/%d %H:%M'), 'pv': count} 
              for ts, count in traffic_counts.items()]
    
    return result


