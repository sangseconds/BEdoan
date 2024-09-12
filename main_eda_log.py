from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse
from typing import List, Optional
import pandas as pd
from datetime import datetime

from EDAXuan.networklog.DNS import process_log_files_dns,plot_ip_distribution,plot_dns_query_distribution
from EDAXuan.nettraffic.edapcap import plot_traffic_trend
from EDAXuan.networklog.Audit import process_log_files_audit,bar_column_distribution,plot_account_activity_over_time,classify_and_plot
from EDAXuan.networklog.Access import process_log_files_access,plot_response_bytes_distribution,pie_column_distribution,get_method_status_counts


app = FastAPI()

# Biến toàn cục để lưu trữ DataFrame
global structured_log_df, templates_log_df
    # Bạn có thể khởi tạo giá trị mặc định cho các DataFrame này nếu cần
structured_log_df = pd.DataFrame()
templates_log_df = pd.DataFrame()

# input_dir = "./EDAXuan/networklog/example"
@app.get("/DNS/process_logs")
def process_logs(input_dir: str = "./EDAXuan/networklog/example", log_file: str="dnstest.log", year: int = 2022):
    global structured_log_df, templates_log_df
    
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_dns(input_dir, log_file, year)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
    return structured_log_json, templates_log_json

# trả về cả 2 loại tùy vào data của structure và template 
@app.get("/get_structured_log")
def get_structured_log():
    global structured_log_df
    # Trả về cấu trúc log đã được xử lý dưới dạng JSON
    return structured_log_df.to_dict()

@app.get("/get_templates_log")
def get_templates_log():
    global templates_log_df
    # Trả về template log dưới dạng JSON
    return templates_log_df.to_dict()
# M1
@app.get("/DNS/M1_template_distribution")
def audit_bar_template_distribution():
    # Tạo bảng phân bố các sự kiện
    event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    # Chuyển đổi DataFrame thành danh sách các dictionary
    result = event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_dict(orient='records')

    # Trả về kết quả dưới dạng JSON
    return result

# M2 ngày "D", giờ "h" phút "min" time_sign = "D" or "h"
@app.get("/DNS/M2_event_counts/{time_sign}")
def bar_event_counts(time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            event_count = plot_traffic_trend(structured_log_df, time_sign, start_time_dt, end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
#M3
@app.get("/DNS/M3_ip_distribution/{top}")
def bar_ip_distribution(start_time: Optional[str] = None, end_time: Optional[str] = None, top: int = 10):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            print("test")
            # Gọi hàm
            result = plot_ip_distribution(structured_log_df, start_time_dt, end_time_dt,top)
            print("test1")
            print(result)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")

# M4
@app.get("/DNS/M4_dns_query_distribution/")
def bar_dns_query_distribution(start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = plot_dns_query_distribution(structured_log_df, start_time_dt, end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    


# audit
@app.get("/Audit/process_logs")
def process_logs(input_dir: str= "./EDAXuan/networklog/example", log_file: str="audit"):
    global structured_log_df, templates_log_df
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_audit(input_dir, log_file)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
    return structured_log_json, templates_log_json

# M1
@app.get("/Audit/M1_template_distribution")
def audit_bar_template_distribution():
    # Tạo bảng phân bố các sự kiện
    event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    # Chuyển đổi DataFrame thành danh sách các dictionary
    result = event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_dict(orient='records')

    # Trả về kết quả dưới dạng JSON
    return result

# M2ngày "D", giờ "h" phút "min" time_sign = "D" or "h"
@app.get("/Audit/M2_event_counts/{time_sign}")
def bar_event_counts(time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            event_count = plot_traffic_trend(structured_log_df, time_sign, start_time_dt, end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
# M3
# # M3.1 Phân phối của Event Type column = Type
# M3.2 Phân phối của Account "acct"
# M3.3 Phân phối của Pid "pid"
# 3.4 Phân phối của uid "uid"
# 3.5 Tạo biểu đồ phân phối của exe "exe"
@app.get("/Audit/M3_bar_column_distribution/{column}/{top}")
def audit_bar_column_distribution(column, top:int, start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = bar_column_distribution(structured_log_df, column, top=top, start_time=start_time_dt, end_time=end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
# M4   
@app.get("/Audit/M4_account_activity_over_time/{account}/{time_sign}")
def audit_plot_account_activity_over_time(account: str, time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = plot_account_activity_over_time(structured_log_df, account=account, time_sign=time_sign, start_time=start_time_dt, end_time=end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# M5 Pie chart veef result
@app.get("/Audit/M5_classify_and_plot/")
def audit_pie_classify_and_plot(start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = classify_and_plot(structured_log_df, start_time=start_time_dt, end_time=end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
 
# Access
# input_dir = "./EDAXuan/networklog/example"
@app.get("/Access/process_logs")
def access_process_logs(input_dir: str = "./EDAXuan/networklog/example", log_file: str="accesstest.log"):
    global structured_log_df, templates_log_df
    
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_access(input_dir, log_file)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
    return structured_log_json, templates_log_json

# M1
@app.get("/Access/M1_template_distribution")
def access_bar_template_distribution():
    # Tạo bảng phân bố các sự kiện
    event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()

    # Chuyển đổi DataFrame thành danh sách các dictionary
    result = event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_dict(orient='records')

    # Trả về kết quả dưới dạng JSON
    return result

# M2 ngày "D", giờ "h" phút "min" time_sign = "D" or "h"
@app.get("/Access/M2_event_counts/{time_sign}")
def access_bar_event_counts(time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            event_count = plot_traffic_trend(structured_log_df, time_sign, start_time_dt, end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")

   
#M3 Bar chart Phân bố Client_IP, User_Agent theo top column = Client_IP or User_Agent (M6_dạng bảng)
@app.get("/Access/M3_bar_column_distribution/{column}/{top}")
def audit_bar_column_distribution(column:str, top:int, start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = bar_column_distribution(structured_log_df, column, top=top, start_time=start_time_dt, end_time=end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# M4. Bar chart Phân bố Response_Bytes theo khoảng bins để mặc định là 8
@app.get("/Access/M4_response_bytess_distribution/")
def access_plot_response_bytes_distribution(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetim
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time= datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = plot_response_bytes_distribution(structured_log_df, num_bins=8, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
# M5 _ Stacked bar chart
@app.get("/Access/M5_method_status_counts/")
def access_stackedbar_method_status_counts(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetim
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time= datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = get_method_status_counts(structured_log_df, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
    
# M6 (ở M3)
# 
# Pie chart M7 column = Status_Code M8 = Version M9 = Method
@app.get("/Access/M789_pie_column_distribution/{column}")
def audit_pie_column_distribution(column,start_time: Optional[str] = None, end_time: Optional[str] = None):
    # Gọi hàm plot_ip_distribution và trả về kết quả
    global structured_log_df
    if structured_log_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
            
            # Gọi hàm
            result = pie_column_distribution(structured_log_df, column=column,start_time=start_time_dt, end_time=end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    


    

    





 
 





    
    



