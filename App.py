import pandas as pd
from fastapi import Depends, FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
import os
import shutil
import subprocess
import random
import string
import yaml
import time
from datetime import datetime
from fastapi.responses import HTMLResponse
from typing import List, Optional
import re

from Sang.pcaptpCSV import convert_pcap_to_csv, read_csv_to_dataframe, predict_anomalies, wait_for_csv_completion  # Import các hàm từ traffic.py

from EDAXuan.nettraffic.edapcap import process_csv,generate_ip_map,generate_network_graph,analyze_ip_flows,num_event
from EDAXuan.nettraffic.edapcap import plot_traffic_trend,plot_time_sum_column_trend,count_artifacts,plot_totlen_pkts_distribution,plot_address_distribution_barchart
from EDAXuan.nettraffic.edapcap import plot_top_ip_pairs_by_frame_len,summarize_column,plot_protocol_pie_chart,plot_column_distribution_barchart

from EDAXuan.networklog.DNS import process_log_files_dns,plot_ip_distribution,plot_dns_query_distribution
from EDAXuan.nettraffic.edapcap import plot_pkts_traffic_trend
from EDAXuan.networklog.Audit import process_log_files_audit,bar_column_distribution,plot_account_activity_over_time,classify_and_plot
from EDAXuan.networklog.Access import process_log_files_access,plot_response_bytes_distribution,pie_column_distribution,get_method_status_counts

from fastapi.middleware.cors import CORSMiddleware

import crud
import models
from database import SessionLocal, engine
from sqlalchemy.orm import Session

models.Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

# Cấu hình CORS
origins = [
    "http://localhost:3000",  # Cho phép từ localhost:3000
    "http://192.168.131.197:3000",   # Cho phép từ domain khác nếu cần
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Cho phép tất cả các phương thức HTTP như GET, POST
    allow_headers=["*"],  # Cho phép tất cả các header
)




TEMPLATE_CONFIG_PATH = "../BEdoan/huongdancaidat/config.yml"
COUNTER_FILE = "counter.txt"
df = None
label_df = None
network_dir=''
log_dir=''
log_filename=''
def get_next_counter_value():
    if not os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE, "w") as f:
            f.write("1")
        return 1
    
    with open(COUNTER_FILE, "r") as f:
        value = int(f.read().strip())
    
    new_value = value + 1
    
    with open(COUNTER_FILE, "w") as f:
        f.write(str(new_value))
    
    return new_value

def stop_if_no_change(output_command_name: str, process, interval: int = 5, max_attempts: int = 3):
    attempts = 0
    last_size = -1

    while attempts < max_attempts:
        time.sleep(interval)
        current_size = os.path.getsize(output_command_name)

        if current_size == last_size:
            attempts += 1
        else:
            attempts = 0

        last_size = current_size
    
    if attempts >= max_attempts:
        print("No change detected in log file, stopping process.")
        process.terminate()
        process.wait()


output_counter = get_next_counter_value()

def modify_config_and_run(file_location: str, output_command_name: str):
    global output_counter
    yml_dir = f"yml"
    os.makedirs(yml_dir, exist_ok=True)
    random_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".yml"
    config_path = os.path.join(yml_dir, random_filename)
    shutil.copyfile(TEMPLATE_CONFIG_PATH, config_path)
    
    with open(config_path, "r") as config_file:
        config_content = yaml.safe_load(config_file)
    
    if 'LogResourceList' in config_content and isinstance(config_content['LogResourceList'], list):
        config_content['LogResourceList'].append(f"file://{file_location}")
    else:
        config_content['LogResourceList'] = [f"file://{file_location}"]
    
    with open(config_path, "w") as config_file:
        yaml.dump(config_content, config_file, default_flow_style=False, sort_keys=False)
    
    command = f"sudo aminer -c {config_path} >> {output_command_name}"
    aminer_process = subprocess.Popen(command, shell=True)
    
    return config_path, yml_dir, aminer_process


def generate_network_matrix(df):
    # Giả sử `df` chứa các cột `Src IP`, `Dst IP`, và một số cột khác.
    # Chúng ta sẽ tạo ra danh sách các cạnh nối giữa các nút mạng.
    
    network_matrix = []
    
    if 'Src IP' in df.columns and 'Dst IP' in df.columns:
        for _, row in df.iterrows():
            network_matrix.append({
                "source": row['Src IP'],
                "target": row['Dst IP'],
                "protocol": row.get('Protocol', ''),
                "timestamp": row.get('Timestamp', ''),
                "flow_duration": row.get('Flow Duration', ''),
                "label": row.get('Label', '')
            })
    
    return network_matrix

def generate_log_array(df):
    # Giả sử `df` chứa cột `Line` và `Anomaly`
    log_array = df.to_dict(orient="records")
    return log_array

@app.post("/upload", response_class=JSONResponse)
async def upload_file(file: UploadFile = File(...)):
    global df
    global output_counter
    global network_dir
    global log_dir
    global log_filename
    global label_df
    file_location = f"/home/vothuonghd1998/database/{file.filename}"
    file_output = f"/home/vothuonghd1998/database/"
    
    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(file.file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
    
    if ".pcap" in file.filename:
        # Sử dụng hàm từ traffic.py để chuyển đổi file .pcap sang .csv
        csv_file_location = convert_pcap_to_csv(file_location, file_output)
        os.remove(file_location)
        # Sử dụng hàm từ traffic.py để đọc dữ liệu từ file CSV vào DataFrame
        df = read_csv_to_dataframe(csv_file_location)
        df = predict_anomalies(df)
        
        # Chỉ chọn các cột cần thiết để hiển thị
        selected_columns = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Label']
        # selected_columns = ['Label']
        df = df[selected_columns]
        label_df = df['Label']
        # Trả về DataFrame như là một đối tượng JSON đơn giản để hiển thị
        # return df.to_dict(orient='list')
        # return JSONResponse(content=df.to_dict(orient="records"))
        network_matrix = generate_network_matrix(df)
        network_dir=csv_file_location
        return JSONResponse(content=network_matrix)


    else:
        cmd_dir = f"/home/vothuonghd1998/BEdoan/outputLogDetection"
        
        outputlog = f"outputcommand{output_counter}.txt"
        output_command_name = f"{cmd_dir}/{outputlog}"
        config_filename, yml_dir, aminer_process = modify_config_and_run(file_location, output_command_name)
        
        stop_if_no_change(output_command_name, aminer_process)

        if not os.path.exists(output_command_name):
            raise HTTPException(status_code=500, detail="Failed to generate anomaly detection results")

        with open(output_command_name, "r") as f:
            command_results = f.readlines()
        
        with open(file_location, "r") as infile:
            uploaded_file_content = infile.readlines()
        
        data = {'Line': uploaded_file_content}
        df = pd.DataFrame(data)
        df['Anomaly'] = df['Line'].apply(lambda x: 'Anomaly' if x in command_results else 'Normal')
        
        label_df=df['Anomaly']
        
        # os.remove(file_location)
        log_dir=file_output
        log_filename=file.filename

        output_counter += 1
        log_array = generate_log_array(df)

        
        # return JSONResponse(content=df.to_dict(orient="records"))
        return JSONResponse(content=log_array)


@app.get("/fields", response_class=JSONResponse)
async def get_fields():
    global df
    if df is None:
        raise HTTPException(status_code=400, detail="No data available. Please upload a file first.")
    
    return {"fields": df.columns.tolist()}

@app.get("/search", response_class=JSONResponse)
async def search_data(field: str = Query(...), value: str = Query(...)):
    global df
    
    if df is None:
        raise HTTPException(status_code=400, detail="No data available. Please upload a file first.")

    if field not in df.columns:
        raise HTTPException(status_code=400, detail=f"Field '{field}' not found in the data.")

    # Tìm kiếm các dòng có giá trị của trường tương ứng với `value`
    result_df = df[df[field].astype(str).str.contains(value, case=False, na=False)]

    if result_df.empty:
        return JSONResponse(content={"message": "No matching data found."})

    return JSONResponse(content=result_df.to_dict(orient="records"))

#Xuan EDA_Traffic


# Biến toàn cục để lưu DataFrame
global_df = None

# Đọc csv từ hàm process_csv
@app.get("/traffic/readcsv/")
# def process_and_read_csv(input_file_path: str = Query(..., description="The path to the input CSV file")):
def process_and_read_csv():
    global global_df
    input_file_path=network_dir
    try:
        processed_file_path = process_csv(input_file_path)
        global_df = pd.read_csv(processed_file_path)

        # Chuyển đổi DataFrame thành JSON
        # json_data = global_df.to_json(orient="records", lines=True)

  
        json_data = pd.concat([global_df, label_df], axis=1)

        # Trả về chuỗi JSON
        return json_data.to_dict(orient='records')
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

# M1 return html
@app.get("/traffic/tab1/M1_generate_ip_map/", response_class=HTMLResponse)
def tgenerate_ip_map(
    geoip_db_path: str = Query('./EDAXuan/nettraffic/GeoLite2-City.mmdb', description="The path to the GeoIP database"),
    output_html_path: str = Query(r"./EDAXuan/nettraffic/output/ip_map.html", description="The output HTML file path")
):
    global global_df
    if global_df is not None:
        try:
            # Gọi hàm generate_ip_map với các tham số đã cung cấp
            result_path = generate_ip_map(global_df, geoip_db_path, output_html_path)
            
            # Đọc nội dung của file HTML
            with open(result_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            # Trả về nội dung HTML
            return HTMLResponse(content=html_content)
            
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded")
    

@app.get("/traffic/tab1/M2_net-graph/")
def tget_network_graph():
    global global_df
    if global_df is not None:
        try:
            graph_data = generate_network_graph(global_df)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded")


@app.get("/traffic/tab1/M3_ip-flows/")
def tanalyze_ip_flows():
    global global_df
    if global_df is not None:
        try:
            graph_data = analyze_ip_flows(global_df)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please call /readcsv/ first.")
    
# tab2/M0  
@app.get("/traffic/tab2/M0_event-count/")
def tnum_events():
    global global_df
    if global_df is not None:
        try:
            event_count = num_event(global_df)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please call /readcsv/ first.")
    
# tab2 /M1
# ngày "D", giờ "h" phút "min"
@app.get("/traffic/tab2/M1_traffic_trend/")
def tplot_traffic_trend(time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global global_df
    if global_df is not None:
        try:

            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()

            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            event_count = plot_traffic_trend(global_df, time_sign, start_time_dt, end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# tab2/m2   column = Time_Delta or Totlen Pkts    dùng lại hàm ở tab4 M5 column="TotLen Fwd Pkts" M6 column="TotLen Bwd Pkts"
@app.get("/traffic/tab2/M2_time_sum_column_trend/{column}")
def tplot_time_sum_column_trend(column:str, time_sign: str = 'h', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = plot_time_sum_column_trend(global_df, column, time_sign, start_time_dt, end_time_dt)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
# tab3/m1
@app.get("/traffic/tab2/M1_count_artifacts/")
def tcount_artifacts():
    global global_df
    if global_df is not None:
        try:
                     
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = count_artifacts(global_df)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
# tab3/M2
@app.get("/traffic/tab3/M2_totlen_pkts_distribution/")
def tplot_totlen_pkts_distribution(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetim
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time= datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
        
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = plot_totlen_pkts_distribution(global_df, num_bins=8, start_time=start_time, end_time=end_time)

            return result.to_dict(orient='records')
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    # result=[
    #             { "name": 'html', 'count': 80 },
    #             { "name": 'unknown', 'count': 20 },
    #             { "name": 'json', 'count': 10 },
    #             { "name": 'plain', 'count': 5 },
    #             ]

# tab3/M3+M4   column=Source IP or Destination IP
@app.get("/traffic/tab3/M3_address_distribution_barchart/{top}/{column}")
def tget_address_distribution_barchart(top: int, column: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_address_distribution_barchart(global_df, top=top, start_time=start_time, end_time=end_time, column=column)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    
    
    
# tab3/M5  
@app.get("/traffic/tab3/M5_top_ip_pairs_by_frame_len/{top}")
def tplot_top_ip_pairs_by_frame_len(top: int, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_top_ip_pairs_by_frame_len(global_df, top=top, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")   



# tab4/m1
@app.get("/traffic/tab4/M1_summarize_column/")
def tsummarize_column():
    global global_df
    if global_df is not None:
        try:
                     
            # Gọi hàm plot_traffic_trend để tính số lượng sự kiện
            result = summarize_column(global_df)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")
    


# tab4/m2 column=Protocol
@app.get("/traffic/tab4/M2_protocol_pie_chart")
def tplot_protocol_pie_chart(start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_protocol_pie_chart(global_df, start_time=start_time, end_time=end_time)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")   
    

# tab4/M3,4 column="Application Protocol" or "Source Port" or "Destination Port"
@app.get("/traffic/tab4/M3_protocol_pie_chart/{column}/{top}")
def tplot_column_distribution_barchart(top: int, column: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    global global_df
    if global_df is not None:
        try:
            # Chuyển đổi thời gian từ chuỗi sang datetime nếu có, nếu không dùng giá trị min/max từ DataFrame
            start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
            end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
            
            # Gọi hàm plot_address_distribution_barchart để tính toán và trả về kết quả
            result = plot_column_distribution_barchart(global_df, top =top, start_time=start_time, end_time=end_time,column=column)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")   

# ngày "D", giờ "h" phút "min"
# m5 column = 'TotLen Fwd Pkts'  or M6 = 'TotLen Bwd Pkts'
@app.get("/traffic/tab4/M56_pkts_traffic_trend/{column}")
def tplot_pkts_traffic_trend(time_sign: str = 'h', column: str = 'TotLen Fwd Pkts', start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[dict]:
    global global_df
    if global_df is not None:
        try:

            # Chuyển đổi thời gian từ chuỗi sang datetime
            start_time_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else global_df['Timestamp'].min()

            end_time_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
 
            event_count = plot_pkts_traffic_trend(global_df, time_sign="h", column= 'TotLen Fwd Pkts', start_time=start_time_dt, end_time=end_time_dt)
            return event_count
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="DataFrame is not loaded. Please load the DataFrame first.")



#Xuan Log_EDA



# Biến toàn cục để lưu trữ DataFrame
global structured_log_df, templates_log_df
    # Bạn có thể khởi tạo giá trị mặc định cho các DataFrame này nếu cần
structured_log_df = pd.DataFrame()
templates_log_df = pd.DataFrame()

#lOG_TYPE
@app.get("/test-log-type/")
async def test_log_type():
    log_type = None
    file_path = f"{log_dir}/{log_filename}"
    try:
        # Đọc nội dung tệp tin trực tiếp từ bộ nhớ
        # content = await File.read(f"{log_dir}/{log_filename}")
        with open(file_path, 'r') as file:
        # Mỗi dòng trong file là một chuỗi byte, cần chuyển đổi thành chuỗi string
            for line in file:
                if re.search(r'^type=', line):
                    log_type = "audit"
                    break
                elif re.search(r'^\d+\.\d+\.\d+\.\d+ - - \[\d+/\w+/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]', line):
                    log_type = "access"
                    break
                elif re.search(r'\[\w+ \w+ \d{2} \d{2}:\d{2}:\d{2}\.\d+ \d{4}\]', line):
                    log_type = "error"
                    break
                elif re.search(r'^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} dnsmasq\[\d+\]:', line):
                    log_type = "dns"
                    break
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {e}")

    if log_type:
        return log_type
    else:
        raise HTTPException(status_code=404, detail="Log type not found")

# input_dir = "./EDAXuan/networklog/example"
@app.get("/DNS/process_logs")
# def process_logs(input_dir: str = "./EDAXuan/networklog/example", log_file: str="dnstest.log", year: int = 2022):
def process_logs( year: int = 2022):
    global structured_log_df, templates_log_df
    input_dir=log_dir
    log_file=log_filename
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_dns(input_dir, log_file, year)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
    # return structured_log_json, templates_log_json
    return structured_log_json

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

            # Gọi hàm
            result = plot_ip_distribution(structured_log_df, start_time_dt, end_time_dt,top)

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
# def process_logs(input_dir: str= "./EDAXuan/networklog/example", log_file: str="audit.log"):
def process_logs():
    global structured_log_df, templates_log_df
    input_dir=log_dir
    log_file=log_filename
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_audit(input_dir, log_file)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
        # return structured_log_json, templates_log_json
    return structured_log_json

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
# def access_process_logs(input_dir: str = "./EDAXuan/networklog/example", log_file: str="accesstest.log"):
def access_process_logs():
    global structured_log_df, templates_log_df
    input_dir=log_dir
    log_file=log_filename
    # Gọi hàm process_log_files từ file log_processor.py và nhận về 2 DataFrame
    structured_log_df, templates_log_df = process_log_files_access(input_dir, log_file)
    # Convert DataFrames to JSON
    structured_log_json = structured_log_df.to_json(orient="records", date_format="iso")
    templates_log_json = templates_log_df.to_json(orient="records", date_format="iso")
        # return structured_log_json, templates_log_json
    return structured_log_json

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


@app.get("/test")
async def test(
    search: str | None = "",
    page_index: int = 1,
    page_size: int = 10,
    db: Session = Depends(get_db),
):
    traffic = crud.get_traffics(db, page_size, (page_index - 1) * page_size)
    return {"status": "success", "data": traffic}

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=5001)
