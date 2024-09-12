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
from sqlalchemy.orm import Session
from fastapi import Depends
import crud
import models
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

# Biến toàn cục để lưu trữ DataFrame
global df
global output_counter
global network_dir
global log_dir
global log_filename
global label_df

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



@app.post("/log/upload_and_process/",response_class=JSONResponse)
async def upload_and_process_file(file: UploadFile = File(...),start_time: Optional[str] = None, end_time: Optional[str] = None, top:int = 10,time_sign = "h"):
    # global structured_log_df, templates_log_df, log_dir, log_filename, output_counter
    global output_counter 
    file_location = f"/home/vothuonghd1998/database/{file.filename}"
    file_output = f"/home/vothuonghd1998/database/"
    log_filename=file.filename
    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(file.file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")

    # Xử lý file log
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


    output_counter += 1
    log_array = generate_log_array(df)
    
    # Kiểm tra loại log
    log_type = None
    file_path = f"{log_dir}/{log_filename}"
    try:
        with open(file_path, 'r') as file:
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
    results = []
    if log_type == "dns":
        # Nếu log_type là "dns", xử lý và vẽ biểu đồ
        structured_log_df, templates_log_df = process_log_files_dns(log_dir, log_filename, year=2022)
        # results = []
        results.append(structured_log_df.to_json(orient="records"))

        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        # time_sign='h'
        # top = 10

        # Biểu đồ phân bố template
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        results.append(event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_json(orient='records'))
        # Biểu đồ đếm sự kiện theo thời gian

        event_count = plot_traffic_trend(structured_log_df, time_sign, start_time, end_time)
        results['event_counts'] = event_count

        # Biểu đồ phân bố IP
        top=10
        ip_distribution = plot_ip_distribution(structured_log_df, start_time, end_time, top)
        results['ip_distribution'] = ip_distribution

        # Biểu đồ phân bố DNS query
        dns_query_distribution = plot_dns_query_distribution(structured_log_df, start_time, end_time)
        results['dns_query_distribution'] = dns_query_distribution

        # return JSONResponse(content=results)

        ## Audit

    elif log_type == "audit":
        # Nếu log_type là "audit", xử lý và vẽ biểu đồ
        structured_log_df, templates_log_df = process_log_files_audit(log_dir, log_filename)
        # results = []
        results.append(structured_log_df.to_json(orient="records"))

        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        # time_sign='h'
        # top = 10

        # Biểu đồ phân bố template
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        results.append(event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_json(orient='records'))
        # Biểu đồ đếm sự kiện theo thời gian

        event_count = plot_traffic_trend(structured_log_df, time_sign, start_time, end_time)
        results.append(event_count)

# M3
# # M3.1 Phân phối của Event Type column = Type
# M3.2 Phân phối của Account "acct"
# M3.3 Phân phối của Pid "pid"
# 3.4 Phân phối của uid "uid"
# 3.5 Tạo biểu đồ phân phối của exe "exe"
        column= "Type"
        ip_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(ip_distribution)

        column= "acct"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)

        column= "pid"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)

        column= "uid"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)

        column= "exe"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)

  # M4      
        # column_distribution = plot_account_activity_over_time(structured_log_df, account = '', time_sign, start_time, end_time)
        column_distribution = plot_account_activity_over_time(structured_log_df, '', time_sign, start_time, end_time)
        results.append(column_distribution)
# M5
        column_distribution=classify_and_plot(structured_log_df, start_time, end_time)
        results.append(column_distribution)

    elif log_type == "access":
        # Nếu log_type là "acccess", xử lý và vẽ biểu đồ
        structured_log_df, templates_log_df = process_log_files_access(log_dir, log_filename)
        # results = []
        results.append(structured_log_df.to_json(orient="records"))

        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        # time_sign='h'
        # top = 10

        # Biểu đồ phân bố template
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        results.append(event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_json(orient='records'))
        # Biểu đồ đếm sự kiện theo thời gian

        event_count = plot_traffic_trend(structured_log_df, time_sign, start_time, end_time)
        results.append(event_count)

#M3. Bar chart Phân bố Client_IP, User_Agent theo top column = Client_IP or User_Agent (M6_dạng bảng)
        column= "Client_IP"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)


# M4
        # num_bins=8
        column_result = plot_response_bytes_distribution(structured_log_df, 8, start_time,end_time)
        results.append(column_result)
# M5 _ Stacked bar chart
        column= "User_Agent"
        column_distribution = get_method_status_counts(structured_log_df,start_time, end_time)
        results.append(column_distribution)
        # M6
        column= "User_Agent"
        column_distribution = bar_column_distribution(structured_log_df, column, top, start_time, end_time)
        results.append(column_distribution)

        # M7
        column= "Status_Code"
        column_distribution = pie_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        # M8
        column= "Version"
        column_distribution = pie_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        # M9
        column= "Method"
        column_distribution = pie_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        # return JSONResponse(content=results)
    crud.create_log(log_data=results,file_path=file_location,file_name=log_filename,type_log=log_type)
        
    return results


@app.get("/log/{id}")
async def log(
    id: int,
    db: Session = Depends(get_db),
):
    log = crud.get_log(db, id)
    return log

@app.delete("/Log/delete/{id}", response_class=JSONResponse)
async def delete_traffic(id: int, db: Session = Depends(get_db)):
    Log_entry = crud.delete_traffic(db=db, id=id)
    if Log_entry is None:
        raise HTTPException(status_code=404, detail="Traffic entry not found")

    return {"message": "Traffic entry deleted successfully", "data": Log_entry}