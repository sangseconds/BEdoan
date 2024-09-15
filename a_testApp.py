import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
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
import json

from Sang.pcaptpCSV import convert_pcap_to_csv, read_csv_to_dataframe, predict_anomalies, wait_for_csv_completion  # Import các hàm từ traffic.py

from EDAXuan.nettraffic.edapcap import process_csv,generate_ip_map,generate_network_graph,analyze_ip_flows,num_event
from EDAXuan.nettraffic.edapcap import plot_traffic_trend,plot_time_sum_column_trend,count_artifacts,plot_totlen_pkts_distribution,plot_address_distribution_barchart
from EDAXuan.nettraffic.edapcap import plot_top_ip_pairs_by_frame_len,summarize_column,plot_protocol_pie_chart,plot_column_distribution_barchart
from EDAXuan.nettraffic.edapcap import plot_pkts_traffic_trend,alert_general,bar_alert_categories,bar_alert_generating_hosts, bar_alert_receiving_hosts, pie_alert_generating_protocol


from EDAXuan.networklog.DNS import process_log_files_dns,plot_ip_distribution,plot_dns_query_distribution,log_alert_general,log_bar_alert_categories
from EDAXuan.networklog.Audit import process_log_files_audit,bar_column_distribution,plot_account_activity_over_time,classify_and_plot
from EDAXuan.networklog.Access import process_log_files_access,plot_response_bytes_distribution,pie_column_distribution,get_method_status_counts,plot_log_trend

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

def stop_if_no_change(output_command_name: str, process, interval: int = 10, max_attempts: int = 3):
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

#Traffic

@app.post("/Traffic/upload_and_process/", response_class=JSONResponse)
async def upload_and_process_file(file: UploadFile = File(...),start_time: Optional[str] = None, end_time: Optional[str] = None, time_sign = "min",db: Session = Depends(get_db)):
    global global_df
    global network_dir
    global log_dir
    global log_filename
    global label_df
    global output_counter
    network_filename=file.filename
    file_location = f"/home/vothuonghd1998/database/{file.filename}"
    file_output = f"/home/vothuonghd1998/database/"
    results = []
    
    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(file.file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
    
    # if ".pcap" in file.filename:
    csv_file_location = convert_pcap_to_csv(file_location, file_output)
    # os.remove(file_location)
    global_df = read_csv_to_dataframe(csv_file_location)
    global_df = predict_anomalies(global_df)
    
    selected_columns = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Label']
    # global_df_show = global_df[selected_columns]
    label_df = global_df['Label']
    
    # network_matrix = generate_network_matrix(global_df)
    network_dir = csv_file_location
    # results.append({"network_matrix": network_matrix})

    # Process CSV and add to results
    try:
        global_df = process_csv(network_dir,file_location)
        combined_df = pd.concat([global_df, label_df], axis=1)
        results.append(combined_df.to_dict(orient='records'))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing CSV file: {str(e)}")

    # Xử lí tham số đầu vào
    start_time = datetime.strptime(start_time, '%Y/%m/%d %H:%M:%S') if start_time else global_df['Timestamp'].min()
    end_time = datetime.strptime(end_time, '%Y/%m/%d %H:%M:%S') if end_time else global_df['Timestamp'].max()
    # time_sign='h'

    # Generate network graph and add to results
    try:
        graph_data = generate_network_graph(global_df)
        results.append(graph_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Analyze IP flows and add to results
    try:
        graph_data = analyze_ip_flows(global_df)
        results.append(graph_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Count events and add to results
    try:
        event_count = num_event(global_df)
        results.append(event_count)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot traffic trend and add to results
    try:
        traffic_trend = plot_traffic_trend(global_df, time_sign, start_time, end_time)
        results.append(traffic_trend)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot time sum column trend and add to results
    try:
        # column = Time_Delta or Totlen Pkts
        column = 'Time_Delta'
        time_sum_column_trend = plot_time_sum_column_trend(global_df, column, time_sign, start_time, end_time)
        results.append(time_sum_column_trend)

        column = 'Totlen Pkts'
        time_sum_column_trend = plot_time_sum_column_trend(global_df, column, time_sign, start_time, end_time)
        results.append(time_sum_column_trend)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Count artifacts and add to results
    try:
        artifact_count = count_artifacts(global_df)
        results.append(artifact_count)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot total length packets distribution and add to results
    try:
        pkt_distribution = plot_totlen_pkts_distribution(global_df, num_bins=8, start_time=start_time, end_time=end_time)
        results.append(pkt_distribution)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Get address distribution bar chart and add to results
    try:
        column = 'Source IP'
        address_distribution = plot_address_distribution_barchart(global_df, start_time=start_time, end_time=end_time, column=column)
        results.append(address_distribution)

        # Des ip
        column = 'Destination IP'
        address_distribution = plot_address_distribution_barchart(global_df, start_time=start_time, end_time=end_time, column=column)
        results.append(address_distribution)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot IP pairs by frame length and add to results
    try:
        ip_pairs_by_frame_len = plot_top_ip_pairs_by_frame_len(global_df, start_time, end_time)
        results.append(ip_pairs_by_frame_len)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Summarize columns and add to results
    try:
        column_summary = summarize_column(global_df)
        results.append(column_summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot protocol pie chart and add to results
    try:
        protocol_pie_chart = plot_protocol_pie_chart(global_df, start_time, end_time)
        results.append(protocol_pie_chart)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot column distribution bar chart and add to results
    # tab4/M3,4 column="Application Protocol" or "Source Port" or "Destination Port"
    try:
        column = 'Application Protocol'
        column_distribution = plot_column_distribution_barchart(global_df, start_time, end_time, column)
        results.append(column_distribution)

        column = 'Source Port'
        column_distribution = plot_column_distribution_barchart(global_df, start_time, end_time, column)
        results.append(column_distribution)

        column = 'Destination Port'
        column_distribution = plot_column_distribution_barchart(global_df, start_time, end_time, column)
        results.append(column_distribution)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Plot packets traffic trend and add to results
    try:
        column = 'TotLen Fwd Pkts'
        pkts_traffic_trend = plot_pkts_traffic_trend(global_df, column, time_sign, start_time, end_time)
        results.append(pkts_traffic_trend)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    try:
        column = 'TotLen Bwd Pkts'
        pkts_traffic_trend = plot_pkts_traffic_trend(global_df, column, time_sign, start_time, end_time)
        results.append(pkts_traffic_trend)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    
    # Generate IP map and add to results
    try:
        # geoip_db_path = './EDAXuan/nettraffic/GeoLite2-City.mmdb'
        # output_html_path = r"./EDAXuan/nettraffic/output/ip_map.html"
        result_path = generate_ip_map(global_df)
        # with open(result_path, 'r', encoding='utf-8') as file:
        #     html_content = file.read()
        results.append(result_path.to_dict(orient="records"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Trả về ngày giờ bất thường
        # Lấy các giá trị "Ngày/giờ" có sự kiện Anomaly là "Anomaly"
        # Tạo một cột mới lấy phần giờ từ cột 'Timestamp' sau khi cắt bỏ phút và giây
        # Tạo một cột mới lấy phần ngày và giờ (không bao gồm phút và giây)

    try:    
        combined_df['Anomaly_Min'] = combined_df['Timestamp'].str.slice(0, 16)  # Lấy định dạng "YYYY/MM/DD HH:MM"
        anomaly_hours = combined_df[combined_df['Label'] == "Anomaly"]['Anomaly_Min'].to_dict()
        # Lấy tất cả các giá trị từ dict
        # Lấy các giá trị duy nhất
        unique_values = sorted(list(set(anomaly_hours.values())))
        # Kiểm tra lại sau khi thao tác
        print("Traffic Các ngày/giờ có sự kiện Anomaly là 'Anomaly':", unique_values)
        results.append(unique_values)   
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# tab ALert
# M1. Thông tin chung
    try:
        alert_general_result= alert_general(combined_df)
        results.append(alert_general_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# M2. Alert Categories by Alert Count  
    try:
        alert_categories = bar_alert_categories(combined_df)
        results.append(alert_categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

# # M3. Top Alert-Generating Hosts
    try:
        alert_generating_hosts = bar_alert_generating_hosts(combined_df)
        results.append(alert_generating_hosts)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# # M4. Top Alert-receiving Hosts
    try:
        alert_receiving_hosts = bar_alert_receiving_hosts(combined_df)
        results.append(alert_receiving_hosts)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# M5. Top Alert-Generating Protocols
    try:
        alert_generating_protocol = pie_alert_generating_protocol(combined_df)
        results.append(alert_generating_protocol)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

    crud.create_traffic(db=db, traffic_data=results, file_path=file_location, file_name=network_filename)
    
    return results

    
@app.get("/traffic/{id}")
async def traffic(
    id: int,
    db: Session = Depends(get_db),
):
    traffic = crud.get_traffic(db, id)
    return traffic

@app.delete("/Traffic/delete/{traffic_id}", response_class=JSONResponse)
async def delete_traffic(traffic_id: int, db: Session = Depends(get_db)):
    traffic_entry = crud.delete_traffic(db=db, traffic_id=traffic_id)
    if traffic_entry is None:
        raise HTTPException(status_code=404, detail="Traffic entry not found")

    return {"message": "Traffic entry deleted successfully", "data": traffic_entry}

@app.get("/traffic")
async def traffic(
    search: str | None = "",
    page_index: int = 1,
    page_size: int = 10,
    db: Session = Depends(get_db),
):
    traffic = crud.get_traffics(db, page_size, (page_index - 1) * page_size)
    return traffic




#Log


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



@app.post("/log/upload_and_process/",response_class=JSONResponse)
async def upload_and_process_file(file: UploadFile = File(...),start_time: Optional[str] = None, end_time: Optional[str] = None, time_sign = "min", db: Session = Depends(get_db)):
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
    df['Line_cleaned'] = df['Line'].str.strip()
    command_results_cleaned = [line.strip() for line in command_results]
    df['Anomaly'] = df['Line_cleaned'].apply(lambda x: 'Anomaly' if x in command_results_cleaned else 'Normal')
    
    label_df=df['Anomaly']
    
    # os.remove(config_filename)
    # os.remove(output_command_name)
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
        # print("type dns: ",type(structured_log_df))
        # results = []
        structured_log_df = pd.concat([structured_log_df, label_df], axis=1)
        print("Trước khi thao tác:")
        print(structured_log_df['Anomaly'].value_counts())  # Kiểm tra số lượng giá trị "Anomaly" ban đầu
        append_structure_log= structured_log_df.to_json(orient="records")
        results.append(json.loads(append_structure_log))

        structured_log_df['Timestamp'] = pd.to_datetime(structured_log_df['Timestamp'])
        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y/%m/%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y/%m/%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        
        # Biểu đồ phân bố template
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        a=event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_json(orient='records')
        results.append(json.loads(a))
        # Biểu đồ đếm sự kiện theo thời gian

        event_count = plot_traffic_trend(structured_log_df, time_sign, start_time, end_time)
        results.append(event_count)

        # Biểu đồ phân bố IP

        ip_distribution = plot_ip_distribution(structured_log_df, start_time, end_time)
        results.append(ip_distribution)

        # Biểu đồ phân bố DNS query
        dns_query_distribution = plot_dns_query_distribution(structured_log_df, start_time, end_time)
        results.append(dns_query_distribution)

        # Trả về ngày và giờ có sự kiện bất thường
        # Lấy các giá trị "Ngày/giờ" có sự kiện Anomaly là "Anomaly"
        # Tạo một cột mới lấy phần giờ từ cột 'Timestamp' sau khi cắt bỏ phút và giây
        # Tạo một cột mới lấy phần ngày và giờ (không bao gồm phút và giây)
        structured_log_df['Anomaly_Min'] = structured_log_df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M')  # Lấy định dạng "YYYY/MM/DD HH"
        print(structured_log_df)
        anomaly_hours = structured_log_df[structured_log_df['Anomaly'] == "Anomaly"]['Anomaly_Min'].to_dict()
        # Lấy tất cả các giá trị từ dict
        # Lấy các giá trị duy nhất
        unique_values = sorted(list(set(anomaly_hours.values())))
        # Kiểm tra lại sau khi thao tác
        print("DNS Các ngày/giờ có sự kiện Anomaly là 'Anomaly':", unique_values)
        for _ in range(5):
            results.append([])
        results.append(unique_values)

# ALert
# M1Alert. Thông tin chung
        result = log_alert_general(structured_log_df)
        results.append(result)
#M2Alert. Thông tin sự kiện theo loại bất thường
        result = log_bar_alert_categories(structured_log_df)
        results.append(result)


        # return JSONResponse(content=results)

        ## Audit

    elif log_type == "audit":
        # Nếu log_type là "audit", xử lý và vẽ biểu đồ
        structured_log_df, templates_log_df = process_log_files_audit(log_dir, log_filename)
        # results = []
        structured_log_df = pd.concat([structured_log_df, label_df], axis=1)
        
        a=structured_log_df.to_json(orient="records")

        a=json.loads(a)
        results.append(a)
        structured_log_df['Timestamp'] = pd.to_datetime(structured_log_df['Timestamp'])
        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y/%m/%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y/%m/%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        # time_sign='h'

        # Biểu đồ phân bố template
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        # results.append(event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'})
        a=event_distribution.to_json(orient='records')
        a=json.loads(a)
        results.append(a)
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
        ip_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(ip_distribution)

        column= "acct"
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        column= "pid"
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        column= "uid"
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

        column= "exe"
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
        results.append(column_distribution)

  # M4      
        # column_distribution = plot_account_activity_over_time(structured_log_df, account = '', time_sign, start_time, end_time)
        # column_distribution = plot_account_activity_over_time(structured_log_df, '', time_sign, start_time, end_time)
        # results.append(column_distribution)
# M5
        column_distribution=classify_and_plot(structured_log_df, start_time, end_time)
        results.append(column_distribution)

# Trả về ngày giờ bất thường
        # Lấy các giá trị "Ngày/giờ" có sự kiện Anomaly là "Anomaly"
        # Tạo một cột mới lấy phần giờ từ cột 'Timestamp' sau khi cắt bỏ phút và giây
        # Tạo một cột mới lấy phần ngày và giờ (không bao gồm phút và giây)
        
        structured_log_df['Anomaly_Min'] = structured_log_df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M')  # Lấy định dạng "YYYY/MM/DD HH"
        print(structured_log_df)
        anomaly_hours = structured_log_df[structured_log_df['Anomaly'] == "Anomaly"]['Anomaly_Min'].to_dict()
        # Lấy tất cả các giá trị từ dict
        # Lấy các giá trị duy nhất
        unique_values = sorted(list(set(anomaly_hours.values())))
        # Kiểm tra lại sau khi thao tác
        print("Audit Các ngày/giờ có sự kiện Anomaly là 'Anomaly':", unique_values)
        results.append([])
        results.append(unique_values)

# ALert
# M1Alert.Thông tin chung
        result = log_alert_general(structured_log_df)
        results.append(result)
#M2Alert. Thông tin sự kiện theo loại bất thường
        result = log_bar_alert_categories(structured_log_df)
        results.append(result)

    elif log_type == "access":
        # Nếu log_type là "acccess", xử lý và vẽ biểu đồ
        structured_log_df, templates_log_df = process_log_files_access(log_dir, log_filename)
        # results = []
        structured_log_df = pd.concat([structured_log_df, label_df], axis=1)
        # Bảng
        a=structured_log_df.to_json(orient="records")
        a=json.loads(a)
        results.append(a)
        
        structured_log_df['Timestamp'] = pd.to_datetime(structured_log_df['Timestamp'])
        # Xử lí tham số đầu vào
        start_time = datetime.strptime(start_time, '%Y/%m/%d %H:%M:%S') if start_time else structured_log_df['Timestamp'].min()
        end_time = datetime.strptime(end_time, '%Y/%m/%d %H:%M:%S') if end_time else structured_log_df['Timestamp'].max()
        # time_sign='h'

        # Biểu đồ phân bố template
        # M1
        event_distribution = templates_log_df.groupby('EventTemplate')['Occurrences'].sum().reset_index()
        # results.append(event_distribution.rename(columns={'EventTemplate': 'name', 'Occurrences': 'uv'}).to_json(orient='records'))
        a=json.loads(event_distribution.to_json(orient='records'))
        results.append(a)
        # Biểu đồ đếm sự kiện theo thời gian
        # M2
        event_count = plot_log_trend(structured_log_df, time_sign, start_time, end_time)
        results.append(event_count)

#M3. Bar chart Phân bố Client_IP, User_Agent theo top column = Client_IP or User_Agent (M6_dạng bảng)
        column= "Client_IP"
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
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
        column_distribution = bar_column_distribution(structured_log_df, column, start_time, end_time)
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

        # Trả về ngày và giờ có sự kiện bất thường
        # Lấy các giá trị "Ngày/giờ" có sự kiện Anomaly là "Anomaly"
        # Tạo một cột mới lấy phần giờ từ cột 'Timestamp' sau khi cắt bỏ phút và giây
        # Tạo một cột mới lấy phần ngày và giờ (không bao gồm phút và giây)
        
        structured_log_df['Anomaly_Min'] = structured_log_df['Timestamp'].dt.strftime('%Y/%m/%d %H:%M')  # Lấy định dạng "YYYY/MM/DD HH"
        print(structured_log_df)
        anomaly_hours = structured_log_df[structured_log_df['Anomaly'] == "Anomaly"]['Anomaly_Min'].to_dict()
        # Lấy tất cả các giá trị từ dict
        # Lấy các giá trị duy nhất
        unique_values = sorted(list(set(anomaly_hours.values())))
        # Kiểm tra lại sau khi thao tác
        print("Access Các ngày/giờ có sự kiện Anomaly là 'Anomaly':", unique_values)
        results.append(unique_values)

# ALert
# Thông tin chung M1
        result = log_alert_general(structured_log_df)
        results.append(result)
#Thông tin sự kiện theo loại bất thường
        result = log_bar_alert_categories(structured_log_df)
        results.append(result)

        # return JSONResponse(content=results)
    crud.create_log(db=db,log_data=results,file_path=file_location,file_name=log_filename,type_log=log_type)
    # os.remove()  
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
    Log_entry = crud.delete_Log(db=db,log_id=id)
    if Log_entry is None:
        raise HTTPException(status_code=404, detail="Traffic entry not found")

    return {"message": "Traffic entry deleted successfully", "data": Log_entry}

@app.get("/log")
async def log(
    search: str | None = "",
    page_index: int = 1,
    page_size: int = 10,
    db: Session = Depends(get_db),
):
    log = crud.get_logs(db, page_size, (page_index - 1) * page_size)
    return log
