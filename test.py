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
from Sang.pcaptpCSV import convert_pcap_to_csv, read_csv_to_dataframe, predict_anomalies

app = FastAPI()

TEMPLATE_CONFIG_PATH = "../BEdoan/huongdancaidat/config.yml"
COUNTER_FILE = "counter.txt"
df = None
processed_data = None  # Biến toàn cục để lưu trữ dữ liệu đã xử lý

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

def wait_for_csv_completion(csv_file_location: str, process, interval: int = 5, max_attempts: int = 3):
    attempts = 0
    last_size = -1

    while attempts < max_attempts:
        time.sleep(interval)
        if os.path.exists(csv_file_location):
            current_size = os.path.getsize(csv_file_location)
            if current_size == last_size:
                attempts += 1
            else:
                attempts = 0
            last_size = current_size
        else:
            last_size = -1
        
        if attempts >= max_attempts:
            print("CSV file creation completed.")
            process.terminate()
            process.wait()
            break

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
    log_array = df.to_dict(orient="records")
    return log_array

@app.post("/upload", response_class=JSONResponse)
async def upload_file(file: UploadFile = File(...)):
    global df, processed_data
    global output_counter
    file_location = f"/home/vothuonghd1998/database/{file.filename}"
    file_output = f"/home/vothuonghd1998/database/"
    
    try:
        with open(file_location, "wb+") as file_object:
            file_object.write(file.file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
    
    if ".pcap" in file.filename:
        csv_file_location = convert_pcap_to_csv(file_location, file_output)
        df = read_csv_to_dataframe(csv_file_location)
        df = predict_anomalies(df)
        
        selected_columns = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Label']
        df = df[selected_columns]
        
        network_matrix = generate_network_matrix(df)
        processed_data = network_matrix  # Lưu dữ liệu đã xử lý
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
        
        os.remove(file_location)
        
        output_counter += 1
        log_array = generate_log_array(df)
        processed_data = log_array  # Lưu dữ liệu đã xử lý
        return JSONResponse(content=log_array)

@app.get("/getupload", response_class=JSONResponse)
async def get_upload_data():
    if processed_data is None:
        raise HTTPException(status_code=404, detail="No data available. Please upload a file first.")
    return JSONResponse(content=processed_data)

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

    result_df = df[df[field].astype(str).str.contains(value, case=False, na=False)]

    if result_df.empty:
        return JSONResponse(content={"message": "No matching data found."})

    return JSONResponse(content=result_df.to_dict(orient="records"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)
