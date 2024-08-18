from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import shutil
import subprocess
import os
import random
import string
import yaml
import time

app = FastAPI()

# Cài đặt đường dẫn tới templates và static  files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Đường dẫn tới file config mẫu
TEMPLATE_CONFIG_PATH = "/etc/aminer/config.yml"

# Đường dẫn tới file lưu trữ giá trị của `i`
COUNTER_FILE = "counter.txt"

# Hàm để đọc và tăng giá trị của `i`
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

# Mỗi lần khởi động backend, giá trị `i` sẽ được cập nhật
output_counter = get_next_counter_value()

# Mật khẩu sudo (Không khuyến nghị lưu mật khẩu như thế này)
SUDO_PASSWORD = "1"

def modify_config_and_run(file_location: str, output_command_name: str):
    global output_counter

    # Tạo thư mục lưu file .yml
    yml_dir = f"yml{output_counter}"
    os.makedirs(yml_dir, exist_ok=True)

    # Sao chép file config gốc và đổi tên ngẫu nhiên
    random_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".yml"
    config_path = os.path.join(yml_dir, random_filename)
    shutil.copyfile(TEMPLATE_CONFIG_PATH, config_path)
    
    # Đọc nội dung file config gốc và sửa đổi
    with open(config_path, "r") as config_file:
        config_content = yaml.safe_load(config_file)
    
    # Thêm đường dẫn log mới vào LogResourceList
    if 'LogResourceList' in config_content and isinstance(config_content['LogResourceList'], list):
        config_content['LogResourceList'].append(f"file://{file_location}")
    else:
        config_content['LogResourceList'] = [f"file://{file_location}"]
    
    # Ghi lại file config mới
    with open(config_path, "w") as config_file:
        yaml.dump(config_content, config_file, default_flow_style=False, sort_keys=False)
    
    # Chạy chương trình aminer với file config vừa tạo và ghi kết quả vào file outputcommand.txt
    command = f"echo {SUDO_PASSWORD} | sudo -S aminer -c {config_path} >> {output_command_name}"
    aminer_process = subprocess.Popen(command, shell=True)
    
    return config_path, yml_dir, aminer_process

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
    
    # Nếu không có thay đổi sau max_attempts lần kiểm tra, dừng tiến trình aminer
    if attempts >= max_attempts:
        process.terminate()
        process.wait()

@app.post("/upload", response_class=HTMLResponse)
async def upload_file(request: Request, background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    global output_counter
    file_location = f"/home/trung/Desktop/sang/test/{file.filename}"
    
    # Lưu file đã upload lên server
    with open(file_location, "wb+") as file_object:
        file_object.write(file.file.read())
    
    # Tạo tên file output và anomaly
    output_command_name = f"outputcommand{output_counter}.txt"
    anomaly_file_name = f"anomaly{output_counter}.txt"

    # Sửa đổi cấu hình và chạy tiến trình phân tích
    config_filename, yml_dir, aminer_process = modify_config_and_run(file_location, output_command_name)
    
    # Dừng lệnh aminer nếu không có thay đổi trong file outputcommand.txt
    stop_if_no_change(output_command_name, aminer_process)
    
    # Đọc nội dung file outputcommand.txt
    if not os.path.exists(output_command_name):
        return "Không tìm thấy file outputcommand.txt"
    
    with open(output_command_name, "r") as f:
        command_results = f.readlines()
    
    # So sánh và xác định các dòng bất thường
    abnormal_lines = []
    with open(file_location, "r") as infile, open(anomaly_file_name, "w") as anomaly_file:
        uploaded_file_content = infile.readlines()
        for line in uploaded_file_content:
            if line in command_results:
                anomaly_file.write(line)
                abnormal_lines.append(f"<tr style='color:red'><td>{line}</td></tr>")
    
    # Xóa các file log tạm thời sau khi xử lý xong
    background_tasks.add_task(os.remove, file_location)
    
    # Tăng biến đếm để tạo tên file output và anomaly tiếp theo
    output_counter += 1
    
    # Trả về kết quả trên giao diện web và cho phép upload file mới
    return templates.TemplateResponse("result.html", {"request": request, "results": abnormal_lines})

@app.get("/", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
