import pandas as pd
import subprocess
import os
import time
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

# Đường dẫn trực tiếp đến file model
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/RF_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/KNN_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/LGB_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/SKGB_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/CB_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/XGB_10.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/modelCLFCICnew.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/modelCLFCICnew_NewData.pkl"
# MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/modelCLFCICnew_NewData_deep58.pkl"
MODEL_PATH = "/home/vothuonghd1998/BEdoan/Sang/modelCLFCICnew_NewData_deep58_3.pkl"

# sc=joblib.load("/home/vothuonghd1998/BEdoan/Sang/scalerCIC.pkl")
sc=joblib.load("/home/vothuonghd1998/BEdoan/Sang/scalerCIC_NewData.pkl")

# Load mô hình ngay khi import module


def convert_pcap_to_csv(pcap_file_path: str, output_dir: str) -> str:
    csv_file_path = os.path.join(output_dir, f"{os.path.basename(pcap_file_path)}_Flow.csv")
    
    convert_command = (
        f"sudo java "
        f"-Djava.library.path=/home/vothuonghd1998/BEdoan/CICFlowMeter40/lib/native "
        f"-cp /home/vothuonghd1998/BEdoan/CICFlowMeter40/bin:/home/vothuonghd1998/BEdoan/CICFlowMeter40/lib/* "
        f"cic.cs.unb.ca.ifm.Cmd {pcap_file_path} {output_dir}"
    )
    
    process = subprocess.Popen(convert_command, shell=True)
    wait_for_csv_completion(csv_file_path, process)
    
    return csv_file_path

def wait_for_csv_completion(csv_file_path: str, process, interval: int = 5, max_attempts: int = 3):
    attempts = 0
    last_size = -1

    while attempts < max_attempts:
        time.sleep(interval)
        if os.path.exists(csv_file_path):
            current_size = os.path.getsize(csv_file_path)
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

def read_csv_to_dataframe(csv_file_path: str) -> pd.DataFrame:
    if os.path.exists(csv_file_path):
        df = pd.read_csv(csv_file_path)
        return df
    else:
        raise FileNotFoundError(f"CSV file not found at {csv_file_path}")
    
def predict_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """
    Dự đoán nhãn bất thường cho DataFrame dựa trên mô hình đã train.
    
    :param df: DataFrame chứa dữ liệu để dự đoán
    :param model: Mô hình RandomForest đã train
    :return: DataFrame với cột Label đã được cập nhật
    """
    df1=df
    model = joblib.load(MODEL_PATH)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    df["time"] = df["Timestamp"].dt.hour * 3600 + df["Timestamp"].dt.minute * 60 + df["Timestamp"].dt.second

    # Chỉ lấy các cột cần thiết để dự đoán
    # features = ['Src Port', 'Flow Duration', 'Bwd Pkt Len Min', 'Flow Pkts/s', 
    #             'Flow IAT Mean', 'Flow IAT Max', 'Bwd IAT Tot', 
    #             'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Std']
    # X = df[features]

    # featurenew = [
    # 'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 
    # 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Std', 'Bwd Pkt Len Std', 
    # 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Std', 'Fwd IAT Std', 'Bwd IAT Std', 
    # 'Fwd PSH Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 
    # 'Bwd Pkts/s', 'Pkt Len Std', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 
    # 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'ECE Flag Cnt', 
    # 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 
    # 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 
    # 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 
    # 'Active Std', 'Idle Std', 'time'
    # ]

    X_new_feature = [
    'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Std', 'Bwd Pkt Len Std', 'Flow Byts/s',
    'Flow Pkts/s', 'Flow IAT Std', 'Fwd IAT Std', 'Bwd IAT Std', 'Bwd PSH Flags', 'Fwd Header Len',
    'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Std', 'FIN Flag Cnt', 'SYN Flag Cnt',
    'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
    'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts',
    'Subflow Bwd Byts', 'Fwd Act Data Pkts', 'Active Std', 'Idle Std', 'time'
]

    X_new = df[X_new_feature]
    # Giả sử X_new là DataFrame
    X_new.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Sau đó, xử lý NaN (bạn có thể thay thế bằng giá trị trung bình hoặc loại bỏ hàng/cột chứa NaN)
    X_new.fillna(X_new.mean(), inplace=True)
    # Dự đoán với mô hình RandomForest
    # predictions = model.predict(X)
    X_dataprediction=sc.transform(X_new)
    # X_dataprediction=X_new
    predictions = model.predict(X_dataprediction)
    conferren_score=model.predict_proba(X_dataprediction)

    # Cập nhật cột Label dựa trên dự đoán
    df['Label'] = ['Normal' if pred == 0 else 'Anomaly' for pred in predictions]
    df1['Label']=df['Label']
    df['Conference'] = [float(conferrnescore[1]) for conferrnescore in conferren_score]
    df1['Conference'] = df['Conference']
    print(df['Conference'].dtype)
    print(conferren_score)

    return df1

