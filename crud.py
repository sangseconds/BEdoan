from sqlalchemy.orm import Session

import models

def get_traffic(db: Session, id: int):
    return db.query(models.Traffic).filter(models.Traffic.id == id).first()
def get_log(db: Session, id: int):
    return db.query(models.Log).filter(models.Log.id == id).first()

# def get_traffics(db: Session, limit: int = 10, offset: int = 0):
#     return db.query(models.Traffic).offset(offset).limit(limit).all()
def get_traffics(db: Session, limit: int = 10, offset: int = 0):
    results = db.query(models.Traffic.id, models.Traffic.filename).offset(offset).limit(limit).all()
    return [{"id": r[0], "filename": r[1]} for r in results]


# def get_logs(db: Session, limit: int = 10, offset: int = 0):
#     return db.query(models.Log).offset(offset).limit(limit).all()          
def get_logs(db: Session, limit: int = 10, offset: int = 0):
    results = db.query(models.Log.id, models.Log.filename).offset(offset).limit(limit).all()
    return [{"id": r[0], "filename": r[1]} for r in results]



#Traffic

def create_traffic(db: Session, traffic_data: dict, file_path: str, file_name: str):
    db_traffic = models.Traffic(
        typeLog="",
        filePath=file_path,
        filename=file_name,
        m1=traffic_data[0],  # List of JSON objects
        m2=traffic_data[1],  # JSON object
        m3=traffic_data[2],  # JSON object
        m4=traffic_data[3],  # JSON object
        m5=traffic_data[4],  # JSON object
        m6=traffic_data[5],  # JSON object
        m7=traffic_data[6],  # JSON object
        m8=traffic_data[7],  # JSON object
        m9=traffic_data[8],  # JSON object
        m10=traffic_data[9],  # JSON object
        m11=traffic_data[10],  # JSON object
        m12=traffic_data[11],  # JSON object
        m13=traffic_data[12],  # JSON object
        m14=traffic_data[13],  # JSON object
        m15=traffic_data[14],  # JSON object
        m16=traffic_data[15],  # JSON object
        m17=traffic_data[16],  # JSON object
        m18=traffic_data[17],  # JSON object
        m19=traffic_data[18],  # JSON object
        m20=traffic_data[19],  # HTML block
        m21=traffic_data[20] if len(traffic_data) > 20 else None,  # HTML block
        m22=traffic_data[21] if len(traffic_data) > 21 else None ,  # HTML block
        m23=traffic_data[22] if len(traffic_data) > 22 else None ,  # HTML block
        m24=traffic_data[23] if len(traffic_data) > 23 else None ,  # HTML block
        m25=traffic_data[24] if len(traffic_data) > 24 else None ,  # HTML block
        m26=traffic_data[25] if len(traffic_data) > 25 else None   # HTML block
        # m27=traffic_data[26] if len(traffic_data) > 26 else None ,  # HTML block
        # m28=traffic_data[27] if len(traffic_data) > 27 else None  # HTML block

    )
    db.add(db_traffic)
    db.commit()
    db.refresh(db_traffic)
    return db_traffic

def delete_traffic(db: Session, traffic_id: int):
    # Lấy bản ghi cần xóa từ cơ sở dữ liệu
    db_traffic = db.query(models.Traffic).filter(models.Traffic.id == traffic_id).first()
    if db_traffic is None:
        return None

    # Xóa bản ghi khỏi cơ sở dữ liệu
    db.delete(db_traffic)
    db.commit()
    return db_traffic

#Log

def create_log(db: Session, log_data: dict, file_path: str, file_name: str, type_log: str):
    db_log = models.Log(
        typeLog=type_log,
        filePath=file_path,
        filename=file_name,
        m1=log_data[0] if len(log_data) > 0 else None,
        m2=log_data[1] if len(log_data) > 1 else None,
        m3=log_data[2] if len(log_data) > 2 else None,
        m4=log_data[3] if len(log_data) > 3 else None,
        m5=log_data[4] if len(log_data) > 4 else None,
        m6=log_data[5] if len(log_data) > 5 else None,
        m7=log_data[6] if len(log_data) > 6 else None,
        m8=log_data[7] if len(log_data) > 7 else None,
        m9=log_data[8] if len(log_data) > 8 else None,
        m10=log_data[9] if len(log_data) > 9 else None,
        m11=log_data[10] if len(log_data) > 10 else None,
        m12=log_data[11] if len(log_data) > 11 else None,
        m13=log_data[12] if len(log_data) > 12 else None,
        
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


def delete_Log(db: Session, log_id: int):
    # Lấy bản ghi cần xóa từ cơ sở dữ liệu
    db_Log = db.query(models.Log).filter(models.Log.id == log_id).first()
    if db_Log is None:
        return None

    # Xóa bản ghi khỏi cơ sở dữ liệu
    db.delete(db_Log)
    db.commit()
    return db_Log