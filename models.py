from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, JSON, Text
from sqlalchemy.orm import relationship

from database import Base

class Traffic(Base):
    __tablename__ = "traffic"

    id = Column(Integer, primary_key=True)
    typeLog = Column(String(255))
    filePath = Column(String(255))
    filename = Column(String(255))
    m1 = Column(JSON)  # JSON object cho phần tử 1 (Danh sách các lưu lượng mạng)
    m2 = Column(JSON)  # JSON object cho phần tử 2 (Biểu đồ mạng)
    m3 = Column(JSON)  # JSON object cho phần tử 3 (Flows mạng)
    m4 = Column(JSON)  # JSON object cho phần tử 4 (Số lượng sự kiện)
    m5 = Column(JSON)  # JSON object cho phần tử 5 (Xu hướng lưu lượng)
    m6 = Column(JSON)  # JSON object cho phần tử 6 (HTTP response 1)
    m7 = Column(JSON)  # JSON object cho phần tử 7 (HTTP response 2)
    m8 = Column(JSON)  # JSON object cho phần tử 8 (Thông tin thống kê IP)
    m9 = Column(JSON)  # JSON object cho phần tử 9 (Phân phối kích thước gói tin)
    m10 = Column(JSON)  # JSON object cho phần tử 10 (Dữ liệu IP nguồn)
    m11 = Column(JSON)  # JSON object cho phần tử 11 (Dữ liệu IP đích)
    m12 = Column(JSON)  # JSON object cho phần tử 12 (Dữ liệu flows giữa IP)
    m13 = Column(JSON)  # JSON object cho phần tử 13 (Thông tin về thời lượng)
    m14 = Column(JSON)  # JSON object cho phần tử 14 (Biểu đồ tròn giao thức mạng)
    m15 = Column(JSON)  # JSON object cho phần tử 15 (Dữ liệu giao thức mạng)
    m16 = Column(JSON)  # JSON object cho phần tử 16 (Dữ liệu cổng nguồn)
    m17 = Column(JSON)  # JSON object cho phần tử 17 (Dữ liệu cổng đích)
    m18 = Column(JSON)  # JSON object cho phần tử 18 (Xu hướng lưu lượng gói tin 1)
    m19 = Column(JSON)  # JSON object cho phần tử 19 (Xu hướng lưu lượng gói tin 2)
    m20 = Column(JSON)  # HTML block cho phần tử 20 (Bản đồ IP)
    m21 = Column(JSON) # Time có sự kiện bất thường
    m22 = Column(JSON) # Time có sự kiện bất thường
    m23 = Column(JSON) # Time có sự kiện bất thường
    m24 = Column(JSON) # Time có sự kiện bất thường
    m25 = Column(JSON) # Time có sự kiện bất thường
    m26 = Column(JSON) # Time có sự kiện bất thường
    # m27 = Column(JSON) # Time có sự kiện bất thường
    # m28 = Column(JSON) # Time có sự kiện bất thường

class Log(Base):
    __tablename__ = "log"

    id = Column(Integer, primary_key=True)
    typeLog = Column(String(255))
    filePath = Column(String(255))
    filename = Column(String(255))
    m1 = Column(JSON)
    m2 = Column(JSON)
    m3 = Column(JSON)
    m4 = Column(JSON)
    m5 = Column(JSON)
    m6 = Column(JSON)
    m7 = Column(JSON)
    m8 = Column(JSON)
    m9 = Column(JSON)
    m10 = Column(JSON)
    m11 = Column(JSON)
    m12 = Column(JSON)
    m13 = Column(JSON)