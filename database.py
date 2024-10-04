from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import sqlalchemy as sa

DATABASE_URL = sa.engine.URL.create(
    drivername="mysql+pymysql",
    username="root",
    password="1",
    host="34.170.214.142",
    port="3306",
    database="dbforensic",
)

engine = create_engine(
    DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()