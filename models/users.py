from sqlalchemy import Column, Integer, String, Boolean
from app import db_connect


class User(db_connect.Model):
    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), unique=True)
    name = Column(String(50))
    password = Column(String(80))
    admin = Column(Boolean)
    read_only = Column(Boolean)
    disabled = Column(Boolean)
    info = Column(String(256))


class Connection(db_connect.Model):
    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), unique=True)
    username = Column(String(50))
    password = Column(String(50))
    database = Column(String(50))
