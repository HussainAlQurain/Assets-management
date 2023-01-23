from ast import Str
from turtle import color
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import pymssql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import sqlalchemy as db

Base = declarative_base()
app = Flask(__name__)

engine = db.create_engine(
    "mssql+pymssql://AHALGOSAIBI\hqurain:Zerrr123!@AHAB-HR-01/Inhouse_App")

# CREATE THE TABLE MODEL TO USE IT FOR QUERYING
class Requests(Base):
 
    __tablename__ = 'Mobile'
 
    id = db.Column(db.INT,
                           primary_key=True)
    name = db.Column(db.String(255))
    model = db.Column(db.String(255))
    color = db.Column(db.String(50))
    
    def __repr__(self):
        return f"{self.name} {self.model} {self.color}"

    def __init__(self, id, name, model, color):
        self.id = id
        self.name = name
        self.model = model
        self.color = color
        
def format_event(event):
    return {
        "name": Requests.id,
        "model": Requests.model,
        "color": Requests.color
    }

# CREATE A SESSION OBJECT TO INITIATE QUERY
# IN DATABASE
Session = sessionmaker(bind=engine)
session = Session()

@app.route('/')
def hello():
    return "Hello"

@app.route('/mobile', methods=['POST'])
def create_mobile():
    return


@app.route('/mobiles', methods=['GET'])
def get_events():
    events = session.query(Requests).all()
    return str(events)
    

if __name__ == '__main__':
    app.run()

