from sqlalchemy.orm import sessionmaker
import sqlalchemy as db
from sqlalchemy.ext.declarative import declarative_base
import pymssql
Base = declarative_base()
 
# DEFINE THE ENGINE (CONNECTION OBJECT)
engine = db.create_engine(
    "mssql+pymssql://AHALGOSAIBI\hqurain:Zerrr123!@AHAB-HR-01/Inhouse_App")
 
# CREATE THE TABLE MODEL TO USE IT FOR QUERYING
class Requests(Base):
 
    __tablename__ = 'Requests'
 
    requestNo = db.Column(db.INT,
                           primary_key=True)
    empNO = db.Column(db.String(50))
    name = db.Column(db.String(50))
    category = db.Column(db.String(50))
    description = db.Column(db.String(50))
    deptName = db.Column(db.String(50))
    
 
 
# CREATE A SESSION OBJECT TO INITIATE QUERY
# IN DATABASE
Session = sessionmaker(bind=engine)
session = Session()
 
# SELECT first_name FROM students
result = session.query(Requests.requestNo)
print("Query 1:", result)
 
# SELECT first_name, last_name, course
# FROM students
result = result.add_columns(Requests.name,
                            Requests.description)
print("Query 2:", result)
 
# VIEW THE ENTRIES IN THE RESULT
for r in result:
    print(r.requestNo, "|", r.name, "|", r.description)