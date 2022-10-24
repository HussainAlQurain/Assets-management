import pyodbc
import os
from dotenv import load_dotenv

load_dotenv()

def connection():
    s = os.getenv('SERVER_NAME') #Your server name 
    d = os.getenv('DATABASE_NAME') 
    u = os.getenv('USER_NAME') #Your login
    p = os.getenv('PASS') #Your login password
    cstr = 'DRIVER={SQL Server Native Client 11.0};SERVER='+s+';DATABASE='+d+';UID='+u+';PWD='+p+';Trusted_connection=yes'
    conn = pyodbc.connect(cstr)
    return conn


def search_employee(id):

    try:
        id = str(id)
    except:
        raise Exception("ID must contain numbers only")

    
    info = {}
    con = connection()
    cursor = con.cursor()
    cursor.execute("SELECT * FROM dbo.Employees where EmployeeNo = ?",id)
    result = cursor.fetchone()
    if result == None:
        raise Exception("no Employee found")
    info['name'] = result[2]
    info['department'] = result[3]

    #return name and department in a dictionary
    return info




if __name__ == '__main__':
    pass