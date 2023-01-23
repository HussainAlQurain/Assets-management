from encodings.utf_8_sig import encode
import json
from sqlite3 import connect
from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyodbc
import datetime
from myModules import searchEmp
#import sys

###
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
###

import os
from dotenv import load_dotenv
import io
import csv
from flask import make_response


load_dotenv()
#
csv_list = []
selected_date = ''
#
mobiles = Flask(__name__)

###
db = SQLAlchemy(mobiles)
bcrypt = Bcrypt(mobiles)
mobiles.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
mobiles.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
mobiles.config['SESSION_TYPE'] = 'filesystem'



login_manager = LoginManager()
login_manager.init_app(mobiles)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')






@mobiles.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@mobiles.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    return render_template('dashboard.html', info=info[0])


@mobiles.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#@mobiles.route('/register', methods=['GET', 'POST'])
#def register():
    #form = RegisterForm()

    #if form.validate_on_submit():
        #hashed_password = bcrypt.generate_password_hash(form.password.data)
        #new_user = User(username=form.username.data, password=hashed_password)
        #db.session.add(new_user)
        #db.session.commit()
        #return redirect(url_for('login'))

    #return render_template('register.html', form=form)

###
def connection():
    s = os.getenv('SERVER_NAME') #Your server name 
    d = os.getenv('DATABASE_NAME') 
    u = os.getenv('USER_NAME') #Your login
    p = os.getenv('PASS') #Your login password
    cstr = 'DRIVER={SQL Server};SERVER='+s+';DATABASE='+d+';UID='+u+';PWD='+p+';Trusted_connection=yes'
    conn = pyodbc.connect(cstr)
    return conn

@mobiles.route("/")
def home():
    return redirect('/login')


@mobiles.route("/Mobiles")
@login_required
def main():

    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    if current_user.username != 'admin':
        return "Admin privileges required"
    mobiles = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dbo.Mobile")
    for row in cursor.fetchall():
        mobiles.append({"id": row[0], "name": row[1], "model": row[2], "color": row[3], "empID": row[4], "serial_id": row[5], "history": row[6]})
    conn.close()
    return render_template("Mobile.html", mobiles = mobiles, info=info[0])

@mobiles.route('/updatemobile/<int:id>',methods = ['GET','POST'])
@login_required
def updatemobile(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    mobile = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Mobile WHERE id = ?", id)
        for row in cursor.fetchall():
            mobile.append({"id": row[0], "name": row[1], "model": row[2], "color": row[3], "empID": row[4], "serial_id": row[5], "history": row[6]})
        conn.close()
        return render_template("updatemobile.html", mobile = mobile[0])
    if request.method == 'POST':
        empID = str(request.form["empID"])
        name = str(request.form["name"])
        model = str(request.form["model"])
        color = str(request.form["color"])
        serial_id = str(request.form["serial_id"])
        history = str(request.form["history"])
        #save history automatically

        index = 0
        count = 0
        cursor.execute("select name from dbo.Mobile where id = ?", id)
        prvname = cursor.fetchone()
        prvname = prvname[0]
        if prvname in history:
            pass
        else:
            history = prvname + ', ' + history
#save three previous users
        for x in history:
            if x == ',':
                count += 1
    
            if count == 10:
                break
            
            index += 1
        history = history[0: index:] + history[len(history) + 1::]

        ###
        cursor.execute("UPDATE dbo.Mobile SET name = ?, model = ?, color = ?, empID = ?, serial_id = ?, history = ? WHERE id = ?", name, model, color, empID, serial_id, history, id)
        conn.commit()
        conn.close()
        return redirect('/Mobiles')

@mobiles.route('/deletemobile/<int:id>')
@login_required
def deletemobile(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dbo.Mobile WHERE id = ?", id)
    conn.commit()
    conn.close()
    return redirect('/Mobiles')


@mobiles.route('/addmobile/',methods = ['GET','POST'])
@login_required
def addmobile():
    if current_user.username != 'admin':
        return "Admin privileges required"
    mobile = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Mobile")
        for row in cursor.fetchall():
            mobile.append({"id": row[0], "name": row[1], "model": row[2], "color": row[3], "empID": row[4], "serial_id": row[5], "history": row[6]})
        conn.close()
        return render_template("addmobile.html", mobile = [])
    if request.method == 'POST':
        empID = str(request.form["empID"])
        name = str(request.form["name"])
        model = str(request.form["model"])
        color = str(request.form["color"])
        serial_id = str(request.form["serial_id"])
        history = str(request.form["history"])
        cursor.execute("INSERT INTO dbo.Mobile VALUES (?, ?, ?, ?, ?, ?)", name, model, color, empID, serial_id, history)
        conn.commit()
        conn.close()
        return redirect('/Mobiles')

#Computers 

@mobiles.route("/Computers")
@login_required
def computers():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    if current_user.username != 'admin':
        return "Admin privileges required"
    computers = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dbo.Workstation")
    for row in cursor.fetchall():
        computers.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23]})
    conn.close()
    return render_template("Computer.html", computers = computers, info = info[0])


@mobiles.route('/updatecomputer/<int:id>',methods = ['GET','POST'])
@login_required
def updatecomputer(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Workstation WHERE id = ?", id)
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23]})
        conn.close()
        return render_template("updatecomputer.html", computer = computer[0])
    if request.method == 'POST':
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = str(request.form["History"])
        empID = str(request.form["empID"])

        index = 0
        count = 0
        cursor.execute("select username from dbo.Workstation where id = ?", id)
        prvname = cursor.fetchone()
        prvname = prvname[0]
        if prvname in history:
            pass
        else:
            history = prvname + ', ' + history
#save three previous users
        for x in history:
            if x == ',':
                count += 1
    
            if count == 10:
                break
            
            index += 1
        history = history[0: index:] + history[len(history) + 1::]

        
        cursor.execute("UPDATE dbo.Workstation SET office = ?, department = ?, username = ?, computername = ?, computerbrand = ?, computermodel = ?, stsn = ?, os = ?, cpus = ?, ram = ?, hdsize = ?, hdtype = ?, officever = ?, adobe = ?, msprojects = ?, visio = ?, brand = ?, size = ?, travelport = ?, externalhd = ?, bag = ?, history = ?, empID = ? WHERE id = ?", Office, Department, User, Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID, id)
        conn.commit()
        conn.close()
        return redirect('/Computers')


@mobiles.route('/addcomputer',methods = ['GET','POST'])
@login_required
def addcomputer():
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Workstation")
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23]})
        conn.close()
        return render_template("addcomputer.html", computer = [])
    if request.method == 'POST':
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = User
        empID = str(request.form["empID"])
        
        cursor.execute("INSERT INTO dbo.Workstation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Office, Department, User, Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID)
        conn.commit()
        conn.close()
        return redirect('/Computers')

#Inventory


@mobiles.route("/Inventory")
@login_required
def inventory():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dbo.Inventory")
    for row in cursor.fetchall():
        inventory.append({"id": row[0], "name": row[1], "asset": row[2], "description": row[3], "quantity": row[4], "empID": row[5]})
    conn.close()
    return render_template("Inventory.html", inventory = inventory, info=info[0])

@mobiles.route('/addinventory/',methods = ['GET','POST'])
@login_required
def addinventory():
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Inventory")
        for row in cursor.fetchall():
            inventory.append({"id": row[0], "name": row[1], "asset": row[2], "description": row[3], "quantity": row[4], "empID": row[5]})
        conn.close()
        return render_template("addinventory.html", inventory = [])
    if request.method == 'POST':
        name = str(request.form["name"])
        asset = str(request.form["asset"])
        description = str(request.form["description"])
        quantity = str(request.form["quantity"])
        empID = str(request.form["empID"])
        cursor.execute("INSERT INTO dbo.Inventory VALUES (?, ?, ?, ?, ?)", name, asset, description, quantity, empID)
        conn.commit()
        conn.close()
        return redirect('/Inventory')


@mobiles.route('/updateinventory/<int:id>',methods = ['GET','POST'])
@login_required
def updateinventory(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Inventory WHERE id = ?", id)
        for row in cursor.fetchall():
            inventory.append({"id": row[0], "name": row[1], "asset": row[2], "description": row[3], "quantity": row[4], "empID": row[5]})
        conn.close()
        return render_template("updateinventory.html", inventory = inventory[0])
    if request.method == 'POST':
        name = str(request.form["name"])
        asset = str(request.form["asset"])
        description = str(request.form["description"])
        quantity = str(request.form["quantity"])
        empID = str(request.form["empID"])
        cursor.execute("UPDATE dbo.Inventory SET name = ?, asset = ?, description = ?, quantity = ?, empID = ? WHERE id = ?", name, asset, description, quantity, empID, id)
        conn.commit()
        conn.close()
        return redirect('/Inventory')


#search page
@mobiles.route('/searchby',methods = ['GET','POST'])
@login_required
def searchby():
    if current_user.username != 'admin':
        return "Admin privileges required"
    assets = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        conn.close()
        return render_template("searchby.html", assets = [0])
    if request.method == 'POST':
        selected = str(request.form["searchID"])
        myInput = str(request.form["myInput"])
        if selected == "userID":
            cursor.execute("SELECT * FROM dbo.Inventory where empID = ?", myInput)
            for row in cursor.fetchall():
                assets.append({"id": row[0], "name": row[1], "asset": row[2], "description": row[3], "quantity": row[4], "empID": row[5]})
            cursor.execute("SELECT * FROM dbo.Mobile where empID = ?", myInput)
            for row in cursor.fetchall():
                assets.append({"model": row[2], "color": row[3]})
            cursor.execute("SELECT * FROM dbo.Workstation where empID = ?", myInput)
            for row in cursor.fetchall():
                assets.append({"Office": row[1], "Department": row[2],"uname": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "eID": row[23]})


        conn.commit()
        conn.close()
        messages = json.dumps(assets)
        session['messages'] = messages
        return redirect(url_for('searchresults', messages=messages))

@mobiles.route('/searchresults', methods = ['GET','POST'])
@login_required
def searchresults():
    if current_user.username != 'admin':
        return "Admin privileges required"
    messages = request.args['messages']
    messages = session['messages']
    assets = json.loads(messages)
    return render_template("searchresults.html", assets = assets)

#Toners Search

@mobiles.route('/searchtoners',methods = ['GET','POST'])
@login_required
def searchtoners():
    if request.method == 'GET':
        return render_template("tonersearch.html", toners = [0])
    if request.method == 'POST':
        selected = str(request.form["searchID"])
        myInput = request.form["myInput"]


        messages = json.dumps(myInput)
        session['messages'] = messages
        return redirect(url_for('tonersresults', messages=messages))

@mobiles.route('/tonersresults', methods = ['GET','POST'])
@login_required
def tonersresults():
    messages = request.args['messages']
    messages = session['messages']
    selected = json.loads(messages)



    toners = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("select printer.name, emp, toner.name, toner.tonerNO, quantity, toner.id from dbo.toner inner join dbo.printer on toner.printerID = printer.printerID")
    for row in cursor.fetchall():
        toners.append({"printername": row[0], "emp": row[1], "tonername": row[2], "tonerid": row[3], "quantity": row[4], "id": row[5]})
    conn.close()


    try:
        index = 0
        for x in toners:
            index += 1
            test = index
            tmp = x["printername"]
            for c in range(test, len(toners)):
                if tmp == toners[c]["printername"]:
                    toners[c]["printername"] = ''
                else:
                    break
                        
    except:
        pass

    try:
        index = 0
        for x in toners:
            index += 1
            test = index
            tmp = x["emp"]
            for c in range(test, len(toners)):
                if tmp == toners[c]["emp"]:
                    toners[c]["emp"] = ''
                else:
                    break
                        
    except:
        pass
        
    conn = connection()
    cursor = conn.cursor()
    changes = []

    selectedDate = datetime.datetime.fromisoformat(selected)
    cursor.execute("SELECT * FROM PurchaseToner where purchaseDate > ?", selectedDate)
    for row in cursor.fetchall():
        changes.append(toners[row[4]-1]["tonerid"])
        q = row[2]
        t_id = row[4] - 1
        sign = row[5]
        if sign == 'NEW':
            q = -1 * q
        toners[t_id]["quantity"] += q
        

    global csv_list
    csv_list = toners
    global selected_date
    selected_date = selectedDate
    info = []
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    conn.close()
    return render_template("tonersResult.html", toners = toners, info = info[0], changes = changes, selectedDate = selectedDate)










#toners
@mobiles.route("/Toners")
@login_required
def toners():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    toners = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("select printer.name, emp, toner.name, toner.tonerNO, quantity, toner.id from dbo.toner inner join dbo.printer on toner.printerID = printer.printerID")
    for row in cursor.fetchall():
        toners.append({"printername": row[0], "emp": row[1], "tonername": row[2], "tonerid": row[3], "quantity": row[4], "id": row[5]})
    conn.close()


    try:
        index = 0
        for x in toners:
            index += 1
            test = index
            tmp = x["printername"]
            for c in range(test, len(toners)):
                if tmp == toners[c]["printername"]:
                    toners[c]["printername"] = ''
                else:
                    break
                
    except:
        pass

    try:
        index = 0
        for x in toners:
            index += 1
            test = index
            tmp = x["emp"]
            for c in range(test, len(toners)):
                if tmp == toners[c]["emp"]:
                    toners[c]["emp"] = ''
                else:
                    break
                
    except:
        pass

    
    return render_template("Toners.html", toners = toners, info=info[0])


@mobiles.route('/updatetoners/<int:id>',methods = ['GET','POST'])
@login_required
def updatetoners(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    global oldquantity
    
    toners = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Toner WHERE id = ?", id)
        for row in cursor.fetchall():
            toners.append({"id": row[0], "printerID": row[1], "name": row[2], "quantity": row[3], "tonerNO": row[4]})
        conn.close()
        oldquantity = toners[0]['quantity']
        return render_template("updatetoners.html", toners = toners[0])
    if request.method == 'POST':
        #update quantity
        printerID = str(request.form["printerID"])
        name = str(request.form["name"])
        quantity = int(request.form["quantity"]) + oldquantity
        quantity = str(quantity)
        tonerNO = str(request.form["tonerNO"])
        cursor.execute("UPDATE dbo.Toner SET printerID = ?, name = ?, quantity = ?, tonerNO = ? WHERE id = ?", printerID, name, quantity, tonerNO, id)
        conn.commit()
        conn.close()
        #make order
        
        datenow = datetime.datetime.now()
        username = 'NEW'
        purchasedQuantity = (request.form["quantity"])
        tonerID = id
        
        username2 = username
        conn = connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO dbo.PurchaseToner VALUES (?, ?, ?, ?, ?)", username, purchasedQuantity, datenow, tonerID, username2)
        conn.commit()
        conn.close()
        return redirect('/Toners')


@mobiles.route('/spenttoners/<int:id>',methods = ['GET','POST'])
@login_required
def spenttoners(id):
    if current_user.username != 'admin':
    
        toners = []
        conn = connection()
        cursor = conn.cursor()
        if request.method == 'GET':
            cursor.execute("SELECT * FROM dbo.Toner WHERE id = ?", id)
            for row in cursor.fetchall():
                toners.append({"id": row[0], "printerID": row[1], "name": row[2], "quantity": row[3], "tonerNO": row[4]})
            conn.close()
            return render_template("spenttoners.html", toners = toners[0])
        if request.method == 'POST':
            #update quantity
            quantity = int(request.form["quantity"])
            #make order
            datenow = datetime.datetime.now()
            purdate = request.form['purdate']
            if purdate in '1900-01-01':
                purdate = datenow
            username = str(request.form["empid"])
            username2 = username
            purchasedQuantity = (request.form["quantity"])
            tonerID = id
            conn = connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO dbo.tonerapproval VALUES (?, ?, ?, ?, ?)", username, purchasedQuantity, purdate, tonerID, username2)
            conn.commit()
            conn.close()
            return redirect('/Toners')

#admin
    global oldquantity
    
    toners = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Toner WHERE id = ?", id)
        for row in cursor.fetchall():
            toners.append({"id": row[0], "printerID": row[1], "name": row[2], "quantity": row[3], "tonerNO": row[4]})
        conn.close()
        oldquantity = toners[0]['quantity']
        return render_template("spenttoners.html", toners = toners[0])
    if request.method == 'POST':
        #update quantity
        quantity = int(request.form["quantity"])
        if oldquantity < quantity:
            return 'There is not enough toners available'
        else:
            quantity = oldquantity - quantity
        cursor.execute("UPDATE dbo.Toner SET quantity = ? WHERE id = ?", quantity, id)
        conn.commit()
        conn.close()
        #make order
        
        datenow = datetime.datetime.now()
        username = str(request.form["empid"])
        username2 = username
        purchasedQuantity = (request.form["quantity"])
        purdate = request.form['purdate']
        if purdate in '1900-01-01':
            purdate = datenow
        tonerID = id
        conn = connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO dbo.PurchaseToner VALUES (?, ?, ?, ?, ?)", username, purchasedQuantity, purdate, tonerID, username2)
        conn.commit()
        conn.close()
        return redirect('/Toners')


@mobiles.route("/PurchasedToners")
@login_required
def purchasedtoners():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    toners = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("select tonerNO, username2, purchasetoner.quantity, purchaseDate, printer.name  from PurchaseToner inner join dbo.toner on toner.id = purchasetoner.tonerID inner join dbo.printer on toner.printerID = printer.printerID order by purchaseDate desc")
    for row in cursor.fetchall():
        toners.append({"tonerNO": row[0], "username2": row[1], "quantity": row[2], "purchaseDate": row[3], "printer_name": row[4]})
    conn.close()
    return render_template("PurchasedToners.html", toners = toners, info=info[0])


@mobiles.route("/TonerApproval")
@login_required
def tonerapproval():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    toners = []
    count = 0
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("select tonerID, username2, quantity, purchaseDate, id  from tonerapproval order by purchaseDate desc")
    for row in cursor.fetchall():
        toners.append({"tonerID": row[0], "username2": row[1], "quantity": row[2], "purchaseDate": row[3], "id": row[4], "tonerNO": ""})
        tem = toners[count]['tonerID']
        cursor.execute("select tonerNO from toner where id = ?", tem)
        resu = cursor.fetchone()
        resu = resu[0]
        toners[count]['tonerNO'] = resu
        count = count + 1

    conn.close()
    return render_template("TonerApproval.html", toners = toners, info=info[0])




@mobiles.route('/approveToner/<int:id>',methods = ['GET','POST'])
@login_required
def approvetoner(id):
    if current_user.username != 'admin':
        return 'Admin user required'
#admin
    global oldquantity2

    
    toners = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("select tonerID, username2, quantity, purchaseDate from tonerapproval where id = ?", id)
    resu = cursor.fetchone()
    usname = resu[1]
    quan = resu[2]
    pdate = resu[3]
    resu = resu[0]

    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Toner WHERE id = ?", resu)
        for row in cursor.fetchall():
            toners.append({"id": row[0], "printerID": row[1], "name": row[2], "quantity": quan, "tonerNO": row[4], "username": usname, "quant": row[3]})
        conn.close()
        oldquantity2 = toners[0]['quant']
        return render_template("approveToner.html", toners = toners[0])

        
    if request.method == 'POST':
        #update quantity
        quantity = int(request.form["quantity"])
        if oldquantity2 < quantity:
            return 'There is not enough toners available'
        else:
            quantity = oldquantity2 - quantity
        cursor.execute("UPDATE dbo.Toner SET quantity = ? WHERE id = ?", quantity, resu)
        conn.commit()
        conn.close()
        #make order
        
        username = str(request.form["empid"])
        username2 = username
        purchasedQuantity = (request.form["quantity"])
        conn = connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO dbo.PurchaseToner VALUES (?, ?, ?, ?, ?)", username, purchasedQuantity, pdate, resu, username2)
        conn.commit()
        conn.close()


        conn = connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dbo.TonerApproval WHERE id = ?", id)
        conn.commit()
        conn.close()
        return redirect('/TonerApproval')
#computer storage

@mobiles.route('/rejectToner/<int:id>',methods = ['GET','POST'])
@login_required
def rejecttoner(id):
    if current_user.username != 'admin':
        return 'Admin user required'
    
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM dbo.TonerApproval WHERE id = ?", id)
    conn.commit()
    conn.close()
    return redirect('/TonerApproval')

@mobiles.route('/storecomputer/<int:id>',methods = ['GET','POST'])
@login_required
def storecomputer(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.Workstation WHERE id = ?", id)
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23]})
        conn.close()
        return render_template("storecomputer.html", computer = computer[0])
    if request.method == 'POST':
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = User + ", " + str(request.form["History"])
        empID = str(request.form["empID"])
        note = str(request.form["note"])

        index = 0
        count = 0
#save three previous users
        for x in history:
            if x == ',':
                count += 1
    
            if count == 10:
                break
            
            index += 1
        history = history[0: index:] + history[len(history) + 1::]
        
        
        cursor.execute("INSERT INTO dbo.ComputerStorage VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Office, Department, User, Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID, note)
        conn.commit()
        conn.close()


        conn = connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dbo.Workstation WHERE id = ?", id)
        conn.commit()
        conn.close()
        return redirect('/Computers')

@mobiles.route("/ComputerStorage")
@login_required
def computerstorage():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    if current_user.username != 'admin':
        return "Admin privileges required"
    computers = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dbo.ComputerStorage")
    for row in cursor.fetchall():
        computers.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23], "note": row[24]})
    conn.close()
    return render_template("ComputerStorage.html", computers = computers, info=info[0])


@mobiles.route('/updatecomputerstorage/<int:id>',methods = ['GET','POST'])
@login_required
def updatecomputerstorage(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.ComputerStorage WHERE id = ?", id)
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23], "note": row[24]})
        conn.close()
        return render_template("updatecomputerstorage.html", computer = computer[0])
    if request.method == 'POST':
        note = str(request.form["note"])
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = User + ", " + str(request.form["History"])
        empID = str(request.form["empID"])

        index = 0
        count = 0
#save three previous users
        for x in history:
            if x == ',':
                count += 1
    
            if count == 10:
                break
            
            index += 1
        history = history[0: index:] + history[len(history) + 1::]

        
        cursor.execute("UPDATE dbo.ComputerStorage SET office = ?, department = ?, username = ?, computername = ?, computerbrand = ?, computermodel = ?, stsn = ?, os = ?, cpus = ?, ram = ?, hdsize = ?, hdtype = ?, officever = ?, adobe = ?, msprojects = ?, visio = ?, brand = ?, size = ?, travelport = ?, externalhd = ?, bag = ?, history = ?, empID = ?, note = ? WHERE id = ?", Office, Department, User, Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID, note, id)
        conn.commit()
        conn.close()
        return redirect('/ComputerStorage')


@mobiles.route('/assigncomputer/<int:id>',methods = ['GET','POST'])
@login_required
def assigncomputer(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.ComputerStorage WHERE id = ?", id)
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23], "note": row[24]})
        conn.close()
        return render_template("assigncomputer.html", computer = computer[0])
    if request.method == 'POST':
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = User + ", " + str(request.form["History"])
        empID = str(request.form["empID"])
        note = str(request.form["note"])
        employeeInfo = {}
        try:
            employeeInfo = searchEmp.search_employee(empID)
        except:
            employeeInfo = {'name': '','department': ''}

        index = 0
        count = 0
#save three previous users
        for x in history:
            if x == ',':
                count += 1
    
            if count == 10:
                break
            
            index += 1
        history = history[0: index:] + history[len(history) + 1::]
        
        
        cursor.execute("INSERT INTO dbo.Workstation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Office, employeeInfo['department'], employeeInfo['name'], Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID)
        conn.commit()
        conn.close()


        conn = connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM dbo.ComputerStorage WHERE id = ?", id)
        conn.commit()
        conn.close()
        if employeeInfo['name'] == '':
            flash("employee was not found: please go to computers and edit the name and department for the assigned computer")
        else:
            pass
        return redirect('/ComputerStorage')

@mobiles.route('/addcomputerstorage',methods = ['GET','POST'])
@login_required
def addcomputerstorage():
    if current_user.username != 'admin':
        return "Admin privileges required"
    computer = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.ComputerStorage")
        for row in cursor.fetchall():
            computer.append({"id": row[0], "Office": row[1], "Department": row[2], "User": row[3], "Computer name": row[4], "Computer Brand": row[5], "Computer Model No": row[6], "Service tag / Serial No": row[7], "OS": row[8], "CPUs": row[9], "Ram": row[10], "HD Size": row[11], "HD Type": row[12], "Office365": row[13], "Adobe Pro": row[14], "Microsoft Projects": row[15], "Visio": row[16], "Brand": row[17], "Size": row[18], "Travel port DS": row[19], "External HD": row[20], "Bag": row[21], "History": row[22], "empID": row[23], "note": row[24]})
        conn.close()
        return render_template("addcomputerstorage.html", computer = [])
    if request.method == 'POST':
        Office = str(request.form["Office"])
        Department = str(request.form["Department"])
        User = str(request.form["User"])
        Computer_name = str(request.form["Computer name"])
        Computer_Brand = str(request.form["Computer Brand"])
        Computer_Model_No = str(request.form["Computer Model No"])
        Service_tag = str(request.form["Service tag / Serial No"])
        OS = str(request.form["OS"])
        CPUs = str(request.form["CPUs"])
        Ram = str(request.form["Ram"])
        HD_Size = str(request.form["HD Size"])
        HD_Type = str(request.form["HD Type"])
        Office365 = str(request.form["Office365"])
        Adobe_Pro = str(request.form["Adobe Pro"])
        Microsoft_Projects = str(request.form["Microsoft Projects"])
        Visio = str(request.form["Visio"])
        Brand = str(request.form["Brand"])
        Size = str(request.form["Size"])
        Travel_port_DS = str(request.form["Travel port DS"])
        External_HD = str(request.form["External HD"])
        Bag = str(request.form["Bag"])
        history = User
        empID = str(request.form["empID"])
        note = str(request.form["note"])
        cursor.execute("INSERT INTO dbo.ComputerStorage VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Office, Department, User, Computer_name, Computer_Brand, Computer_Model_No, Service_tag, OS, CPUs, Ram, HD_Size, HD_Type, Office365, Adobe_Pro, Microsoft_Projects, Visio, Brand, Size, Travel_port_DS, External_HD, Bag, history, empID, note)
        conn.commit()
        conn.close()
        return redirect('/ComputerStorage')

#PrinterStorage


@mobiles.route("/PrinterStorage")
@login_required
def printerstorage():
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dbo.PrinterStorage")
    for row in cursor.fetchall():
        inventory.append({"id": row[0], "owner": row[1], "brand": row[2], "model": row[3], "empID": row[4], "note": row[5]})
    conn.close()
    return render_template("PrinterStorage.html", inventory = inventory, info=info[0])

@mobiles.route('/addprinterstorage/',methods = ['GET','POST'])
@login_required
def addprinterstorage():
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.PrinterStorage")
        for row in cursor.fetchall():
            inventory.append({"id": row[0], "owner": row[1], "brand": row[2], "model": row[3], "empID": row[4], "note": row[5]})
        conn.close()
        return render_template("addprinterstorage.html", inventory = [])
    if request.method == 'POST':
        owner = str(request.form["owner"])
        brand = str(request.form["brand"])
        model = str(request.form["model"])
        empID = str(request.form["empID"])
        note = str(request.form["note"])
        cursor.execute("INSERT INTO dbo.PrinterStorage VALUES (?, ?, ?, ?, ?)", owner, brand, model, empID, note)
        conn.commit()
        conn.close()
        return redirect('/PrinterStorage')


@mobiles.route('/updateprinterstorage/<int:id>',methods = ['GET','POST'])
@login_required
def updateprinterstorage(id):
    if current_user.username != 'admin':
        return "Admin privileges required"
    inventory = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("SELECT * FROM dbo.PrinterStorage WHERE id = ?", id)
        for row in cursor.fetchall():
            inventory.append({"id": row[0], "owner": row[1], "brand": row[2], "model": row[3], "empID": row[4], "note": row[5]})
        conn.close()
        return render_template("updateprinterstorage.html", inventory = inventory[0])
    if request.method == 'POST':
        owner = str(request.form["owner"])
        brand = str(request.form["brand"])
        model = str(request.form["model"])
        empID = str(request.form["empID"])
        note = str(request.form["note"])
        cursor.execute("UPDATE dbo.PrinterStorage SET owner = ?, brand = ?, model = ?, empID = ?, note = ? WHERE id = ?", owner,brand, model, empID, note, id)
        conn.commit()
        conn.close()
        return redirect('/PrinterStorage')

@mobiles.route('/travelports', methods = ['GET'])
@login_required
def travelports():
    if current_user.username != 'admin':
        return "Admin Login required"
    
    
    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    conn.close()


    items = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("select username, travelport from workstation where travelport != 'no' and travelport != '-' and travelport != ''")
        for row in cursor.fetchall():
            items.append({'username': row[0], 'travelport':row[1]})
        conn.close()
        return render_template('travelports.html', items=items, info=info[0])


@mobiles.route('/externalhd', methods = ['GET'])
@login_required
def externalhd():
    if current_user.username != 'admin':
        return "Admin Login required"
    

    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    conn.close()


    items = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("select username, externalhd from workstation where externalhd != 'no' and externalhd != '-' and externalhd != ''")
        for row in cursor.fetchall():
            items.append({'username': row[0], 'externalhd':row[1]})
        conn.close()
        return render_template('externalhd.html', items=items, info=info[0])

@mobiles.route('/bags', methods = ['GET'])
@login_required
def bags():
    if current_user.username != 'admin':
        return "Admin Login required"
    

    info = []
    conn = connection()
    cursor = conn.cursor()
    cursor.execute("Select count(id) from tonerApproval")
    resu = cursor.fetchone()
    resu = resu[0]
    info.append({'tonersCount': resu})
    conn.close()


    items = []
    conn = connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        cursor.execute("select username, bag from workstation where bag != 'no' and bag != '-' and bag != ''")
        for row in cursor.fetchall():
            items.append({'username': row[0], 'bags':row[1]})
        conn.close()
        return render_template('bags.html', items=items, info=info[0])



##
@mobiles.route('/exportcsv', methods=['GET', 'POST'])
def exportcsv():
    
    global csv_list
    global selected_date
    keys = csv_list[0].keys()

    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=keys)
    cw.writeheader()
    cw.writerows(csv_list)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename={}.csv".format(selected_date)
    output.headers["Content-type"] = "text/csv"
    return output

##


if(__name__ == "__main__"):
    mobiles.secret_key = os.getenv('SECRET_KEY')
    mobiles.run(host='0.0.0.0', port=80)

