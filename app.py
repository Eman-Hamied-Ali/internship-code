from flask import * 
from flask import flash
import json, time
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
import os
import pandas as pd
import requests, json
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from smtplib import SMTP
import ssl 
from flask_mail import Mail, Message
import bcrypt
import io
import tempfile
import pandas as pd
import stripe
from prettytable import PrettyTable 
from prettytable.colortable import ColorTable, Themes
import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'test123'
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587

app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
powerbi_blueprint = Blueprint('powerbi', __name__)


mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
class UploadFile(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Submit File")

@app.route("/")

def home():
    username = ''
    if session.get('token') == None:
        return render_template("index.html")
    else:
        if session.get('username') == None:
            return render_template("index.html")
        else:
            username = session.get('username')
        return render_template("home.html",username=username)


# --> This is tha function that uses upload API

@app.route("/analyze-company-data", methods = ["GET","POST"])

def analyze_company_data():
    results = []

    # getting user type to know if he is eligible for this feature or not 
    type = session.get('type')
    username = ''
    token = session.get('token')
    table = ''
    charts_data = []

    print(session.get("token"))
    print(session.get("username"), "username")
    if session.get('token') == None:
        return redirect(url_for('sign_in'))
    elif session.get('username') == None:
        return redirect(url_for('sign_in'))
    else :
        username = session.get('username')
        bearer_token = 'Bearer ' + token

        #this tag is for displaying it in HTML file
        tag = "Upload one file for employees data to get analyzed!"
        primary_key = request.form.get('field-2')
        measure = request.form.get('select')
        files = []
        if request.method == "POST":
            files_form = request.files.getlist('file-field') 
            
            print(files_form)
            for file in files_form:  
                file_name = secure_filename(file.filename)

                #we save the files at first then remove them after the request is completed
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                file_saved = open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), "rb")
                files.append(("file",file_saved))

            #the API request
            r = requests.post(url="https://opus-backend.azurewebsites.net/upload", headers={'Authorization': bearer_token}, data={'primary_key':primary_key,'uploader':token,'measure':measure},files=files)
            if r.status_code == 200:
                #getting results from JSON Object
                for item in r.json().get("root", []):
                    measure = item.get("measure", "")
                    result = item.get("result", "")
                    results.append(result)

                    #labels are always the first thing before the semicolon
                    labels = result.split(";")[0]

                    #Split labels to get how many columns 
                    labels = labels.split(",")

                    #get the rest of the result
                    values = result.split(";")[1:]
                    print(labels, values, measure, "measure")
                    if len(values) > 0:
                        chart_data = []
                        for i in values:
                            row_data = i.split(",")
                            data_point = {label: value for label, value in zip(labels, row_data)}
                            chart_data.append(data_point)

                        charts_data.append({
                            "measure": measure,
                            "data": chart_data
                        })

                        myTable = PrettyTable(labels)

                        #adding the measure as a title to the table
                        myTable.title = measure 
                        
                        #this for loop is for detecting the rows and appending them to the table
                        for i in values:
                            myTable.add_row(i.split(","))
                        myTable.align = "l"
                        #myTable.border = True
                        #myTable.padding_width = 3

                        #appending each table to the result 
                        table += myTable.get_html_string(attributes={"class":"tbl"}, format=True)
                        
                flash('Files Uploaded Successfully','success')
            elif r.status_code == 403:
                flash('You have used the free features five times. Please subscribe!','warning')
            elif r.status_code == 401:
                return redirect(url_for('sign_in'))
            else:
                flash('Invalid Data','error')
            @after_this_request
            def remove_file(response):
                for file in files_form: 
                    file_name = secure_filename(file.filename)
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                return response
    #returning table to HTML to be represented 
    return (render_template("account-form-upload.html",table= table,tag=tag,username=username,type=type,charts=charts_data))



@app.route("/our-offerings")

def our_offerings():
    username = ''
    if session.get('token') == None:
        return render_template("our-offerings.html")
    else:
        if session.get('username') == None:
            return render_template("our-offerings.html")
        else:
            username = session.get('username')
        return render_template("our-offerings-authenticated.html",username=username)


@app.route("/partners")

def partners():
    username = ''
    if session.get('token') == None:
        return render_template("partners.html")
    else:
        if session.get('username') == None:
            return render_template("partners.html")
        else:
            username = session.get('username')
        return render_template("partners-authenticated.html",username=username)


@app.route("/contact", methods = ["GET", "POST"])

def contact():
    username = ''
    if session.get('token') == None:
        return render_template("contact.html")
    else:
        if session.get('username') == None:
            return render_template("contact.html")
        else:
            username = session.get('username')
        return render_template("contact-authenticated.html",username=username)


@app.route("/privacy-policy")

def privacy_policy():
    username = ''
    if session.get('token') == None:
        return render_template("privacy-policy.html")
    else:
        if session.get('username') == None:
            return render_template("privacy-policy.html")
        else:
            username = session.get('username')
        return render_template("privacy-policy-authenticated.html",username=username)


@app.route("/cookie-policy")

def cookie_policy():
    username = ''
    if session.get('token') == None:
        return render_template("cookie-policy.html")
    else:
        if session.get('username') == None:
            return render_template("cookie-policy.html")
        else:
            username = session.get('username')
        return render_template("cookie-policy-authenticated.html",username=username)


@app.route("/terms-of-use")

def terms_of_use():
    if session.get('token') == None:
        return render_template("terms-of-use.html")
    else:
        if session.get('username') == None:
            return render_template("terms-of-use.html")
        else:
            username = session.get('username')
        return render_template("terms-of-use-authenticated.html",username=username)


@app.route("/sign-in", methods = ["GET","POST"])

def sign_in():
    email = request.form.get('User-Name')
    password = request.form.get("Password")
    r = requests.post(url="https://opus-backend.azurewebsites.net/authenticate", json={"username":email,"password":password})
    if request.method == "POST":
        if r.status_code == 200:
            session['token'] = r.json()['token']
            session['username'] = email
            session['type'] = r.json()['user_type']
            return redirect(url_for('home'))
        else:
            flash('Login Failed!','error')
    return (render_template("sign-in.html"))


@app.route("/sign-up", methods = ["GET","POST"])

def sign_up():
   
    token = ''

    return (render_template("signup.html",token = token))


@app.route("/log-out", methods = ["GET","POST"])

def log_out():
    session.pop('token',None)
    session.pop('username',None)
    session.pop('type',None) 
    return redirect(url_for('home'))

@app.route("/compare_resume_job", methods = ["GET","POST"])

def compare_resume_job():
    type = session.get('type')
    username = ''
    enable_multiple = False
    has_job = True
    token = session.get('token')
    if token == None:
        return redirect(url_for('sign_in'))
    elif session.get('username') == None:
        return redirect(url_for('sign_in'))
    else:
       username = session.get('username')
       bearer_token = "Bearer " + token 
       r =  requests.post(url="https://opus-openai.azurewebsites.net/compare/resume", headers={'Authorization': bearer_token})
       if r.status_code == 401:
            return redirect(url_for('sign_in'))
       else:
        tag = "Upload one file and submit a job title!"
        result = ''
        job_title = request.form.get('field-2')
        file = request.form.get('file-field')
        if request.method == "POST":
            file_ = request.files['file-field']        
            file_name = secure_filename(file_.filename)     
            file_.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            test_file = open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), "rb")
            r = requests.post(url="https://opus-openai.azurewebsites.net/compare/resume", headers={'Authorization': bearer_token},data = {"description" : job_title},  files={"analyze-files" : test_file})
            if r.status_code == 200:
                jsonData = json.dumps(r.json()[0])
                resp = json.loads(jsonData)
                result = resp['message']['content']
                result = "</br>".join(result.split("\n"))
                flash('Files Uploaded Successfully','success')
            elif r.status_code == 403:
                flash('You have used the free features five times. Please subscribe!','warning')
            elif r.status_code == 500:
                return redirect(url_for("sign_in"))
            else:
                flash('Invalid Data','error')
                result = r.status_code
            @after_this_request
            def remove_file(response):
                file_name = secure_filename(file_.filename)
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                return response
    return (render_template("account-not-premium-form.html",result= result,tag=tag, enable_multiple = enable_multiple,username=username,has_job=has_job, type=type))


@app.route("/compare_resumes", methods = ["GET","POST"])

def compare_resumes():
    type = session.get('type')
    username = ''
    enable_multiple = True
    has_job = True
    token = session.get('token')
    if session.get('token') == None:
        return redirect(url_for('sign_in'))
    elif session.get('username') == None:
        return redirect(url_for('sign_in'))
    else : 
        username = session.get('username')
        bearer_token = "Bearer " + token 
        tag = "Upload two files and submit a job title!"
        result = ''
        job_title = request.form.get('field-2')
        files = []
        if request.method == "POST":    
            files_form = request.files.getlist('file-field') 
            
            for file in files_form:    
                file_name = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                file_saved = open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), "rb")
                files.append(("analyze-files",file_saved))
            r = requests.post(url="https://opus-openai.azurewebsites.net/compare/resumes", headers= {'Authorization':bearer_token},data={"description" : job_title},  files=files)
            if r.status_code == 200:
                jsonData = json.dumps(r.json()[0])
                resp = json.loads(jsonData)
                result = resp['message']['content']
                result = "</br>".join(result.split("\n"))
                flash('Files Uploaded Successfully','success')
            elif r.status_code == 403:
                flash('You have used the free features five times. Please subscribe!','warning')
            elif r.status_code == 500:
                return redirect(url_for("sign_in"))
            else:
                flash('Invalid Data','error')
            @after_this_request
            def remove_file(response):
                for file in files_form: 
                    file_name = secure_filename(file.filename)
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                return response
    return (render_template("account-not-premium-form.html",result= result,tag=tag,username=username,enable_multiple=enable_multiple,has_job=has_job,type=type))



@app.route("/compare-resumes-job", methods = ["GET","POST"])

def compare_resumes_job():
    type = session.get('type')
    username = ''
    enable_multiple = True
    has_job = True
    token = session.get('token')
    if session.get('token') == None:
        return (render_template('404.html'))
    elif session.get('username') == None:
        return redirect(url_for('sign_in'))
    else :
        username = session.get('username')
        bearer_token = "Bearer " + token 
        tag = "Upload two files and submit a job title!"
        result = ''
        job_title = request.form.get('field-2')
        files = []
        if request.method == "POST":    
            files_form = request.files.getlist('file-field') 
            
            for file in files_form:    
                file_name = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                file_saved = open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), "rb")
                files.append(("analyze-files",file_saved))
            r = requests.post(url="https://opus-openai.azurewebsites.net/compare/each/resume", headers= {'Authorization':bearer_token},data={"description" : job_title},  files=files)
            if r.status_code == 200:
                jsonData = json.dumps(r.json()[0])
                resp = json.loads(jsonData)
                result = resp['message']['content']
                result = "</br>".join(result.split("\n")) 
                flash('Files Uploaded Successfully','success')
            elif r.status_code == 403:
                flash('You have used the free features five times. Please subscribe!','warning')
            elif r.status_code == 500:
                return redirect(url_for("sign_in"))
            else:
                flash('Invalid Data','error')
            @after_this_request
            def remove_file(response):
                for file in files_form: 
                    file_name = secure_filename(file.filename)
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                return response
    return (render_template("account-not-premium-form.html",result= result,tag=tag,username=username,enable_multiple=enable_multiple,has_job=has_job,type=type))


@app.route("/analyze-resume", methods = ["GET","POST"])

def analyze_resume():
    type = session.get('type')
    username = ''
    enable_multiple = True
    has_job = False
    token = session.get('token')
    if session.get('token') == None:
        return (render_template('404.html'))
    elif session.get('username') == None:
        return redirect(url_for('sign_in'))
    else :
        username = session.get('username')
        bearer_token = "Bearer " + token 
        tag = "Upload a resume to get analyzed!"
        result = ''
        file = request.form.get('file-field')
        if request.method == "POST":
            file_ = request.files['file-field']        
            file_name = secure_filename(file_.filename)
                    
            file_.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            test_file = open(os.path.join(app.config['UPLOAD_FOLDER'], file_name), "rb")
            r = requests.post(url="https://opus-openai.azurewebsites.net/analyze/resume",headers= {'Authorization':bearer_token},files={"analyze-file" : test_file})
            if r.status_code == 200:
                jsonData = json.dumps(r.json()[0])
                resp = json.loads(jsonData)
                result = resp['message']['content']
                result = "</br>".join(result.split("\n"))
                flash('Files Uploaded Successfully','success')
            elif r.status_code == 403:
                flash('You have used the free features five times. Please subscribe!','warning')
            elif r.status_code == 500:
                return redirect(url_for("sign_in"))
            else:
                flash('Invalid Data','error')
            @after_this_request
            def remove_file(response):
                file_name = secure_filename(file_.filename)
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
                return response
    return (render_template("account-not-premium-form.html",result= result,tag=tag,username=username,enable_multiple=enable_multiple,has_job=has_job,type=type))


@app.route("/reset-password", methods = ["GET","POST"])
def reset_password():
    token = ''
    return (render_template('reset-passowrd.html',token=token))
            

@app.route("/subscription", methods = ["GET","POST"])

def subscription():
    username = ''
    if session.get('token') == None:
        return (render_template("subscription.html"))
    
    else:
        if session.get('username') == None:
            return (render_template("subscription.html"))
        else:
            username = session.get('username')
        return (render_template("subscription-authenticated.html",username=username))
    

@app.route("/dashboard", methods = ["GET","POST"])

def dashboard():
    username = ''
    embed_url = ''
    embed_token = ''
    report_id = ''
    type = session.get('type')
    if session.get('token') == None:
        return redirect(url_for('sign_in'))
    else:
        if session.get('username') == None:
            return redirect(url_for('sign_in'))
        else:
            username = session.get('username')
        
        return (render_template("account-not-premium.html",username=username,type=type))



if __name__ == '__main__':
    app.run(debug=True)