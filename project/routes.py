from flask import render_template, url_for, redirect, request, flash
from project import app, crypt, db, Users, Carts, Products, Customer_Cart, Billing
import secrets
import random
import string
import os
from PIL import Image
from werkzeug.utils import secure_filename
from datetime import date, datetime
import plotly
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import numpy as np
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logged_in = False
logged_in_detail = None
otp = None
adminpass = None
receiver = None
loginmsg = None
pschanged = False
admincount = 0

def noneall():
    global otp
    global adminpass
    global receiver
    global loginmsg
    global pschanged
    otp = adminpass = receiver = loginmsg = None
    pschanged = False

def check_data(email):
    query = {"email": email}
    x = Users.find_one(query)
    return x

'''def create_plot():
    N = 40
    x = np.linspace(0,1,N)
    y = np.random.randn(N)
    df = pd.DataFrame({'x':x, 'y':y})
    data = [go.Bar(x=df['x'],y=df['y'])]
    graphJSON = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)
    return graphJSON

def index():
    rng = pd.date_range('1/1/2011', periods=7500, freq='H')
    ts = pd.Series(np.random.randn(len(rng)), index=rng)
    graphs=[
        dict( data=[ dict(x=[1,2,3], y=[10,20,30], type='scatter') ], layout=dict(title='First Graph')),
        dict( data=[ dict(x=[1,3,6], y=[10,50,20], type='bar') ], layout=dict(title='Second Graph')),
        dict( data=[ dict(x=ts.index, y=ts)])
    ]
    ids = ['graph-{}'.format(i) for i,_ in enumerate(graphs)]
    graphJSON = json.dumps(graphs, cls=plotly.utils.PlotlyJSONEncoder)
    return ids,graphJSON'''

@app.route('/')
def home():
    print(f"Logged In : {logged_in}")
    # return render_template('layout.html', title='HomePage', logged_in=logged_in)
    return redirect('/OTPVerification')

def send_mail():
    sender = 'jaiswal.apurva.aj011@gmail.com'
    subject = 'IntelliCart account password reset'
    global otp
    global adminpass
    adminpass = cpass
    otp = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    msg = '''<h4 style='color: #292b2c;'>IntelliCart Account</h4>
        <big><h1 style='color: #0275d8;'>Password reset code</h1></big>
        <p>Please use this code to reset the password for the IntelliCart account ''' + receiver + '''.</p><br>
        <p>Here is your code : <big><b>''' + otp + '''</b></big><br><br>Thanks.<br>The IntelliCart Team</p>'''
    success = False
    m = MIMEMultipart('alternative')
    m['From'] = sender
    m['To'] = receiver
    m['Subject'] = subject
    m.attach(MIMEText(msg,'html'))
    print(f'sender : {sender}\nReceiver : {receiver}\nOTP : {otp}\nMessage : {msg}\nSuccess : {success}\nMIME Content : {m}')

    con = smtplib.SMTP('smtp.gmail.com', 587)
    print('Connected to SMTP Server')
    con.starttls()
    print('TLS Encryption Enabled')
    try:
        con.login(sender, cpass)
        print('Logged In by Comapny Email')
        msg_content = m.as_string()
        print('Message Created for the Mail to be Sent : \n',msg_content)
        # con.sendmail(sender, receiver, 'Subject: So long.\nDear Alice, so long and thanks for all the fish. Sincerely, Bob')
        con.sendmail(sender, receiver, msg_content)
        print('Mail Sent')
        success = True
    except smtplib.SMTPAuthenticationError:
        print('Wrong Company Password Entered!')
        otp = None
        success = False
    finally:
        con.quit()
        print('Logged out of the Company Mail')
        print('Sending Process Ended')
        return success

def send_confirmation():
    sender = 'jaiswal.apurva.aj011@gmail.com'
    subject = 'IntelliCart Account Password Change'
    msg = '''<h4 style='color: #444444;'>IntelliCart Account</h4>
    <big><h1 style='color: blue;'>Your Password Changed</h1></big>
    <p>Your password for the Microsoft account '''+receiver+''' was changed on '''+datetime.now().strftime('%Y/%m/%d %H:%M:%S')+'''.</p>
    <p>Thanks,\nThe Intellicode Team.</p>'''
    success = False
    m = MIMEMultipart('alternative')
    m['From'] = sender
    m['Bcc'] = receiver
    m['Subject'] = subject
    m.attach(MIMEText(msg,'html'))
    print(f'sender : {sender}\nReceiver : {receiver}\nAdmin Password : {adminpass}\nMessage : {msg}\nSuccess : {success}\nMIME Content : {m}')

    con = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    print('Connected to SMTP Server via SSL')
    # con.starttls()
    # print('TLS Encryption Enabled')
    if adminpass:
        print('Admn Password : ',adminpass,' is OK')
        try:
            print('Logging In!')
            con.login(sender, cpass)
            print('Logged In by Comapny Email')
            msg_content = m.as_string()
            print('Message Created for the Mail to be Sent : \n',msg_content)
            # con.sendmail(sender, receiver, 'Subject: So long.\nDear Alice, so long and thanks for all the fish. Sincerely, Bob')
            con.sendmail(sender, receiver, msg_content)
            print('Mail Sent')
            success = True
        except smtplib.SMTPAuthenticationError:
            print('Wrong Company Password Entered!')
            # otp = None
            success = False
        except smtplib.SMTPAuthenticationError:
            print('The server didn\'t accept the username/password combination.')
        except smtplib.SMTPNotSupportedError:
            print('The AUTH command is not supported by the server.')
        except smtplib.SMTPException:
            print('No suitable authentication method was found.')
        except smtplib.SMTPHeloError:
            print('The server didn\'t reply properly to the helo greeting.')
        except smtplib.SMTPRecipientsRefused:
            print('The server rejected ALL recipients (no mail was sent).')
        except smtplib.SMTPSenderRefused:
            print('The server didn\'t accept the from_addr.')
        except smtplib.SMTPDataError:
            print('The server replied with an unexpected error code (other than a refusal of a recipient).')
        except smtplib.SMTPNotSupportedError:
            print('The mail_options parameter includes \'SMTPUTF8\' but the SMTPUTF8 extension is not supported by the server.')
        finally:
            con.quit()
            print('Logged out of the Company Mail')
            print('Sending Process Ended')
            return success
    else:
        print('No Admin Password Given')
        return False

@app.route('/login', methods=['GET','POST'])
def login():
    message = None
    alert = 'danger'
    global logged_in
    global logged_in_detail
    if request.method == "POST":
        login_email = request.form.get('login_email')
        login_password = request.form.get('login_password')
        print("Login Detail : ",login_email, login_password)
        detail = check_data(login_email)
        logged_in_detail = detail
        if detail:
            if crypt.check_password_hash(detail["password"], login_password):
                print("Email and Password Matched, Login Successful")
                logged_in = True
                return redirect('/account')
            else:
                print("Password Not matched")
                message = 'Invalid Email or Password!'
                logged_in = False
            print(f"Password is {detail['password']} of type {type(detail['password'])}")
        else:
            print("Invalid Username")
            message = 'Invalid Email or Password!'
            logged_in = False
    if not message and loginmsg:
        message = loginmsg
        alert = 'success'
        if pschanged:
            noneall()
    print(f"Logged In : {logged_in}\nOTP : {otp}\nAdmin Pass : {adminpass}\nReceiver : {receiver}\nLogin Msg : {loginmsg}\nPassword Changed : {pschanged}")
    return render_template('login.html', title='Login', logged_in=logged_in, user=logged_in_detail, message=message, alert=alert)

@app.route('/forgotpassword', methods=['GET','POST'])
def forgotpassword():
    message=None
    global logged_in
    global receiver
    if request.method == "POST":
        receiver = request.form.get('receiver')
        admin_pass = request.form.get('admin_pass')
        print("Mail Receiver : ",receiver," Company Password : ", admin_pass)
        x = Users.find_one({'email': receiver})
        print('Receiver Data : ',x)
        if x:
            if send_mail(admin_pass):
                print(f'Mail Sent to Receiver {receiver} with OTP : {otp}')
                return redirect('/OTPVerification')
            else:
                message = 'Sender\'s Password is Wrong!'
        else:
            message = 'No User for given Email Found!'
    print(f"Logged In : {logged_in}")
    return render_template('forgotpassword.html', title='Forgot Password', message=message)

@app.route('/OTPVerification', methods=['GET','POST'])
def otpverification():
    if request.method == "POST":
        verify = request.form.get('otp')
        if verify == otp:
            print('OTP Matched!')
            return redirect('/ChangePassword')
        else:
            print('Wrong OTP Entered!')
    return render_template('otpverification.html', title='OTP Verification', otp=otp)

@app.route('/ChangePassword', methods=['GET','POST'])
def changepassword():
    global loginmsg
    if request.method == "POST":
        np = request.form.get('newpass')
        cp = request.form.get('confpass')
        print('New Password : ',np)
        print('Confirm Password : ',cp)
        if np == cp:
            print('New Pasword Matched!')
            x = Users.find_one({'email': receiver})
            print('Receiver Data whose Password is to be changed : ',x)
            if x:
                hashed_password = crypt.generate_password_hash(np).decode('utf-8')
                print(f'Hash Password for {np} generated is :\n{hashed_password}')
                y = Users.update_one({"email": receiver},{"$set":{"password": hashed_password}})
                if y.modified_count:
                    print('Password Changed Successfully!\n',Users.find_one({'email': receiver}))
                    # send_confirmation()
                    global pschanged
                    pschanged = True
                    loginmsg = 'Password Changed Successfully. You can login to your account now.'
                    return redirect('/login')
                else:
                    print('Error in Saving New Password!')
            else:
                print('No Such User Found with the Specified Email!')
        else:
            print('New Password did not match!')
    return render_template('changepassword.html', title='Change Password')

def save_data(username, fname, lname, mobile, email, password, access, image="/static/profile_pics/default.jpg"):
    value = {"username":username,"first_name":fname, "last_name":lname, "mobile":mobile, "email":email, "password":password, "image_file":image}
    if access == 'Admin':
        value['admin'] = 'True'
    else:
        value['admin'] = 'False'
    x = Users.insert_one(value)
    print("Data Inserted",x.inserted_id)

def is_present(key,value):
    query = {key:value}
    x = Users.find_one(query)
    if x:
        return True
    else:
        return False

def coutnadmins():
    global admincount
    admincount = 0
    x = Users.find({"admin": "True"})
    for i in x:
        print(i['first_name']+" "+i['last_name'])
        admincount += 1
    print("No of Admins : ",admincount)

@app.route('/register', methods=['GET','POST'])
def register():
    message=None
    global logged_in
    coutnadmins()
    if admincount == 2:
        moreadmin = False
    else:
        moreadmin = True
    alert = "danger"
    if request.method == 'POST':
        reg_access = request.form.get('access')
        reg_fname = request.form.get('firstname')
        reg_lname = request.form.get('lastname')
        reg_username = request.form.get('register_username')
        reg_mobile = request.form.get('mobile')
        reg_email = request.form.get('register_email')
        reg_password = request.form.get('register_password')
        reg_confirm = request.form.get('register_confirm')
        print(f"Username : {reg_username}, Name : {reg_fname} {reg_lname}, Mobile : {reg_mobile}, Email : {reg_email}, Password : {reg_password}, confirm : {reg_confirm}, accessibility : {reg_access}")
        if is_present("username",reg_username):
            message="Username Already Taken. Enter Another One!"
            print("Username Already Taken. Enter Another One!")
        elif is_present("email",reg_email):
            message="Email Already Taken. Enter Another One!"
            print("Email Already Taken. Enter Another One!")
        elif reg_password != reg_confirm:
            message="Password Do Not Match!"
            print("Password Do Not Match!")
        else:
            print('Password Matched')
            hashed_password = crypt.generate_password_hash(reg_password).decode('utf-8')
            save_data(reg_username, reg_fname, reg_lname, reg_mobile, reg_email, hashed_password, reg_access)
            message = 'You Have Been Registered. You May Login!'
            alert = "success"
    print(f"Logged In : {logged_in}")
    return render_template('register.html', title='Register', logged_in=logged_in, message=message, alert=alert, ma=moreadmin)

@app.route('/dashboard')
def dashboard():
    # graph = create_plot()
    # ids,graphJSON = index()
    User_cursor = Users.find().sort("username").limit(8)
    Cart_cursor = Carts.find().sort("_id").limit(8)
    Product_cursor = Products.find().sort("_id").limit(8)
    Customer_cart_cursor = Customer_Cart.find().sort("used_date").limit(8)
    Billing_cursor = Billing.find().sort("_id").limit(8)
    print(f"Logged In : {logged_in}")
    return render_template('dashboard.html', title='Dashboard', logged_in=logged_in, user=logged_in_detail, usrcrsr=User_cursor, crtcrsr=Cart_cursor, prdcrsr=Product_cursor, cccrsr=Customer_cart_cursor, bilcrsr=Billing_cursor)#, graphJSON=graphJSON, ids=ids)

@app.route('/logout')
def logout():
    global logged_in
    logged_in=False
    print(f"Logged in : {logged_in}")
    return redirect('/login')

# def save_picture(form_picture):
#     random_hex = secrets.token_hex(8)
#     print("random hex :",random_hex)
#     _, f_ext = os.path.splitext(form_picture)
#     picture_fn = random_hex + f_ext
#     print("picture name :",picture_fn)
#     picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn).replace('\\',"/")
#     print("picture path :",picture_path)
#     #form_picture.save(picture_path)
#     output_size = (125, 125)
#     i = Image.open(picture_path)
#     i.thumbnail(output_size)
#     i.save(picture_path)
#     print(picture_fn)
#     return picture_fn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'png', 'jpeg', 'gif'}

@app.route('/account', methods=['GET','POST'])
def account():
    print(f"Logged In : {logged_in}")
    global logged_in_detail
    email=mobile=uname=oldpass=imgpath=message=umsg=None
    newvalues={}
    if request.method == "POST":
        # print("Files Extraced :",request.files)
        # print("The user is :",logged_in_detail['first_name'],logged_in_detail['last_name'])
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        mobile=request.form.get('mobile').strip()
        uname=request.form.get('uname').strip()
        oldpass=request.form.get('oldpass')
        newpass=request.form.get('newpass')
        confpass=request.form.get('confpass')
        
        if crypt.check_password_hash(logged_in_detail["password"], oldpass):
            print("Old Password Entered Correctly")
            print("Details Entered")
            print("Name :",fname,lname)
            print("Email :",email)
            print("Mobile :",mobile)
            print("Username :",uname)
            print("Password :",oldpass)
            print(newpass,' = ',confpass,' : ',newpass==confpass)
            # print("We get",request.files.getlist('image_files'),"as File")
            if request.files.getlist('image_file'):
                image=request.files.getlist('image_file')[0]
                # print("The new image path is :",os.path.join(app.config['UPLOAD_FOLDER'].replace('\\','/'),image.filename))
                print("And we get",image,"as File with filename :",image.filename)
                _, file_ext=os.path.splitext(image.filename)
                # print("Extracted file extention :",file_ext)
                random_filename=secrets.token_hex(8)
                # print("Random file name generated :",random_filename)
                new_filename=random_filename+file_ext
                print("New file name :",new_filename)
                # print("The uploading folder path is :",app.config['UPLOAD_FOLDER'].replace('\\','/'))
                # print("The root path is",app.root_path.replace('\\','/'))
                new_file_path=os.path.join(app.config['UPLOAD_FOLDER'],new_filename)
                print("The new path to store the image : ",new_file_path)
                image.save(new_file_path)
                i = Image.open(new_file_path)
                output_size = (200, 200)
                i.thumbnail(output_size)
                i.save(new_file_path)
                imgpath="/static/profile_pics/"+new_filename
                print("imgpath : "+imgpath)
                print(i)
                print("Image Saved!!!")
            else:
                print("No File Selected!")
            
            if newpass == confpass and newpass !='' and confpass!='' :
                newvalues['password']=crypt.generate_password_hash(newpass).decode('utf-8')
                print("Hash of New Password created :",newvalues['password'])
                print("New Password is safe")
            else:
                print("Password Doesn\'t Match")
            
            if email and email != logged_in_detail['email']:
                newvalues['email']=email
            else:
                newvalues['email']=logged_in_detail['email']
            
            if mobile and mobile != logged_in_detail['mobile']:
                newvalues['mobile']=mobile
            else:
                newvalues['mobile']=logged_in_detail['mobile']
            
            if uname and uname != logged_in_detail['username']:
                if not Users.find_one({'username':uname}):
                    newvalues['username']=uname
                else:
                    umsg=uname
            else:
                newvalues['username']=logged_in_detail['username']
            
            if imgpath:
                newvalues['image_file']=imgpath
            else:
                newvalues['image_file']=logged_in_detail['image_file']
            
            print("The Data Created :", newvalues)
            print("Data  Created for : ", logged_in_detail['first_name'])
            x=Users.update_one({'first_name': logged_in_detail['first_name']}, {'$set': newvalues})
            if x.modified_count:
                message='Changes Saved!'
                print(message)
            else:
                print("Any Error Occured in saving the Changes")
            logged_in_detail=check_data(newvalues['email'])
            print("Changed Logged in Data,",logged_in_detail['first_name'],logged_in_detail['image_file'])
    pre_data = {"email": email, "mobile": mobile, "uname": uname}
    if logged_in:
        print('Logged in Data :',logged_in_detail['first_name'],logged_in_detail['last_name'], logged_in_detail['image_file'])
    else:
        print("Not Logged In!")
    return render_template('account.html', title='Account', user=logged_in_detail, logged_in=logged_in, oldpass=oldpass, pd=pre_data, msg=message, umsg=umsg)

@app.route('/add_user', methods=['GET','POST'])
def add_user():
    message=None
    print(f"Logged In : {logged_in}")
    User_cursor = Users.find().sort("username")
    if request.method == 'POST':
        username=request.form.get('uname')
        if username:
            message=None
            print("Username to be Edited :",username)
            if Users.find_one({'username':username}):
                print("The Data found :",Users.find_one({'username':username}))
            else:
                message='Invalid Username!'
                print("Enter a Valid Username")
        else:
            print("Please Enter a Username")
    return render_template('addusers.html', usrcrsr=Users, message=message, title='Add User')

@app.route('/delete_user', methods=['GET','POST'])
def delete_user():
    message=None
    typed=None
    print(f"Logged In : {logged_in}")
    User_cursor = Users.find().sort('username')
    if request.method == 'POST':
        userid=request.form.get('uid')
        if userid:
            message=None
            print("User Name to be Edited :",userid)
            x=Users.find_one({'username':userid})
            if x:
                print("The Data found :",x)
                y=Users.delete_one({'username':userid})
                message=f"{y.deleted_count} Record Deleted!"
                typed="success"
                #return redirect(f'/update_cart/{userid}')
            else:
                message='Invalid Cart Id!'
                typed="danger"
                print("Enter a Valid Cart Id")
        else:
            print("Please Enter a Cart Id")
    return render_template('deleteuser.html', usrcrsr=Users, message=message, type=typed, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Delete User')

@app.route('/add_cart', methods=['GET','POST'])
def add_cart():
    message=None
    newvalue={}
    global logged_in_detail
    print(f"Logged In : {logged_in}")
    if logged_in_detail:
        print(f"Admin : {logged_in_detail['admin']}")
    if request.method == 'POST':
        message='\n'
        if len(list(Carts.find()))<10:  
            cid=None
            if request.form.get('cid') and request.form.get('cid') != '':
                print('Cart Found? : ',Carts.find_one({"_id":int(request.form.get('cid'))}))
                if Carts.find_one({"_id":int(request.form.get('cid'))}):
                    message='Cart Already Registered! | '
                else:
                    cid=int(request.form.get('cid'))
            else:
                cid=None
            status=request.form.get('status')
            use=request.form.get('use')
            if cid != '' and cid != None:
                newvalue['_id']=cid
            else:
                message = message + 'Select a Cart ID! | '
            
            if status != '':
                newvalue['status']=status
            else:
                message = message + 'Select the Cart Status! | '
            
            if use != '':
                newvalue['use']=use
            else:
                message = message + 'Select the Usage Status!'
            print('New Values going to be inserted : ',newvalue)
        else:
            message='All The Carts have been Registered!'
        if message == '\n':
            print("'"+message+"'")
            x = Carts.insert_one(newvalue)
            print("The Data Inserted for ID :",x.inserted_id)
            return redirect('/dashboard')
        else:
            print(f"The Message = '{message}'")
    return render_template('addcart.html', message=message, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Add Cart')

@app.route('/cart_details', methods=['GET','POST'])
def cart_details():
    message=None
    print(f"Logged In : {logged_in}")
    Cart_cursor = Carts.find().sort('_id')
    if request.method == 'POST':
        cartid=request.form.get('cid')
        if cartid:
            message=None
            print("Cart Id to be Edited :",cartid)
            x=Carts.find_one({'_id':int(cartid)})
            if x:
                print("The Data found :",x)
                return redirect(f'/update_cart/{cartid}')
            else:
                message='Invalid Cart Id!'
                print("Enter a Valid Cart Id")
        else:
            print("Please Enter a Cart Id")
    return render_template('carts.html', crtcrsr=Carts, message=message, logged_in=logged_in, title='Carts')

@app.route('/update_cart/<int:cid>', methods=['GET','POST'])
def update_cart(cid):
    print(f"Logged In : {logged_in}")
    if logged_in_detail:
        print(f"Admin : {logged_in_detail['admin']}")
    print("Data to be Updated :",cid,"with type : ",type(cid))
    x=Carts.find_one({'_id':int(cid)})
    if request.method == 'GET':
        if x:
            print("Data Present for id :",cid)
            return render_template('updatecart.html', cid=cid, cdata=x, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Update Cart')
    else:
        newvalue={}
        oldvalue={'_id':cid}
        status=request.form.get('status')
        if status == '':
            status='Cart Inactive'
        use=request.form.get('use')
        if use == '':
            use='Unused'
        newvalue['_id']=cid
        newvalue['status']=status
        newvalue['use']=use
        print("We Get the Update Values as ",newvalue)
        x=Carts.update_one(oldvalue,{'$set':newvalue})
        if x:
            print("Cart Details Updated!!")
            return redirect('/cart_details')
        else:
            print("Error in updating cart details")
    return render_template('updatecart.html', cid=cid, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Update Cart')

@app.route('/delete_cart', methods=['GET','POST'])
def delete_cart():
    message=None
    typed=None
    print(f"Logged In : {logged_in}")
    Cart_cursor = Carts.find().sort('_id')
    if request.method == 'POST':
        cartid=request.form.get('cid')
        if cartid:
            message=None
            print("Cart Id to be Edited :",cartid)
            x=Carts.find_one({'_id':int(cartid)})
            if x:
                print("The Data found :",x)
                y=Carts.delete_one({'_id':int(cartid)})
                message=f"{y.deleted_count} Record Deleted!"
                typed="success"
                #return redirect(f'/update_cart/{cartid}')
            else:
                message='Invalid Cart Id!'
                typed="danger"
                print("Enter a Valid Cart Id")
        else:
            print("Please Enter a Cart Id")
    return render_template('deletecart.html', crtcrsr=Carts, message=message, type=typed, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Delete Cart')

@app.route('/add_product', methods=['GET','POST'])
def add_product():
    message=None
    newvalue={}
    global logged_in_detail
    prodid='P' + str(random.randint(100,999))
    while Products.find_one({"_id":prodid}):
        prodid='P' + str(random.randint(100,999))
    print(f"Logged In : {logged_in}")
    print(f"The Assigning ID : {prodid}")
    if logged_in_detail:
        print(f"Admin : {logged_in_detail['admin']}")
    if request.method == 'POST':
        message='\n'
        # if request.form.get('prodid') and request.form.get('prodid') != '':
        #     prodid=request.form.get('prodid')
        # else:
        #     prodid=None
        prodname=request.form.get('prodname')
        price=request.form.get('price')
        barcode=request.form.get('barcode')
        category=request.form.get('category')
        # if prodid != '' and prodid != None:
        newvalue['_id']=prodid
        # else:
        #     message = message + 'Enter a Product ID! | '
        
        if prodname != '':
            newvalue['name']=prodname
        else:
            message = message + 'Enter the Product Name! | '
        
        if price != '':
            newvalue['price']=int(price)
        else:
            message = message + 'Enter the Product Price! | '
           
        if barcode != '':
            newvalue['barcode']=barcode
        else:
            message = message + 'Enter the Barcode! | '
        
        if category != '':
            newvalue['category']=category
        else:
            message = message + 'Enter the Product Category!'
        print('New Values going to be inserted : ',newvalue)
        if message == '\n':
            print("'"+message+"'")
            x = Products.insert_one(newvalue)
            print("The Data Inserted for ID :",x.inserted_id)
            return redirect('/dashboard')
        else:
            print(f"The Message = '{message}'")
    return render_template('addproduct.html', message=message, logged_in=logged_in, logged_in_detail=logged_in_detail, pid=prodid, title='Add Product')

@app.route('/product_details', methods=['GET','POST'])
def product_details():
    message=None
    print(f"Logged In : {logged_in}")
    Product_cursor = Products.find().sort('_id')
    if request.method == 'POST':
        prodid=request.form.get('pid')
        if prodid:
            message=None
            print("Product Id to be Edited :",prodid)
            x=Products.find_one({'_id':prodid})
            if x:
                print("The Data found :",x)
                return redirect(f'/update_product/{prodid}')
            else:
                message='Invalid Product Id!'
                print("Enter a Valid Product Id")
        else:
            print("Please Enter a Product Id")
    return render_template('products.html', prdcrsr=Products, message=message, logged_in=logged_in, title='Products')

@app.route('/update_product/<prodid>', methods=['GET','POST'])
def update_product(prodid):
    print(f"Logged In : {logged_in}")
    print("Data to be Updated :",prodid,"with type : ",type(prodid))
    x=Products.find_one({'_id':prodid})
    if request.method == 'GET':
        if x:
            print("Data Present for id :",prodid)
            return render_template('updateproduct.html', prodid=prodid, pdata=x, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Update Product Details')
    else:
        newvalue={}
        oldvalue={'_id':prodid}
        name=request.form.get('name')
        price=int(request.form.get('price'))
        barcode=request.form.get('barcode')
        category=request.form.get('category')
        newvalue['_id']=prodid
        newvalue['name']=name
        newvalue['price']=price
        newvalue['barcode']=barcode
        newvalue['category']=category
        print("We Get the Update Values as ",newvalue)
        x=Products.update_one(oldvalue,{'$set':newvalue})
        if x:
            print("Product Details Updated!!")
            return redirect('/product_details')
        else:
            print("Error in updating cart details")
    return render_template('updateproduct.html', prodid=prodid, logged_in=logged_in, logged_in_detail=logged_in_detail, title='Update Product')

@app.route('/add_customer_cart', methods=['GET','POST'])
def add_customer_cart():
    message=None
    newvalue={}
    global logged_in
    assignid='A' + str(random.randint(100,999))
    while Customer_Cart.find_one({"_id":assignid}):
        assignid='A' + str(random.randint(100,999))
    print(f"Logged In : {logged_in}")
    print(f"The Assigning ID : {assignid}")
    if request.method == 'POST':
        message='\n'
        cid=request.form.get('cid')
        used_date=request.form.get('used_date')
        prodid=request.form.get('prodid')
        quantity=request.form.get('quantity')
        billing=request.form.get('bill')
        newvalue['assign_id']=assignid
        if cid != '':
            newvalue['cart_id']=cid
        else:
            message = message + 'Select A Cart! | '

        if used_date:
            if used_date != '':
                newvalue['used_date']=used_date
            else:
                print('Unretrievable Date!')
        else:
            newvalue['used_date']=str(date.today())
        
        if prodid != '':
            newvalue['product_id']=prodid
        else:
            message = message + 'Select A Product ID! | '
        
        if quantity != '':
            newvalue['quantity']=quantity
        else:
            message = message + 'Select the Date! | '
        
        if billing != '':
            if billing == 'True':
                newvalue['billing']=True
            else:
                newvalue['billing']=False
        else:
            message = message + 'Select the Billing Status!'
        print('New Values going to be inserted : ',newvalue)
        if message == '\n':
            print("'"+message+"'")
            x = Customer_Cart.insert_one(newvalue)
            print("The Data Inserted for ID :",x.inserted_id)
            if newvalue['billing'] == True:
                return redirect(f'/add_bill/{assignid}')
            return redirect(f'/add_more_product/{assignid}/{cid}')
        else:
            print(f"The Message = '{message}'")
        if request.form.get('ptb'):
            print("Proceeding to Billing!")
            return redirect("/dashboard")
    return render_template('addcustomercart.html', message=message, aid=assignid, cst=Products, logged_in=logged_in, title='Add Customers\' Cart')

@app.route('/add_more_product/<assignid>/<cartid>', methods=['GET','POST'])
def add_more_product(assignid,cartid):
    message=None
    newvalue={}
    # assignid='A' + str(random.randint(100,999))
    # while Customer_Cart.find_one({"_id":assignid}):
    #     assignid='A' + str(random.randint(100,999))
    print(f"Logged In : {logged_in}")
    print(f"The Assigning ID : {assignid}")
    if request.method == 'POST':
        message='\n'
        cid=request.form.get('cid')
        used_date=request.form.get('used_date')
        prodid=request.form.get('prodid')
        quantity=request.form.get('quantity')
        billing=request.form.get('bill')
        newvalue['assign_id']=assignid
        if cid != '':
            newvalue['cart_id']=cid
        else:
            message = message + 'Select A Cart! | '

        if used_date:
            if used_date != '':
                newvalue['used_date']=used_date
            else:
                print('Unretrievable Date!')
        else:
            newvalue['used_date']=str(date.today())

        if prodid != '':
            newvalue['product_id']=prodid
        else:
            message = message + 'Select A Product ID! | '
        
        if quantity != '':
            newvalue['quantity']=quantity
        else:
            message = message + 'Select the Date! | '
        
        if billing != '':
            if billing == 'True':
                newvalue['billing']=True
            else:
                newvalue['billing']=False
        else:
            message = message + 'Select the Billing Status!'
        print('New Values going to be inserted : ',newvalue)
        if message == '\n':
            print("'"+message+"'")
            x = Customer_Cart.insert_one(newvalue)
            print("The Data Inserted for ID :",x.inserted_id)
        else:
            print(f"The Message = '{message}'")
        if request.form.get('ptb'):
            print("Proceeding to Billing!")
            x=Customer_Cart.update_many({"assign_id":assignid},{'$set':{"billing":True}})
            print("Data Modified Count :",x.modified_count)
            return redirect(f"/add_bill/{assignid}")
    return render_template('addcustomercart.html', message=message, aid=assignid, cartid=cartid, cst=Products, logged_in=logged_in, title='Add Customers\' Cart')

@app.route('/customer_cart_details', methods=['GET','POST'])
def customer_cart_details():
    message=None
    print(f"Logged In : {logged_in}")
    Product_cursor = Customer_Cart.find().sort('assign_id')
    if request.method == 'POST':
        ccid=request.form.get('ccid')
        if ccid!='' and ccid!=None:
            message=None
            print("Cart Id to be Edited :",ccid)
            c=Customer_Cart.find_one({'assign_id':ccid})
            if c:
                print("The Data found :",c,' With c[billing] : ',c['billing'])
                if c['billing']:
                    b=Billing.find_one({'assign_id':ccid})
                    print("Billing Id : ",b["_id"])
                    return redirect(f'/viewbill/{b["_id"]}')
                else:
                    return redirect(f'/add_bill/{ccid}')
            else:
                message='Invalid Cart Id!'
                print("Enter a Valid Cart Id")
        else:
            print("Please Enter a Cart Id")
    return render_template('customercart.html', cccrsr=Customer_Cart, message=message, logged_in=logged_in, title='Customers\' Cart Details')

@app.route('/view_customer_cart/<string:udate>', methods=['GET','POST'])
def view_ccart_details(udate):
    message=None
    ud=str(udate)
    print(f"Logged In : {logged_in}")
    assignset=set()
    for i in Customer_Cart.find():
        print('Assigned ID : ',i['assign_id'])
        if i['used_date']==ud:
            print("\tDate : ",i['used_date'])
            assignset.add(i['assign_id'])
    assignlist=list(assignset)
    print(f"The Assigned IDs Shopped on {ud} are : ",assignlist)
    cartlist=[]
    for i in assignlist:
        for j in Customer_Cart.find():
            if j['assign_id']==i:
                cartlist.append(j['cart_id'])
                break
    print(cartlist)
    for i in assignlist:
        print("Checking for Assigned ID :",i,'\nCart ID : ',list(set([j['cart_id'] for j in Customer_Cart.find() if j['assign_id']==i])),'\n\tProducts :')
        for j in [k['name'] for k in Products.find() if k['_id'] in [j['product_id'] for j in Customer_Cart.find() if j['assign_id']==i]]:
            print(j)
    return render_template('viewcustomercart.html', message=message, logged_in=logged_in, cc=Customer_Cart, products=Products, assignlist=assignlist, cartlist=cartlist, today=ud, title='Customer Cart Details')

@app.route('/view_customer_cart_by_date', methods=['GET','POST'])
def view_cc_by_date():
    message=None
    udate=str(date.today())
    print(f"Logged In : {logged_in}")
    Product_cursor = Customer_Cart.find().sort('assign_id')
    if request.method == 'POST':
        udate=request.form.get('udate')
        if udate!='' and udate!=None:
            message=None
            print("Date Selected :",udate)
            c=Customer_Cart.find_one({'used_date':udate})
            if c:
                print("Carts Have Been Used on this Date")
                return redirect(f'/view_customer_cart/{udate}')
            else:
                message='No Cart Used on this Date!'
                print("Select a Valid Date")
        else:
            print("Please Enter a Cart Id")
    return render_template('viewccbydate.html', cccrsr=Customer_Cart, message=message, logged_in=logged_in, udate=udate, title='Customer Cart Details By Date')

@app.route('/add_bill/<string:assignid>', methods=['GET','POST'])
def add_bill(assignid):
    global logged_in
    message=None
    newvalue={}
    bill_id='B' + str(random.randint(100,999))
    while Customer_Cart.find_one({"_id":bill_id}):
        bill_id='B' + str(random.randint(100,999))
    cart_id=None
    udate=None
    if Customer_Cart.find_one({"assign_id":assignid}):
        cart_id=Customer_Cart.find_one({"assign_id":assignid})['cart_id']
    if Customer_Cart.find_one({"assign_id":assignid}):
        udate=Customer_Cart.find_one({"assign_id":assignid})['used_date']
    print('Cart Id : ',cart_id)
    print(f"Logged In : {logged_in}")
    print(f"The Assigning ID : {bill_id}")
    if request.method == 'POST':
        cust_name=request.form.get('cname')
        cust_mobile=request.form.get('mob')
        total_items=0
        total_amount=0
        for i in Customer_Cart.find({"assign_id":assignid}):
            total_items=total_items+int(i['quantity'])
            total_amount=total_amount+int(Products.find_one({"_id":i['product_id']})['price']) * int(i['quantity'])
        total_amount=total_amount * 1.24
        print("Total : ",total_amount)
        newvalue['_id']=bill_id
        newvalue['assign_id']=assignid
        newvalue['cart_id']=cart_id
        newvalue['date']=udate
        newvalue['total_items']=str(total_items)
        newvalue['total_amount']=str(total_amount)[:str(total_amount).index(".")+3]
        newvalue['cust_name']=cust_name
        newvalue['cust_mobile']=cust_mobile
        print('New Values going to be inserted : ',newvalue)
        x = Billing.insert_one(newvalue)
        print("The Data Inserted for ID :",x.inserted_id)
        return redirect('/billing_details')
    return render_template('addbill.html', message=message, billid=bill_id, assignid=assignid, cid=cart_id, date=udate, cc=Customer_Cart, prd=Products, logged_in=logged_in, title='Add New Bill')

@app.route('/billing_details', methods=['GET','POST'])
def billing_details():
    message=None
    print(f"Logged In : {logged_in}")
    Product_cursor = Billing.find().sort('_id')
    if request.method == 'POST':
        billid=request.form.get('billid')
        if billid:
            message=None
            print("BIll Id to be Edited :",billid)
            if Billing.find_one({'_id':billid}):
                print("The Data found :",Billing.find_one({'_id':billid}))
                return redirect(f'/viewbill/{billid}')
            else:
                message='Invalid BIll Id!'
                print("Enter a Valid BIll Id")
        else:
            print("Please Enter a BIll Id")
    return render_template('billing.html', billcrsr=Billing, message=message, logged_in=logged_in, title='Billing Details')

@app.route('/viewbill/<string:billid>')
def viewbill(billid):
    print("Hello : "+billid,flush=True)
    billdetails=None
    if billid[0]=='B':
        billdetails=Billing.find_one({'_id':billid})
    print("The Bill Details : ",billdetails,flush=True)
    if not billdetails:
        print("Could Not Load DataSet!",flush=True)
    return render_template('viewbill.html', billid=billid, b=Billing, bd=billdetails, cc=Customer_Cart, prd=Products, title='View Billing Details')