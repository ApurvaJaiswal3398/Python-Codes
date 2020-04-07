from flask import render_template, url_for, redirect, request, flash
from project import app, crypt, db, Users, Carts, Products, Customer_Cart, Billing
import secrets
import os
from PIL import Image
from werkzeug.utils import secure_filename

logged_in = False
logged_in_detail = None
def check_data(email):
    query = {"email": email}
    x = Users.find_one(query)
    return x

@app.route('/')
def home():
    print(f"Logged In : {logged_in}")
    return render_template('layout.html', title='HomePage', logged_in=logged_in)

@app.route('/login', methods=['GET','POST'])
def login():
    message=None
    global logged_in
    global logged_in_detail
    if request.method=="POST":
        login_email = request.form.get('login_email')
        login_password = request.form.get('login_password')
        print("Login Detail : ",login_email, login_password)
        detail=check_data(login_email)
        logged_in_detail = detail
        if detail:
            if crypt.check_password_hash(detail["password"], login_password):
                print("Email and Password Matched, Login Successful")
                logged_in=True
                return redirect('/account')
            else:
                print("Password Not matched")
                message='Invalid Email or Password!'
                logged_in = False
            print(f"Password is {detail['password']} of type {type(detail['password'])}")
        else:
            print("Invalid Username")
            message='Invalid Email or Password!'
            logged_in = False
        # else:
        #     print("User could not be found")
        # if check_data(login_email, login_password):
        #     #crypt.check_password_hash(found["password"], login_password)
        #     print("Login Successful")
        # else:
        #     print("Invalid Email or Password")
        # else:
        #     print("Enter Details to either Login or Register Yourself")
    print(f"Logged In : {logged_in}")
    return render_template('login.html', title='Login', logged_in=logged_in, user=logged_in_detail, message=message)

def save_data(username, fname, lname, mobile, email, password, image="/static/profile_pics/default.jpg"):
    value = {"username":username,"first_name":fname, "last_name":lname, "mobile":mobile, "email":email, "password":password, "image_file":image}
    x = Users.insert_one(value)
    print("Data Inserted",x.inserted_id)

def is_present(key,value):
    query={key:value}
    x=Users.find_one(query)
    if x:
        return True
    else:
        return False

@app.route('/register', methods=['GET','POST'])
def register():
    message=None
    global logged_in
    alert="danger"
    if request.method == 'POST':
        reg_fname = request.form.get('firstname')
        reg_lname = request.form.get('lastname')
        reg_username = request.form.get('register_username')
        reg_mobile = request.form.get('mobile')
        reg_email = request.form.get('register_email')
        reg_password = request.form.get('register_password')
        reg_confirm = request.form.get('register_confirm')
        print(f"Username : {reg_username}, Name : {reg_fname} {reg_lname}, Mobile : {reg_mobile}, Email : {reg_email}, Password : {reg_password}, confirm : {reg_confirm}")
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
            save_data(reg_username, reg_fname, reg_lname, reg_mobile, reg_email, hashed_password)
            message='You Have Been Registered. You May Login!'
            alert="success"
    print(f"Logged In : {logged_in}")
    return render_template('register.html', title='Register', logged_in=logged_in, message=message, alert=alert)

@app.route('/dashboard')
def dashboard():
    User_cursor = Users.find().sort("username")
    Cart_cursor = Carts.find()
    Product_cursor = Products.find()
    Customer_cart_cursor = Customer_Cart.find()
    Billing_cursor = Billing.find()
    print(f"Logged In : {logged_in}")
    return render_template('dashboard.html', title='Dashboard', logged_in=logged_in, user=logged_in_detail, usrcrsr=User_cursor, crtcrsr=Cart_cursor, prdcrsr=Product_cursor, cccrsr=Customer_cart_cursor, bilcrsr=Billing_cursor)

@app.route('/logout')
def logout():
    global logged_in
    logged_in=False
    print(f"Logged in : {logged_in}")
    return redirect('/login')

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    print("random hex :",random_hex)
    _, f_ext = os.path.splitext(form_picture)
    picture_fn = random_hex + f_ext
    print("picture name :",picture_fn)
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn).replace('\\',"/")
    print("picture path :",picture_path)
    #form_picture.save(picture_path)
    output_size = (125, 125)
    # i = Image.open(picture_path)
    # i.thumbnail(output_size)
    # i.save(picture_path)
    # print(picture_fn)
    return picture_fn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'png', 'jpeg', 'gif'}

@app.route('/account', methods=['GET','POST'])
def account():
    print(f"Logged In : {logged_in}")
    oldpass=None
    if request.method == "POST":
        # pic=save_picture(request.form.get("image_file"))
        # print("The IMage File PAth given is :", pic)
        print("Files Extraced :",request.files)
        print("The user is :",logged_in_detail['first_name'],logged_in_detail['last_name'])
        # if 'image_file' not in request.files:
        #     print('No file part')
        #     return redirect(request.url)
        # file = request.files['image_file']
        # print(file)
        # if file.filename == '':
        #     flash('No selected file')
        #     return redirect(request.url)
        # if file and allowed_file(file.filename):
        #     filename = secure_filename(file.filename)
        #     file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        #     print('File Saved to',app.config['UPLOAD_FOLDER'])
            #return redirect(url_for('uploaded_file',filename=filename))
        # pic = save_picture(request.form.get("image_file"))
        # print("received picture path :",pic)

        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        mobile=request.form.get('mobile')
        uname=request.form.get('uname')
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
            print("We get",request.files.getlist('image_files'),"as File")
            # image=request.files.getlist('image_file')[0]
            # print("And we get",image,"as File with filename :",image.filename)
            # print("We Also get",request.files['image_file'],"of type :",type(request.files['image_file']))
            if request.files.getlist('image_file'):
                image=request.files.getlist('image_file')[0]
                print("The new image path is :",os.path.join(app.config['UPLOAD_FOLDER'],image.filename))
                print("And we get",image,"as File with filename :",image.filename)
                print("We Also get",request.files['image_file'],"of type :",type(request.files['image_file']))
                _, file_ext=os.path.splitext(image.filename)
                print("Extracted file extention :",file_ext)
                random_filename=secrets.token_hex(8)
                print("Random file name generated :",random_filename)
                new_filename=random_filename+file_ext
                print("New file name :",new_filename)
                print("The uploading folder path is :",app.config['UPLOAD_FOLDER'])
                print("The root path is",app.root_path.replace('\\','/'))
                new_file_path=os.path.join(app.config['UPLOAD_FOLDER'],new_filename)
                print("The new path to store the image : ",new_file_path)
                image.save(new_file_path)   #this line creates an error (FileNotFoundError)
                print("Image Saved!!!")
            else:
                print("No File Selected!")
        if newpass == confpass:
            print("New Password is safe")
        else:
            print("Password Doesn\'t Match")
    return render_template('account.html', title='Account', user=logged_in_detail, logged_in=logged_in, oldpass=oldpass)