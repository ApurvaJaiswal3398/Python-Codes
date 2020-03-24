from flask import render_template, url_for, redirect, request
from project import app, crypt, db, Users, Carts, Products, Customer_Cart, Billing
import secrets
import os
from PIL import Image

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
                return redirect('/')
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

@app.route('/account', methods=['GET','POST'])
def account():
    print(f"Logged In : {logged_in}")
    if request.method == "POST":
        # pic=save_picture(request.form.get("image_file"))
        # print("The IMage File PAth given is :", pic)
        print("the image is : ",request.form.get("image_file"))
        pic = save_picture(request.form.get("image_file"))
        print("received picture path :",pic)
    return render_template('account.html', title='Account', user=logged_in_detail, logged_in=logged_in)