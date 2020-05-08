from flask import render_template, url_for, redirect, request, flash
from project import app, crypt, db, Users, Carts, Products, Customer_Cart, Billing
import secrets
import random
import os
from PIL import Image
from werkzeug.utils import secure_filename
from datetime import date

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
    email=None
    mobile=None
    uname=None
    oldpass=None
    imgpath=None
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
                newvalues['username']=uname
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
                print("Changes Saved!")
            else:
                print("Any Error Occured in saving the Changes")
            logged_in_detail=check_data(newvalues['email'])
            print("Changed Logged in Data,",logged_in_detail['first_name'],logged_in_detail['image_file'])
    pre_data = {"email": email, "mobile": mobile, "uname": uname}
    print('Logged in Data :',logged_in_detail['first_name'],logged_in_detail['last_name'], logged_in_detail['image_file'])
    return render_template('account.html', title='Account', user=logged_in_detail, logged_in=logged_in, oldpass=oldpass, pd=pre_data)

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
    return render_template('addusers.html', usrcrsr=Users, message=message)

@app.route('/add_cart', methods=['GET','POST'])
def add_cart():
    message=None
    newvalue={}
    print(f"Logged In : {logged_in}")
    if request.method == 'POST':
        message='\n'
        if request.form.get('cid') and request.form.get('cid') != '':
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
        if message == '\n':
            print("'"+message+"'")
            x = Carts.insert_one(newvalue)
            print("The Data Inserted for ID :",x.inserted_id)
            return redirect('/dashboard')
        else:
            print(f"The Message = '{message}'")
    return render_template('addcart.html', message=message)

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
    return render_template('carts.html', crtcrsr=Carts, message=message)

@app.route('/update_cart/<int:cid>', methods=['GET','POST'])
def update_cart(cid):
    print(f"Logged In : {logged_in}")
    print("Data to be Updated :",cid,"with type : ",type(cid))
    x=Carts.find_one({'_id':int(cid)})
    if request.method == 'GET':
        if x:
            print("Data Present for id :",cid)
            return render_template('updatecart.html', cid=cid, cdata=x)
    else:
        newvalue={}
        oldvalue={'_id':cid}
        status=request.form.get('status')
        use=request.form.get('use')
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
    return render_template('updatecart.html', cid=cid)

@app.route('/add_product', methods=['GET','POST'])
def add_product():
    message=None
    newvalue={}
    print(f"Logged In : {logged_in}")
    if request.method == 'POST':
        message='\n'
        if request.form.get('prodid') and request.form.get('prodid') != '':
            prodid=request.form.get('prodid')
        else:
            prodid=None
        prodname=request.form.get('prodname')
        price=request.form.get('price')
        barcode=request.form.get('barcode')
        category=request.form.get('category')
        if prodid != '' and prodid != None:
            newvalue['_id']=prodid
        else:
            message = message + 'Enter a Product ID! | '
        
        if prodname != '':
            newvalue['name']=prodname
        else:
            message = message + 'Enter the Product Name! | '
        
        if price != '':
            newvalue['price']=price
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
    return render_template('addproduct.html', message=message)

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
    return render_template('products.html', prdcrsr=Products, message=message)

@app.route('/update_product/<prodid>', methods=['GET','POST'])
def update_product(prodid):
    print(f"Logged In : {logged_in}")
    print("Data to be Updated :",prodid,"with type : ",type(prodid))
    x=Products.find_one({'_id':prodid})
    if request.method == 'GET':
        if x:
            print("Data Present for id :",prodid)
            return render_template('updateproduct.html', prodid=prodid, pdata=x)
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
    return render_template('updateproduct.html', prodid=prodid)

@app.route('/add_customer_cart', methods=['GET','POST'])
def add_customer_cart():
    message=None
    newvalue={}
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
            return redirect(f'/add_more_product/{assignid}/{cid}')
        else:
            print(f"The Message = '{message}'")
        if request.form.get('ptb'):
            print("Proceeding to Billing!")
            return redirect("/dashboard")
    return render_template('addcustomercart.html', message=message, aid=assignid, cst=Products)

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
    return render_template('addcustomercart.html', message=message, aid=assignid, cartid=cartid, cst=Products)

@app.route('/customer_cart_details', methods=['GET','POST'])
def customer_cart_details():
    message=None
    print(f"Logged In : {logged_in}")
    Product_cursor = Customer_Cart.find().sort('_id')
    if request.method == 'POST':
        ccid=request.form.get('ccid')
        if ccid:
            message=None
            print("Cart Id to be Edited :",ccid)
            if Customer_Cart.find_one({'_id':int(ccid)}):
                print("The Data found :",Customer_Cart.find_one({'_id':int(ccid)}))
            else:
                message='Invalid Cart Id!'
                print("Enter a Valid Cart Id")
        else:
            print("Please Enter a Cart Id")
    return render_template('customercart.html', cccrsr=Customer_Cart, message=message)

@app.route('/add_bill/<string:assignid>', methods=['GET','POST'])
def add_bill(assignid):
    message=None
    newvalue={} 
    billid='B' + str(random.randint(100,999))
    while Customer_Cart.find_one({"_id":billid}):
        billid='B' + str(random.randint(100,999))
    cid=None
    udate=None
    if Customer_Cart.find_one({"assign_id":assignid}):
        cid=Customer_Cart.find_one({"assign_id":assignid})['cart_id']
    if Customer_Cart.find_one({"assign_id":assignid}):
        udate=Customer_Cart.find_one({"assign_id":assignid})['used_date']
    print('Cart Id : ',cid)
    print(f"Logged In : {logged_in}")
    print(f"The Assigning ID : {billid}")
    return render_template('addbill.html', message=message, billid=billid, assignid=assignid, cid=cid, date=udate, cc=Customer_Cart, prd=Products)

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
            if Billing.find_one({'_id':int(billid)}):
                print("The Data found :",Billing.find_one({'_id':int(billid)}))
            else:
                message='Invalid BIll Id!'
                print("Enter a Valid BIll Id")
        else:
            print("Please Enter a BIll Id")
    return render_template('billing.html', billcrsr=Billing, message=message)

@app.route('/invoice')
def invoice():
    return render_template('new.html')