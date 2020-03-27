from flask import Flask,  render_template,  flash, redirect, url_for, session,  request, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update
from flask_login import LoginManager, UserMixin,  \
    AnonymousUserMixin
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
import random
import os
import sys
import sqlite3
import smtplib
from smtplib import SMTPException, SMTP
from flask_mail import Mail, Message
from flask_wtf import Form, FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from base64 import b64encode
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

import cloudinary
import cloudinary.uploader
import cloudinary.api
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url



from flask_dance.contrib.github import make_github_blueprint,github

cloudinary.config(
  cloud_name = "harshkumarkhatri",
  api_key = "189777582685733",
  api_secret = "_66utVOprVTnRO3-ORv4LJHXtkg"
)


allowed_extensions={'jpg','jpeg','png'}

from dateutil import parser

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gymaale.buisness@gmail.com'
app.config['MAIL_PASSWORD'] = 'Harsh96722'

db = SQLAlchemy(app)
app.secret_key = '1234'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

pub_key = 'pk_test_j5M62wU5aump7Ige6RRL6bG300GBcA0F6i'
secret_key = 'sk_test_ZDdijuYIjxaiLE15uvr0CE7v00E9LxRqoN'
admin = Admin(app)
ADMINS = ['mailharshkhatri@gmail.com']

app.config.from_object("config")
host_name='http://localhost:5000'

import boto3
import util
bucket_name=os.environ['PHOTOS_BUCKET']


mail = Mail(app)

github_blueprint=make_github_blueprint(client_id='0e8ce40fec92a01494ad',client_secret='de00d9669d3c8bc3a231f61141c7d6b2c926f5e1')
app.register_blueprint(github_blueprint,url_prefix='/github_login')

class user(db.Model, UserMixin, AnonymousUserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password = db.Column(db.String(80))
    mails = db.relationship('dmail')
    sec_code = db.Column(db.Integer)
    verification = db.Column(db.String(20))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return user.query.get(user_id)

    def get_confirmation_token(self, expires_sec=86400):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_confirmation_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return user.query.get(user_id)


class MyModelView(ModelView):
    def is_accessible(self):
        mm = admindata.query.filter_by(username=g.user).first()
        if mm.username:
            mm = True
        else:
            mm = False
        return mm


class dmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, email, owner_id):
        if email:
            self.email = email
        else:
            self.email = None
        if owner_id:
            self.owner_id = owner_id
        else:
            self.owner_id = None


class admindata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(80))
    email = db.Column(db.String(120))
    security_code = db.Column(db.Integer)

    def __init__(self, username, password, email, security_code):
        if username:
            self.username = username
        else:
            self.username = None
        if password:
            self.password = password
        else:
            self.password = None
        if email:
            self.email = email
        else:
            self.email = None
        if security_code:
            self.security_code = security_code
        else:
            self.security_code = None


class user_data2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(40))
    last_name = db.Column(db.String(40))
    address = db.Column(db.String(200))
    age = db.Column(db.Integer)
    interest = db.Column(db.String(70))
    already_gymming = db.Column(db.String(20))
    time = db.Column(db.String(70))
    update = db.Column(db.String(30))
    user_id = db.Column(db.Integer)

    def __init__(self, first_name, last_name, address, age, interest, already_gymming, time, update, user_id):
        if first_name:
            self.first_name = first_name
        else:
            self.first_name = None
        if last_name:
            self.last_name = last_name
        else:
            self.last_name = None
        if address:
            self.address = address
        else:
            self.address = None
        if age:
            self.age = age
        else:
            self.age = None
        if interest:
            self.interest = interest
        else:
            self.interest = None
        if already_gymming:
            self.already_gymming = already_gymming
        else:
            self.already_gymming = None
        if update:
            self.update = update
        else:
            self.update = None
        if user_id:
            self.user_id = user_id
        else:
            self.user_id = None
        if time:
            self.time = time
        else:
            self.time = None


class ownerregister(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40))
    email = db.Column(db.String(140))
    password = db.Column(db.String(40))
    confirm_password = db.Column(db.String(40))
    security_code = db.Column(db.String(10))

    def __init__(self, username, password, confirm_password, email, security_code):
        if username:
            self.username = username
        else:
            self.username = None
        if password:
            self.password = password
        else:
            self.password = None
        if email:
            self.email = email
        else:
            self.email = None
        if security_code:
            self.security_code = security_code
        else:
            self.security_code = None
        if confirm_password:
            self.confirm_password = confirm_password
        else:
            self.confirm_password = None


class owner_detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(40))
    last_name = db.Column(db.String(40))
    address = db.Column(db.Text)
    mobile_number = db.Column(db.String(10))
    age = db.Column(db.Integer)
    already_training = db.Column(db.String(20))
    time = db.Column(db.String(50))
    u_trainer = db.Column(db.String(20))
    owner_reg_id = db.Column(db.Integer)
    any_other_gym = db.Column(db.String(40))

    def __init__(self, first_name, last_name, address, mobile_number, age,
                 already_training, time, u_trainer, owner_reg_id, any_other_gym):
        if first_name:
            self.first_name = first_name
        else:
            self.first_name = None
        if last_name:
            self.last_name = self.last_name
        else:
            self.last_name = None
        if address:
            self.address = address
        else:
            self.address = None
        if mobile_number:
            self.mobile_number = mobile_number
        else:
            self.mobile_number = None
        if age:
            self.age = age
        else:
            self.age = None
        if already_training:
            self.already_training = already_training
        else:
            self.already_training = None
        if time:
            self.time = time
        else:
            self.time = None
        if u_trainer:
            self.u_trainer = u_trainer
        else:
            self.u_trainer = None
        if owner_reg_id:
            self.owner_reg_id = owner_reg_id
        else:
            self.owner_reg_id = None
        if any_other_gym:
            self.any_other_gym = any_other_gym
        else:
            self.any_other_gym = None


class gym_detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gym_name = db.Column(db.String(100))
    address_1 = db.Column(db.Text)
    address_2 = db.Column(db.Text)
    contact_number = db.Column(db.String(10))
    state = db.Column(db.String(30))
    city = db.Column(db.String(50))
    postal_code = db.Column(db.Integer)
    monthly_fees = db.Column(db.Integer)
    yearly_fees = db.Column(db.Integer)
    trainers_available = db.Column(db.String(20))
    features = db.Column(db.Text)
    estlb = db.Column(db.Integer)
    desc = db.Column(db.Text)
    owner_ref = db.Column(db.Integer)
    m_open = db.Column(db.Integer)
    m_close = db.Column(db.Integer)
    e_open = db.Column(db.Integer)
    e_close = db.Column(db.Integer)
    cb = db.Column(db.String(40))

    def __init__(self, gym_name, address_1, address_2, contact_number, state, city, postal_code, monthly_fees,
                 yearly_fees
                 , trainers_available, features, estlb, desc, owner_ref, m_open, m_close, e_open, e_close, cb):
        if gym_name:
            self.gym_name = gym_name
        else:
            self.gym_name = None
        if address_1:
            self.address_1 = address_1
        else:
            self.address_1 = None
        if address_2:
            self.address_2 = address_2
        else:
            self.address_2 = None
        if contact_number:
            self.contact_number = contact_number
        else:
            self.contact_number = None
        if state:
            self.state = state
        else:
            self.state = None
        if city:
            self.city = city
        else:
            self.city = None
        if postal_code:
            self.postal_code = postal_code
        else:
            self.postal_code = None
        if monthly_fees:
            self.monthly_fees = monthly_fees
        else:
            self.monthly_fees = None
        if yearly_fees:
            self.yearly_fees = yearly_fees
        else:
            self.yearly_fees = None
        if trainers_available:
            self.trainers_available = trainers_available
        else:
            self.trainers_available = None
        if features:
            self.features = features
        else:
            self.features = None
        if estlb:
            self.estlb = estlb
        else:
            self.estlb = None
        if desc:
            self.desc = desc
        else:
            self.desc = None
        if m_open:
            self.m_open = m_open
        else:
            self.m_open = None
        if m_close:
            self.m_close = m_close
        else:
            self.m_close = None
        if e_open:
            self.e_open = e_open
        else:
            self.e_open = None
        if e_close:
            self.e_close = e_close
        else:
            self.e_close = None
        if owner_ref:
            self.owner_ref = owner_ref
        else:
            self.owner_ref = None
        if cb:
            self.cb = cb
        else:
            self.cb = None


class gym_image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref_id = db.Column(db.Integer)
    image_1_link=db.Column(db.String(5000))
    image_2_link=db.Column(db.String(5000))
    image_3_link=db.Column(db.String(5000))
    image_4_link=db.Column(db.String(5000))
    image_5_link=db.Column(db.String(5000))

    def __init__(self, ref_id, image_1_link,image_2_link,image_3_link,image_4_link,image_5_link):
        if ref_id:
            self.ref_id = ref_id
        else:
            self.ref_id = None
        if image_1_link:
            self.image_1_link = image_1_link
        else:
            self.image_1_link = None
        if image_2_link:
            self.image_2_link = image_2_link
        else:
            self.image_2_link = None
        if image_3_link:
            self.image_3_link = image_3_link
        else:
            self.image_3_link = None
        if image_4_link:
            self.image_4_link = image_4_link
        else:
            self.image_4_link = None
        if image_5_link:
            self.image_5_link = image_5_link
        else:
            self.image_5_link = None


class trainer_image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref_id = db.Column(db.Integer)
    owner_ref_id = db.Column(db.Integer)
    image_1_link=db.Column(db.String(5000))
    image_2_link=db.Column(db.String(5000))
    image_3_link=db.Column(db.String(5000))
    image_4_link=db.Column(db.String(5000))
    image_5_link=db.Column(db.String(5000))

    def __init__(self, ref_id, owner_ref_id, image_1_link, image_2_link, image_3_link, image_4_link, image_5_link):
        if ref_id:
            self.ref_id = ref_id
        else:
            self.ref_id = None
        if owner_ref_id:
            self.owner_ref_id = owner_ref_id
        else:
            self.owner_ref_id = None
        if image_1_link:
            self.image_1_link = image_1_link
        else:
            self.image_1_link = None
        if image_2_link:
            self.image_2_link = image_2_link
        else:
            self.image_2_link = None
        if image_3_link:
            self.image_3_link = image_3_link
        else:
            self.image_3_link = None
        if image_4_link:
            self.image_4_link = image_4_link
        else:
            self.image_4_link = None
        if image_5_link:
            self.image_5_link = image_5_link
        else:
            self.image_5_link = None


class hours(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    m_open = db.Column(db.Integer)
    m_close = db.Column(db.Integer)
    e_open = db.Column(db.Integer)
    e_close = db.Column(db.Integer)
    m_hours = db.Column(db.Integer)
    e_hours = db.Column(db.Integer)


class blog2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    date = db.Column(db.DATETIME)
    b_txt = db.Column(db.Text)

    def __init__(self, title, date, b_txt):
        if title:
            self.title = title
        else:
            self.title = None
        if date:
            self.date = date
        else:
            self.date = None
        if b_txt:
            self.b_txt = b_txt
        else:
            self.b_txt = None


class image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    ibt = db.Column(db.String(99))
    file_name = db.Column(db.String(500))
    image_link=db.Column(db.String(5000))

    def __init__(self, user_id, ibt, file_name, image_link):
        if user_id:
            self.user_id = user_id
        else:
            self.user_id = None
        if ibt:
            self.ibt = ibt
        else:
            self.ibt = None
        if file_name:
            self.file_name = file_name
        else:
            self.file_name = None
        if image_link:
            self.image_link = image_link
        else:
            self.image_link = None


class trainerregister(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40))
    email = db.Column(db.String(140))
    password = db.Column(db.String(40))

    def __init__(self, username, email, password):
        if username:
            self.username = username
        else:
            self.username = None
        if email:
            self.email = email
        else:
            self.email = None
        if password:
            self.password = password
        else:
            self.password = None


class trainer_detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    address = db.Column(db.String(200))
    state = db.Column(db.String(40))
    city = db.Column(db.String(40))
    charges=db.Column(db.Integer)
    c_mail = db.Column(db.String(70))  # mail for customers
    p_mob = db.Column(db.Integer)  # personal mobile number
    c_mob = db.Column(db.Integer)  # phone number for customers
    age = db.Column(db.Integer)
    t_time = db.Column(db.String(40))
    certifications = db.Column(db.String(50))
    training_mode = db.Column(db.String(30))  # mode in which training will be provided to the users.
    diet_support = db.Column(db.String(30))
    training_support = db.Column(db.String(30))
    insta_link = db.Column(db.String(300))
    youtube_link = db.Column(db.String(300))
    desc = db.Column(db.Text)
    ref_id = db.Column(db.Integer)
    owner_ref_id = db.Column(db.Integer)
    cb = db.Column(db.String(40))
    verified = db.Column(db.String(40))

    def __init__(self, first_name, last_name, address, state, city,charges, c_mail, p_mob, c_mob, age, t_time, certifications,
                 training_mode
                 , diet_support, training_support, insta_link, youtube_link, desc, ref_id, owner_ref_id, cb, verified):
        self.first_name = first_name
        self.last_name = last_name
        self.address = address
        self.state = state
        self.city = city
        self.charges=charges
        self.c_mail = c_mail
        self.p_mob = p_mob
        if c_mob:
            self.c_mob = c_mob
        else:
            self.c_mob = None
        self.age = age
        self.t_time = t_time
        if certifications:
            self.certifications = certifications
        else:
            self.certifications = None
        self.training_mode = training_mode
        self.diet_support = diet_support
        self.training_support = training_support
        self.insta_link = insta_link
        if youtube_link:
            self.youtube_link = youtube_link
        else:
            self.youtube_link = None
        self.desc = desc
        self.ref_id = ref_id
        self.owner_ref_id = owner_ref_id
        self.cb = cb
        if verified:
            self.verified = verified
        else:
            self.verified = None

class wallet_all(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    ref_id=db.Column(db.Integer)
    ref_type=db.Column(db.String(40))
    ammount=db.Column(db.Integer)


class github_user(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100))
    password=db.Column(db.String(40))
    email=db.Column(db.String(100))
    image_link=db.Column(db.String(5000))
    first_name=db.Column(db.String(40))
    last_name=db.Column(db.String(40))
    address=db.Column(db.String(200))
    age=db.Column(db.Integer)
    interest=db.Column(db.String(70))
    already_gymming=db.Column(db.String(40))
    time=db.Column(db.String(40))
    update=db.Column(db.String(30))

    def __init__(self,username,password,email,image_link,first_name,last_name,address,age,interest
                 ,already_gymming,time,update):
        if username:
            self.username=username
        else:
            self.username=None
        if password:
            self.password=password
        else:
            self.password=None
        if email:
            self.email=email
        else:
            self.email=None
        if image_link:
            self.image_link=image_link
        else:
            self.image_link=None
        if first_name:
            self.first_name=first_name
        else:
            self.first_name=None
        if last_name:
            self.last_name=last_name
        else:
            self.last_name=None
        if address:
            self.address=address
        else:
            self.address=None
        if age:
            self.age=age
        else:
            self.age=None
        if interest:
            self.interest=interest
        else:
            self.interest=None
        if already_gymming:
            self.already_gymming=already_gymming
        else:
            self.already_gymming=None
        if time:
            self.time=time
        else:
            self.time=None
        if update:
            self.update=update
        else:
            self.update=None



"""class blog(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100),nullable=False)
    date_posted=db.Column(db.DateTime,nullable=False, default=datetime.utcnow)
    content=db.Column(db.Text,nullable=False)

    def __repr__(self):
        return user('{self.title}','{sel.date_posted}','{self.content}')
"""


def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to log in first')
            return redirect(url_for('login'))

    return wrap


def owner_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'owner' in session:
            return f(*args, **kwargs)
        else:
            flash("Owner needs to login first to log in first")
            return redirect(url_for('gym_registeration_login'))

    return wrap


def trainer_login_requires(m):
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'trainer' in session:
            return m(*args, **kwargs)
        else:
            flash("Trainer must login first to access this page")
            return redirect(url_for())

    return wrap


@login_manager.user_loader
def load_user(user_id):
    return user.get(user_id)


@app.route("/")
def index():
    return render_template("major.html")

@app.route('/oauth_log')
def oauth_log():
    return '<a id="github-button" class="btn btn-block btn-social btn-github"><i class="fa fa-github"></i> Sign in with Github</a>' \
           '<h1><a href=http://localhost:5000/github>Login with github</a><h1>'

@app.route('/github')
def github_login():
    session.pop('logged_in',None)
    if not github.authorized:
        return redirect(url_for('github.login'))

    account_info = github.get('/user')

    if account_info.ok:
        account_info_json = account_info.json()
        print(account_info_json['email'])
        session['logged_in']=account_info_json['login']
        print(account_info_json['id'])
        qur=github_user.query.filter_by(username=account_info_json['login']).first()
        if account_info_json['login']==qur.username:
            return redirect(url_for('add_email'))
        else:
            email='NULL'
            image_link='NULL'
            first_name='NULL'
            last_name='NULL'
            address='NULL'
            age=0
            interest='NULL'
            already_gymming='NULL'
            time='NULL'
            update='NULL'
            adding=github_user(username=account_info_json['login'],password=account_info_json['id'],email=email,
                               image_link=image_link,update=update,first_name=first_name,last_name=last_name,
                               address=address,age=age,interest=interest,already_gymming=already_gymming,time=time)
            db.session.add(adding)
            db.session.commit()
            return redirect(url_for('add_email')) ,flash('your user name is '+account_info_json['login'])

    return '<h1>Request failed</h1>'

#asking for the email for github users.
@app.route('/add_email',methods=['GET','POST'])
def add_email():
    m=g.user
    qur1 = github_user.query.filter_by(username=m).first()
    print(m)
    if qur1.email!='NULL':
        return redirect(url_for('add_details'))
    else:
        if request.method=="POST":
            mail=request.form['mail']
            qur=github_user.query.filter_by(username=m).first()
            qur.email=mail
            db.session.commit()
            return redirect(url_for('add_details'))

    return render_template('add_github_mail.html')

#asking for the details of github user.
@app.route('/add_details',methods=['GET','POST'])
def add_details():
    m=g.user
    print(m)
    qur1=github_user.query.filter_by(username=m).first()
    if qur1.image_link!='NULL' and qur1.first_name!='NULL':
        return redirect(url_for('main'))
    else:
        qur=github_user.query.filter_by(username=m).first()
        if request.method=='POST':
            first_name=request.form['first_name']
            last_name=request.form['last_name']
            address=request.form['address']
            age=request.form['gender']
            interest=request.form['interest']
            already_gymming=request.form['ag']
            time=request.form['time']
            update=request.form['up']
            file=request.files['file']
            zz=file.filename.rsplit(".",1)[1].lower()
            if zz in allowed_extensions:
                if file:
                    upload_result = cloudinary.uploader.upload(file, folder="profile_pictures", width=200, height=100)
                    print(upload_result['url'])
                    print(file)
                    qur.first_name=first_name
                    qur.last_name=last_name
                    qur.address=address
                    qur.age=age
                    qur.interest=interest
                    qur.already_gymming=already_gymming
                    qur.time=time
                    qur.update=update
                    db.session.commit()
                    return redirect(url_for('main'))
            else:
                flash("Invalid extension of the image or some other error")
                return redirect(url_for('add_details'))
    return render_template('add_github_details.html')



def send_reset_email(data):
    token = data['token']
    link=data['link']
    with app.app_context():
        msg = Message('Password Reset Request', sender='gymaale.buisness@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_message_for_reset.html",link=link,faq=data['faq_link'], token=token, _external=True)
        mail.send(msg)


def send_confirmation_email(data):
    with app.app_context():
        msg = Message('Email Confirmation', sender='gymaale.buisness@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_message.html",faq=data['faq_link'],sec_code=data['sec_code'],  token=data['token'],link=data['link'], _external=True)
        mail.send(msg)


@app.route('/forgot_request', methods=["GET", "POST"])
def forgot_request():
    if request.method == "POST":
        cmail = request.form['cmail']
        z = user.query.filter_by(email=cmail).first()
        if z is not None:
            data={}
            data['email']=z.email
            token=z.get_reset_token()
            data['token']=token
            data['link']=f'{host_name}/reset_password/'+token
            data['faq_link']=f'{host_name}/faqs'
            print(data['link'])
            print(token)
            send_reset_email(data)
            flash("EMAIL SENT")
            return redirect(url_for('login'))
        else:
            return redirect(url_for('register')), flash("Register first")
    return render_template("forgot_request.html")


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    z = user.verify_reset_token(token)
    if z is None:
        flash('Invalid or Expired Token')
        return redirect(url_for('forgot_request'))
    else:
        value1 = z.username
        value2 = z.email
        print(z)
        print(value1, value2)
    if request.method == "POST":
        npass = request.form['npass']
        npassw = request.form['npassw']
        hashed_value = generate_password_hash(npass)
        z.password = hashed_value
        db.session.commit()
        flash("Password updated")
        """user.query.filter_by(username=value1).delete()
        db.session.commit()
        nu = user(username=value1, password=npass, email=value2)
        db.session.add(nu)
        db.session.commit()
"""
        data={}
        data['email']=value2
        data['faq_link']=f'{host_name}/faqs'
        send_password_reset_successful(data)
        return redirect(url_for('login'))
    return render_template("reset_password.html")



def send_password_reset_successful(data):
    with app.app_context():
        msg = Message('Password reset successful', sender='gymaale.business@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_password_reset_successful.html",faq=data['faq_link'], _external=True)
        mail.send(msg)


@app.route('/main', methods=["GET", "POST"])
@login_required
def main():
    b_posts = blog2.query.all()
    if g.user:
        print(g.user)
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
        return redirect(url_for('main')), flash("You have been subscribed.")
    return render_template("index.html", b_posts=b_posts)


@app.route('/user_data', methods=["GET", "POST"])
@login_required
def user_data():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    mm = user_data2.query.filter_by(user_id=value1).first()
    if mm:
        return redirect(url_for('main'))
    else:
        if request.method == "POST":
            iid = value1
            fir_name = request.form["fname"]
            la_name = request.form["lname"]
            addr = request.form["add"]
            umar = request.form["gender"]
            pref = request.form["intr"]
            at = request.form["ag"]
            exp = request.form["ex"]
            upd = request.form["up"]
            todo = user_data2(first_name=fir_name, last_name=la_name, address=addr, age=umar, interest=pref,
                              already_gymming=at, time=exp, update=upd, user_id=iid)
            db.session.add(todo)
            db.session.commit()
            return redirect(url_for('main')), flash("Data submitted successfully")
    return render_template("know.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    r_no = random.randrange(0000, 9999)
    if request.method == "POST":
        uname = request.form['uname']
        mail = request.form['mail']
        passw = request.form['passw']
        hashed_value = generate_password_hash(passw)
        passw2 = request.form['passw2']
        sec_code = r_no
        verification = "No"
        if passw == passw2:
            m = user.query.filter_by(username=uname).first()
            n = user.query.filter_by(email=mail).first()
            if m:
                flash('Username is already taken')
                return redirect(url_for('register'))
            if n:
                flash('Email is already taken')
                return redirect(url_for('register'))
            register = user(username=uname, email=mail, password=hashed_value,
                            sec_code=sec_code, verification=verification)
            db.session.add(register)
            db.session.commit()
            getting_above_user_id=user.query.filter_by(username=uname).first()
            addingToWallet=wallet_all(ref_id=getting_above_user_id.id,ref_type='user',ammount=0)
            db.session.add(addingToWallet)
            db.session.commit()
            z = user.query.filter_by(email=mail).first()
            data={}
            data['email']=z.email
            data['token']=z.get_reset_token()
            data['link']=f'{host_name}/registerr/'+data['token']+'/'+z.username
            data['sec_code']=z.sec_code
            data['faq_link']=f'{host_name}/faqs'
            if z is not None:
                send_confirmation_email(data)
            return redirect(url_for('waiting'))
        else:
            flash('Passwords do not match.')
    return render_template("register.html")


@app.route('/admin_register', methods=["GET", "POST"])
def admin_register():
    mm = random.randrange(0000, 9999)
    if request.method == "POST":
        uname = request.form['uname']
        passw = request.form['passw']
        email = request.form['email']
        sec_code = request.form['sec_code']

        zz = admindata.query.filter_by(username=uname).first()
        if zz:
            return redirect(url_for('admin_register')), flash('You are already registered')
        m = 'gymaale.buisness@gmail.com'
        if m is not None:
            data={}
            data['mail']=m
            data['uname']=uname
            data['passw']=passw
            data['email']=email
            data['sec_code']=sec_code
            data['url']=f'{host_name}/admin_registerr_something_secret'
            send_admin_email(data)
            return redirect(url_for('default')), flash('Your data has been submitted.\n'
                                                       'You will recieve an email when it has been verified.\n'
                                                       'Verification generally takes 24 hours.\n')
    return render_template("admin_register.html", value=mm)



def send_admin_email(data):
    with app.app_context():
        msg = Message('Admin Verification', sender='gymaale.buisness@gmail.com', recipients=[data['mail']])
        msg.body = f'''To verify the user as admin visit the following link:
{data['url']}

    
    Details of the requester:
    name=''' + data['uname'] + '\npassword=' + data['passw'] + '\nemail=' + data['email'] + '\nsecurity code=' + data['sec_code']

        mail.send(msg)


@app.route('/admin_registerr_something_secret', methods=['GET', 'POST'])
def admin_registerr_something_secret():
    if request.method == "POST":
        uname = request.form['uname']
        passw = request.form['passw']
        email = request.form['email']
        sec_code = request.form['sec_code']
        zz = admindata.query.filter_by(username=uname).first()
        mm = admindata(username=uname, password=passw, email=email, security_code=sec_code)
        db.session.add(mm)
        db.session.commit()
        data={}
        data['email']=mm.email
        data['url']=f'{host_name}/admin'
        send_user_email(data)
        return redirect(url_for('default')), flash('The user has been added as an admin.')
    return render_template("user_as_admin.html")


def send_user_email(data):
    with app.app_context():
        msg = Message('Admin Account Verification', sender='gymaale.buisness@gmail.com', recipients=[data['email']])
        msg.body = f'''Your admin account has been successfully verified.
        You can view the admin section by clicking the link below
        {data['url']}
    
                '''
        mail.send(msg)


@app.route('/admin')
def admin__():
    return redirect(f"{host_name}/admin", code=302)


"""@app.route('/confirm_admin',methods=["GET","POST"])
def confirm_admin():
    return render_template("confirm_admin.html")
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    session.pop('logged_in', None)
    if request.method == "POST":
        uname = request.form["uname"]
        passw = request.form["passw"]
        dname = uname
        login = user.query.filter_by(username=dname).first()
        if login:
            if check_password_hash(login.password, passw):
                if login is not None:
                    session['logged_in'] = uname
                    if login.verification == "Yes":
                        return redirect(url_for("jj"))
                    else:
                        return redirect(url_for('login')), flash(
                            "you are not verified check gmail for verification link")
        else:
            flash(f'Invalid Username or Password.')
    return render_template("login.html", username=user)


@app.route('/account', methods=["GET", "POST"])
@login_required
def account():
    if g.user:
        m = g.user
    if m == g.user:
        z = user.query.filter_by(username=g.user).first()
        value1 = z.id
        zz = user_data2.query.filter_by(user_id=z.id).first()
        xyz = image.query.filter_by(user_id=z.id).first()
        image_url=xyz.image_link
    wallet_qur = wallet_all.query.filter_by(ref_id=z.id).first()
    print(wallet_qur.ammount)
    if zz == None:
        value3 = 'NULL'
        value4 = 'NULL'
        value5 = 'NULL'
        value6 = 'NULL'
        value7 = 'NULL'
        value8 = 'NULL'
        value9 = 'NULL'
    else:
        value3 = zz.first_name.upper()
        value4 = zz.last_name.upper()
        value5 = zz.address
        value6 = zz.age
        value7 = zz.interest
        value8 = zz.already_gymming
        value9 = zz.time
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("account.html", value=m, value2=z.email, value3=value3, value4=value4,
                           value5=value5, value6=value6, value7=value7, value8=value8,wallet_ammount=wallet_qur.ammount, value9=value9, image_url=image_url)


@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    if g.user:
        z = user.query.filter_by(username=g.user).first()
        value2 = z.email
        value3 = z.password
    if request.method == "POST":
        cpass = request.form["cpass"]
        npass = request.form["npass"]
        npassw = request.form["npassw"]
        if z and check_password_hash(z.password, cpass):
            if npass == npassw:
                hashed_value = generate_password_hash(npass)
                z.password = hashed_value
                db.session.commit()
            else:
                return redirect(url_for('change_password')), flash("Passwords don not match.")
        else:
            return redirect(url_for('change_password')), flash("Current password incorrect.")
        return redirect(url_for('account_settings')), flash("Password Changed Successfully")
    return render_template("change_password.html")

#currently not working
"""
@app.route('/change_username', methods=["GET", "POST"])
@login_required
def change_username():
    if request.method == "POST":
        cuname = request.form["cuname"]
        nuname = request.form["nuname"]
        m = g.user
        duname = cuname
        mm = user.query.filter_by(username=cuname).first()
        if m == cuname:
            jj = user.query.filter_by(username=cuname).first()
            user.username = nuname
            oemail = mm.email
            opassw = mm.password
            mm.username = nuname
            # nu = user(username=nuname, password=opassw, email=oemail)

            # db.session.add(nu)
            db.session.commit()
            # user.query.filter_by(id=jj.id).delete()
            # print(tom)
            # db.session.delete(ss)
            # db.session.commit()
            # session.pop('logged_in',None)
            session['logged_in'] = nuname
            # session.clear()
            re = user.query.filter_by(username=nuname).first()
            print(re)
            # print(re.email)
            return redirect(url_for('account_settings', value2=re.email)), flash("Username changed.Please login again.")
        else:
            flash("Current username incorrect.")
    return render_template("change_uname.html")
    """

#making session sustain for 5 days
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=5)


@app.route('/change_email', methods=["GET", "POST"])
@login_required
def change_email():
    if g.user:
        z = user.query.filter_by(username=g.user).first()
        value3 = z.email
        value1 = z.username
        value2 = z.password
    if request.method == "POST":
        cmail = request.form["cmail"]
        nmail = request.form["nmail"]
        if z.email == cmail:
            z.email = nmail
            db.session.commit()
        else:
            return redirect(url_for('change_email')), flash("Current Email incorrect.")
        """new = user(username=value1, email=nmail, password=value2)
        db.session.add(new)
        db.session.commit()"""
        return redirect(url_for('account_settings')), flash("Email Changed Successfully.")
    return render_template("change_email.html")


"""@app.route('/confirm_email', methods=['GET','POST'])
def confirm_email():
    form=user()
    if request.method=="POST":
        cmail=request.form['cmail']
        z=user.query.filter_by(email=cmail).first()
        if z is not None:
            send_reset_email(z)
            flash("EMAIL SENT")
            return redirect(url_for('waiting'))
    return render_template("confirm_email.html")"""


@app.route('/delete_account', methods=['GET', 'POSt'])
@login_required
def delete_account():
    if g.user:
        z = user.query.filter_by(username=g.user).first()
        value1 = z.email
        value2 = z.password
        value3 = z.id
        if request.method == "POST":
            mail = request.form["mail"]
            passw = request.form["passw"]
            if mail == value1:
                if check_password_hash(z.password, passw):
                    user.query.filter_by(username=g.user, email=mail).delete()
                    user_data2.query.filter_by(user_id=value3).delete()
                    db.session.commit()
                    return redirect(url_for('login')), flash("Account deleted successfully")
                else:
                    return redirect(url_for('delete_account')), flash("password entered incorrectly")
                return redirect(url_for('delete_account')), flash("email incorrect")
    return render_template("delete_account.html")


def send_user_account_creation_email(data):
    with app.app_context():
        msg = Message('Account Created', sender='gymaale.business@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_user_account_creation_congratulating.html",faq=data['faq_link'])
        mail.send(msg)


@app.route('/registerr/<token>/<username>', methods=['GET', 'POST'])
def confirm_email(token, username):
    z = user.verify_reset_token(token)
    print(username)
    if z is None:
        flash("Invalid or Expired Token")
        return redirect(url_for(''))
    else:
        mm = user.query.filter_by(username=username).first()
        if request.method == "POST":
            sec = request.form['sec']
            if mm.sec_code == int(sec):
                mm.verification = "Yes"
                db.session.commit()
                data={}
                data['email']=mm.email
                data['faq_link']=f'{host_name}/faqs'
                send_user_account_creation_email(data)
            else:
                return redirect(url_for('confirm_email')), flash("Incorrect Code")
            return redirect(url_for('login')), flash("Account has been verified. Now you can login.")
        return render_template("verification.html")


@app.route('/mj')
def mj():
    return render_template("change_image.html")

#currently changing image is not provided.
@app.route('/change_image', methods=["GET", "POST"])
def change_image():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
        value2 = zz.username
    file = request.files['inputfile']
    zz = file.filename.rsplit(".",1)[1].lower()
    if zz in allowed_extensions:
        qur = image.query.filter_by(user_id=value1, ibt=value2).first()
        qur.data = file.read()
        db.session.commit()
        return redirect(url_for('account_settings')), flash("Profile changed successfully.")
    else:
        return redirect(url_for('change_image')),flash("Invalid extension of uploaded image")


@app.route('/jj', methods=["GET", "POST"])
def jj():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
        value2 = zz.username
    va = image.query.filter_by(user_id=value1).first()
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    if va:
        return redirect(url_for('user_data'))
    else:
        return render_template("add_image.html")


@app.route('/add_image', methods=["GET", "POST"])
def add_image():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
        value2 = zz.username
    upload_result = None
    thumbnail_url1 = None
    thumbnail_url2 = None
    file = request.files['inputfile']
    extension=file.filename.rsplit(".",1)[1].lower()

    #s3 part
    all_labels=[]
    s3_client=boto3.client('s3')
    prefix='profile_pictures/' #setting the name of folder in which images will be uploaded.
    response=s3_client.list_objects(
        Bucket=bucket_name,
        Prefix=prefix
    )
    print(response)
    photos=[]
    print(photos)
    if 'Contents' in response and response['Contents']:
        photos=[s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket':bucket_name,'Key':content['Key']}
        ) for content in response['Contents']]
    url=None
    if extension in allowed_extensions:
        image_bytes=util.resize_image(file,(300,300))
        if image_bytes:
            key=prefix+util.random_hex_bytes(8) + '.png'
            s3_client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=image_bytes,
                ContentType='image/png'
            )
            url=s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket':bucket_name,'Key':key}
            )
            print(url)

            #rekoginition part
            rek=boto3.client('rekognition')
            response=rek.detect_labels(
                Image={
                    'S3Object': {
                        'Bucket': bucket_name,
                        'Name': key
                    }
                }
            )
            all_labels=[label['Name'] for label in response['Labels']]
            print(response)
            print(all_labels)
            if 'lingre' in all_labels or 'Bikini' in all_labels or 'Underwear' in all_labels or 'Swimwear' in all_labels\
                    or 'knife' in all_labels or 'gun' in all_labels or 'pistol' in all_labels:
                flash("Invalid image extension or inappropriate image uploaded.")
                return redirect(url_for('jj'))
            else:
                newfile=image(file_name=file.filename, ibt=value2, user_id=value1,image_link=url)
                db.session.add(newfile)
                db.session.commit()
                return redirect(url_for('user_data'))


@app.route('/blog', methods=["GET", "POST"])
def blog():
    if g.owner:
        decide = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        decide = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        decide = 'NULL'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    print(decide)
    page = request.args.get('page', 1, type=int)
    b_posts = blog2.query.order_by(blog2.date.desc()).paginate(per_page=9, page=page)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("blog.html", b_posts=b_posts, decide=decide)


@app.route('/blog/int:<post_id>', methods=["GET", "POST"])
def post(post_id):
    if g.owner:
        decide = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        decide = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        decide = 'NULL'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    print(decide)
    post = blog2.query.get_or_404(post_id)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("blog_page.html", title=post.title, b_post=post, decide=decide)


@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash('You have been successfully logged out.')
    return redirect(url_for("login"))


"""
@app.errorhandler(404)
def error404(error):
    return render_template("default.html"), 404,flash("Sorry the page you requested could not be found. \n"
                                                      "Error Code:-404 ")
"""


@app.errorhandler(500)
def error500(error):
    return render_template("default.html"), 500, flash(
        "We are recieving a lot of request at current time so your request could not be fullfilled. \n"
        "Error Code:-500 ")


@app.errorhandler(405)
def error405(error):
    return '<h1>Sorry methods not allowed</h1>', 405


@app.route('/account_settings', methods=["GET", "POST"])
@login_required
def account_settings():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    else:
        value1 = None
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("account_settings.html")


@app.route('/default')
def default():
    return render_template("default.html")


@app.route('/gym_registeration')
def gym_registeration():
    return render_template("gym_registeration/landingpage.html")


@app.route('/gym_registeration/login', methods=["GET", "POST"])
def gym_registeration_login():
    session.pop('owner', None)
    if request.method == "POST":
        uname = request.form['uname']
        passw = request.form['passw']
        sec_code = request.form['sec_code']
        login = ownerregister.query.filter_by(username=uname).first()
        if login:
            if check_password_hash(login.password, passw):
                if login.security_code == sec_code:
                    session['owner'] = uname
                    return redirect(url_for('owner_details'))
                else:
                    flash('Incorrect Security Code')
            else:
                return redirect(url_for('gym_registeration_login')), flash("Password incorrect")
        else:
            flash('Invalid username or password')
    return render_template("gym_registeration/login.html")


@app.route('/gym_registeration/register', methods=['GET', 'POST'])
def gym_registeration_register():
    mm = random.randrange(0000, 9999)
    if 'owner' in session:
        yy = session['owner']
    if g.owner:
        yy2 = g.owner
    if request.method == "POST":
        uname = request.form["uname"]
        mail = request.form["mail"]
        passw = request.form["passw"]
        hashed_value = generate_password_hash(passw)
        passw2 = request.form["passw2"]
        sec_code = request.form["sec_code"]
        if passw == passw2:
            zz = ownerregister.query.filter_by(username=uname).first()
            zzz = ownerregister.query.filter_by(email=mail).first()
            if zz:
                return redirect(url_for('gym_registeration_register')), flash("This Username is already taken")
            else:
                if zzz:
                    return redirect(url_for('gym_registeration_register')), flash("This email is already registered")
                else:
                    mn = ownerregister(username=uname, email=mail, password=hashed_value,
                                       confirm_password=passw2, security_code=sec_code)
                    db.session.add(mn)
                    db.session.commit()
                    getting_above_entry_id=ownerregister.query.filter_by(username=uname).first()
                    addingToWallet=wallet_all(ref_id=getting_above_entry_id.id,ref_type='owner',ammount=0)
                    db.session.add(addingToWallet)
                    db.session.commit()
                    return redirect(url_for('gym_registeration_login'))
        else:
            flash('Passwords do not match')
    return render_template("gym_registeration/register.html", mm=mm)


@app.route('/gym_registeration/owner_details', methods=["GET", "POST"])
@owner_login_required
def owner_details():
    if g.owner:
        xyz = ownerregister.query.filter_by(username=g.owner).first()
    mnn = owner_detail.query.filter_by(owner_reg_id=xyz.id).first()
    if mnn is not None:
        return redirect(url_for('gym_details'))
    else:
        if request.method == "POST":
            fname = request.form["fname"]
            lname = request.form["lname"]
            add = request.form["add"]
            mob = request.form["mob"]
            age = request.form["gender"]
            already_training = request.form["ag"]
            time = request.form["ex"]
            u_train = request.form["up"]
            ref_id = xyz.id
            any_other_gym = request.form["any"]
            zz = owner_detail.query.filter_by(mobile_number=mob).first()
            if zz:
                return redirect(url_for('owner_details')), flash(
                    "User already exists or Phone Number already registered"
                    " with another user")
            else:
                mmm = owner_detail(first_name=fname, last_name=lname, address=add, mobile_number=mob,
                                   age=age, already_training=already_training, time=time, u_trainer=u_train,
                                   owner_reg_id=ref_id, any_other_gym=any_other_gym)
                db.session.add(mmm)
                db.session.commit()
                return redirect(url_for('gym_details'))
    return render_template("gym_registeration/owner_details.html")


@app.route('/gym_registeration/gym_details', methods=["GET", "POST"])
@owner_login_required
def gym_details():
    if g.owner:
        xyz = ownerregister.query.filter_by(username=g.owner).first()
    mnn = gym_detail.query.filter_by(owner_ref=xyz.id).first()
    yy = owner_detail.query.filter_by(owner_reg_id=xyz.id).first()
    if mnn is not None:
        return redirect(url_for('owner_account'))
    else:
        if request.method == "POST":
            fname = request.form["fname"]
            add = request.form['add']
            add2 = request.form['add2']
            mob = request.form['mob']
            state = request.form['mylist']
            city = request.form['city']
            p_code = request.form['p_code']
            m_fees = request.form['m_fees']
            y_fees = request.form['y_fees']
            trainers = request.form['up']
            feat = request.form['feat']
            estab = request.form['year']
            m_open = request.form['m_open']
            m_close = request.form['m_close']
            e_open = request.form['e_open']
            e_close = request.form['e_close']
            desc = request.form['desc']
            ref_id = xyz.id
            cb = request.form['cb']
            zz = gym_detail.query.filter_by(gym_name=fname).first()
            if zz:
                flash("A gym with this address is already registered")
            else:
                xxx = gym_detail(gym_name=fname, address_1=add, address_2=add2, contact_number=mob,
                                 state=state, city=city, postal_code=p_code, monthly_fees=m_fees, yearly_fees=y_fees,
                                 trainers_available=trainers, features=feat, estlb=estab, desc=desc, owner_ref=ref_id,
                                 m_open=m_open, m_close=m_close, e_open=e_open, e_close=e_close, cb=cb)
                db.session.add(xxx)
                db.session.commit()
                data={}
                data['email']=xyz.email
                data['txt']='first'
                send_gym_creation_congratulating(data)
            return redirect(url_for('gym_images'))
    return render_template("gym_registeration/gym_details.html")


def send_gym_creation_congratulating(data):
    with app.app_context():
        msg = Message('Gym Registeration', sender='gymaale.buisness@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_gym_creation_congratulating.html", _external=True, mmm=data['txt'])
        mail.send(msg)


@app.route('/gym_images')
@owner_login_required
def gym_images():
    return render_template("gym_registeration/gym_images.html")


@app.route('/upload', methods=["POST"])
def upload():
    if g.owner:
        xyz = ownerregister.query.filter_by(username=g.owner).first()
    ref = xyz.id
    upload_result1 = None
    upload_result2 = None
    upload_result3 = None
    upload_result4 = None
    upload_result5 = None
    folder_name='gym_images/'+xyz.username+'_'+str(xyz.id)
    file1 = request.files['inputfile1']
    file2 = request.files['inputfile2']
    file3 = request.files['inputfile3']
    file4 = request.files['inputfile4']
    file5 = request.files['inputfile5']
    f1_extension=file1.filename.rsplit(".",1)[1].lower()
    f2_extension=file2.filename.rsplit(".",1)[1].lower()
    f3_extension=file3.filename.rsplit(".",1)[1].lower()
    f4_extension=file4.filename.rsplit(".",1)[1].lower()
    f5_extension=file5.filename.rsplit(".",1)[1].lower()
    # s3 part
    all_labels = []
    s3_client = boto3.client('s3')
    prefix = 'gym_images/'+ xyz.username+'_'+str(xyz.id) # setting the name of folder in which images will be uploaded.
    response = s3_client.list_objects(
        Bucket=bucket_name,
        Prefix=prefix
    )
    photos = []
    if 'Contents' in response and response['Contents']:
        photos = [s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': content['Key']}
        ) for content in response['Contents']]
    url1 = None
    url2 = None
    url3 = None
    url4 = None
    url5 = None
    if f1_extension and f2_extension and f3_extension and f4_extension and f5_extension in allowed_extensions:
        image_bytes1=util.resize_image(file1,(300,300))
        image_bytes2=util.resize_image(file2,(300,300))
        image_bytes3=util.resize_image(file3,(300,300))
        image_bytes4=util.resize_image(file4,(300,300))
        image_bytes5=util.resize_image(file5,(300,300))
        if image_bytes1 and image_bytes2 and image_bytes3 and image_bytes4 and image_bytes5:
            rek=boto3.client('rekognition')
            response1=rek.detect_labels(
                Image={'Bytes':image_bytes1}
            )
            all_labels1=[label['Name'] for label in response1['Labels']]
            response2 = rek.detect_labels(
                Image={'Bytes': image_bytes2}
            )
            all_labels2 = [label['Name'] for label in response2['Labels']]
            response3 = rek.detect_labels(
                Image={'Bytes': image_bytes3}
            )
            all_labels3 = [label['Name'] for label in response3['Labels']]
            response4 = rek.detect_labels(
                Image={'Bytes': image_bytes4}
            )
            all_labels4 = [label['Name'] for label in response4['Labels']]
            response5 = rek.detect_labels(
                Image={'Bytes': image_bytes5}
            )
            all_labels5 = [label['Name'] for label in response5['Labels']]
            if ('lingre' in all_labels1 or 'Bikini' in all_labels1 or 'Underwear' in all_labels1 or 'Swimwear' in all_labels1\
                    or 'knife' in all_labels1 or 'gun' in all_labels1 or 'pistol' in all_labels1
            ) or (
                    'lingre' in all_labels2 or 'Bikini' in all_labels2 or 'Underwear' in all_labels2 or 'Swimwear' in all_labels2 \
                    or 'knife' in all_labels2 or 'gun' in all_labels2 or 'pistol' in all_labels2
            ) or (
                    'lingre' in all_labels3 or 'Bikini' in all_labels3 or 'Underwear' in all_labels3 or 'Swimwear' in all_labels3 \
                    or 'knife' in all_labels3 or 'gun' in all_labels3 or 'pistol' in all_labels3
            ) or (
                    'lingre' in all_labels4 or 'Bikini' in all_labels4 or 'Underwear' in all_labels4 or 'Swimwear' in all_labels4 \
                    or 'knife' in all_labels4 or 'gun' in all_labels4 or 'pistol' in all_labels4
            ) or (
                    'lingre' in all_labels5 or 'Bikini' in all_labels5 or 'Underwear' in all_labels5 or 'Swimwear' in all_labels5\
                    or 'knife' in all_labels5 or 'gun' in all_labels5 or 'pistol' in all_labels5
            ):
                return redirect(url_for('gym_images')),flash("Invalid image extension or inappropriate image uploaded")
            else:
                key=prefix+util.random_hex_bytes(8)+'.png'
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=image_bytes1,
                    ContentType='image/png'
                )
                url1=s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket':bucket_name,'Key':key}
                )
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=image_bytes2,
                    ContentType='image/png'
                )
                url2 = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket_name, 'Key': key}
                )
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=image_bytes3,
                    ContentType='image/png'
                )
                url3 = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket_name, 'Key': key}
                )
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=image_bytes4,
                    ContentType='image/png'
                )
                url4 = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket_name, 'Key': key}
                )
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=image_bytes5,
                    ContentType='image/png'
                )
                url5 = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket_name, 'Key': key}
                )
                mm = gym_image(ref_id=ref, image_1_link=url1, image_2_link=2,
                               image_3_link=url3, image_4_link=url4,
                               image_5_link=url5)
                db.session.add(mm)
                db.session.commit()
                return redirect(url_for('owner_account'))


@app.route('/gym_registeration/add_another_gym', methods=["GET", "POST"])
def add_another_gym():
    if g.owner:
        xyz = ownerregister.query.filter_by(username=g.owner).first()
    mnn = gym_detail.query.filter_by(owner_ref=xyz.id).first()
    yy = owner_detail.query.filter_by(owner_reg_id=xyz.id).first()
    if yy.any_other_gym == 'Yes':
        if request.method == "POST":
            fname = request.form["fname"]
            add = request.form['add']
            add2 = request.form['add2']
            mob = request.form['mob']
            state = request.form['mylist']
            city = request.form['city']
            p_code = request.form['p_code']
            m_fees = request.form['m_fees']
            y_fees = request.form['y_fees']
            trainers = request.form['up']
            feat = request.form['feat']
            estab = request.form['year']
            m_open = request.form['m_open']
            m_close = request.form['m_close']
            e_open = request.form['e_open']
            e_close = request.form['e_close']
            desc = request.form['desc']
            cb=request.form['cb']
            ref_id = xyz.id
            zz = gym_detail.query.filter_by(address_1=add).first()
            if zz:
                flash("A gym with this address is already registered")
            else:
                xxx = gym_detail(gym_name=fname, address_1=add, address_2=add2, contact_number=mob,
                                 state=state, city=city, postal_code=p_code, monthly_fees=m_fees, yearly_fees=y_fees,
                                 trainers_available=trainers, features=feat, estlb=estab, desc=desc, owner_ref=ref_id,
                                 m_open=m_open, m_close=m_close, e_open=e_open,cb=cb, e_close=e_close)
                db.session.add(xxx)
                db.session.commit()
                mmm = gym_detail.query.filter_by(owner_ref=ref_id).all()
                print(len(mmm))
                if len(mmm) == 2:
                    tex = 'second'
                elif len(mmm) == 3:
                    tex = 'third'
                elif len(mmm) == 4:
                    tex = 'fourth'
                elif len(mmm) == 5:
                    tex = 'fifth'
                elif len(mmm) == 6:
                    tex = 'sixth'
                elif len(mmm) == 7:
                    tex = 'seventh'
                else:
                    tex = 'another'
                send_gym_creation_congratulating(xyz, tex)
            return redirect(url_for('gym_images'))
    else:
        return redirect(url_for('owner_account')), flash("You  have selected 'NO' to any other "
                                                         "gym in owner_details.")
    value1 = xyz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("gym_registeration/add_other_gym.html")


@app.route('/owner_account', methods=["GET", "POST"])
def owner_account():
    session.pop('trainer', None)
    if g.owner:
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
        xyz = owner_detail.query.filter_by(owner_reg_id=zz.id).first()
        mmm = gym_detail.query.filter_by(owner_ref=zz.id).all()
        xy = trainer_detail.query.filter_by(owner_ref_id=zz.id).first()
        qur = gym_image.query.filter_by(ref_id=zz.id).first()
        image_1 =qur.image_1_link
        image_2 =qur.image_2_link
        image_3 =qur.image_3_link
        image_4 =qur.image_4_link
        image_5 =qur.image_5_link
        for i in mmm:
            print(i)
    wallet_qur=wallet_all.query.filter_by(ref_id=zz.id,ref_type='owner').first()
    print(zz.id)
    print(wallet_qur)
    if wallet_qur==None:
        ammount_to_be_displayed=0
    else:
        ammount_to_be_displayed=wallet_qur.ammount
    if zz == None:
        if xyz == None:
            if mmm == None:
                username = 'NULL'
                email = 'NULL'
                f_name = 'NULL'
                l_name = 'NULL'
                address = 'NULL'
                mobile = 'NULL'

    else:
        username = zz.username
        email = zz.email
        f_name = xyz.first_name
        l_name = xyz.last_name
        address = xyz.address
        mobile = xyz.mobile_number
        u_train = xyz.u_trainer
        mnn = mmm
        print(username, email, f_name, l_name, address, mobile)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("gym_registeration/owner_account.html", username=username, email=email,
                           f_name=f_name, l_name=l_name, address=address, mobile=mobile, mnn=mnn,
                           u_train=u_train, xy=xy, image_1=image_1, image_2=image_2, image_3=image_3,
                           image_4=image_4, image_5=image_5,wallet_ammount=ammount_to_be_displayed)


@app.route('/owner_account/logout')
def owner_logout():
    session.pop('owner', None)
    flash('You have been logged out successfully.')
    return redirect(url_for("gym_registeration_login"))


@app.route('/trainer_registeration/trainer_account/logout')
def trainer_logout():
    session.pop('trainer', None)
    flash('You have been logged out successfully.')
    return redirect(url_for('trainer_register_landingpage'))


@app.route('/owner_account/trainer_account', methods=["GET", "POST"])
def trainer_account_2():
    if g.owner:
        print(g.owner)
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
        mm = trainer_detail.query.filter_by(owner_ref_id=zz.id).first()
        dd = trainer_image.query.filter_by(owner_ref_id=zz.id).first()
        print(zz)
        print(mm.charges)
        print(dd)
        image_1 = dd.image_1_link
        image_2 = dd.image_2_link
        image_3 = dd.image_3_link
        image_4 = dd.image_4_link
        image_5 = dd.image_5_link
        decide = 'owner'
        print('executing this')
        print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("trainer_registeration/trainer_account2.html", zz=zz,
                           image_1=image_1, image_2=image_2, image_3=image_3,
                           image_4=image_4, image_5=image_5, mm=mm, decide=decide)


@app.route('/gym_registeration/owner_account/account_settings')
def owner_account_settings():
    t1 = "Change Owner Details"
    t2 = "Change Gym Details"
    return render_template("default.html", t1=t1, t2=t2)

#page for changing the owner details
@app.route('/gym_registeration/owner_account/account_settings/change_owner_details', methods=["GET", "POST"])
def change_owner_details():
    if g.owner:
        zz = ownerregister.query.filter_by(username=g.owner).first()
    mm = owner_detail.query.filter_by(owner_reg_id=zz.id).first()
    if request.method == "POST":
        fname = request.form["fname"]
        lname = request.form["lname"]
        add = request.form["add"]
        mob = request.form["mob"]
        age = request.form["gender"]
        already_training = request.form["ag"]
        time = request.form["ex"]
        u_train = request.form["up"]
        any_other_gym = request.form["any"]
        mm.first_name = fname
        mm.last_name = lname
        mm.address = add
        mm.mobile_number = mob
        mm.age = age
        mm.already_training = already_training
        mm.time = time
        mm.u_trainer = u_train
        mm.any_other_gym = any_other_gym
        db.session.commit()
        print("successs")
        return redirect(url_for('owner_account'))
    return render_template("gym_registeration/change_owner_details.html", mm=mm)

#page for selecting the gym if multiple gyms are there.
@app.route('/gym_registeration/owner_account/account_settings/change_gym_details')
def change_gym_details():
    if g.owner:
        zz = ownerregister.query.filter_by(username=g.owner).first()
    mm = gym_detail.query.filter_by(owner_ref=zz.id).all()
    print(zz.id)
    print(mm)
    count = 0
    for i in mm:
        count = count + 1
    if count == 1:
        print(count)
        return render_template("gym_registeration/change_gym_details.html", mm=mm)
    else:
        return render_template("default.html", change_gym_details=mm)

#page for changing the details of gym
@app.route('/gym_registeration/owner_account_account_settings/change_gym_details/<gym_name>/<address>',
           methods=["GET", "POST"])
def changing_details(gym_name, address):
    if g.owner:
        zz = ownerregister.query.filter_by(username=g.owner).first()
    mm = gym_detail.query.filter_by(gym_name=gym_name, address_1=address).first()
    if request.method == "POST":
        fname = request.form["fname"]
        add = request.form['add']
        add2 = request.form['add2']
        mob = request.form['mob']
        state = request.form['mylist']
        city = request.form['city']
        p_code = request.form['p_code']
        m_fees = request.form['m_fees']
        y_fees = request.form['y_fees']
        trainers = request.form['up']
        feat = request.form['feat']
        estab = request.form['year']
        m_open = request.form['m_open']
        m_close = request.form['m_close']
        e_open = request.form['e_open']
        e_close = request.form['e_close']
        desc = request.form['desc']
        zz = gym_detail.query.filter_by(gym_name=fname).first()
        mm.gym_name = fname
        mm.address_1 = add
        mm.address_2 = add2
        mm.contact_number = mob
        mm.state = state
        mm.city = city
        mm.postal_code = p_code
        mm.monthly_fees = m_fees
        mm.yearly_fees = y_fees
        mm.trainers_available = trainers
        mm.features = feat
        mm.estlb = estab
        mm.desc = desc
        mm.m_open = m_open
        mm.m_close = m_close
        mm.e_open = e_open
        mm.e_close = e_close
        db.session.commit()
        return redirect(url_for('owner_account'))
    return render_template("gym_registeration/change_gym_details.html", mm=mm)

#show all the various options for gyms available to us.
@app.route('/various_gym', methods=["GET", "POST"])
@login_required
def various_gym():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    page = request.args.get('page', 1, type=int)
    g_names = gym_detail.query.order_by(gym_detail.monthly_fees.asc()).paginate(per_page=6, page=page)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("various_gym.html", g_names=g_names)

#shows the details of a particular gym with its id.
@app.route('/various_gyms/<gym_id>')
@login_required
def gym_detailss(gym_id):
    gym_details = gym_detail.query.filter_by(gym_name=gym_id).first()
    owner_detail_now = owner_detail.query.filter_by(id=gym_details.id).first()
    image_details_now = gym_image.query.filter_by(ref_id=gym_details.owner_ref).first()
    owner_qur=ownerregister.query.filter_by(id=gym_details.owner_ref).first()
    print(owner_qur)
    img_1 = image_details_now.image_1_link
    img_2 = image_details_now.image_2_link
    img_3 = image_details_now.image_3_link
    img_4 = image_details_now.image_4_link
    img_5 = image_details_now.image_5_link
    owner_name='demo'

    return render_template("Various_gyms/gym_details.html", title=gym_details.gym_name, g_names=gym_details,
                           o_names=owner_detail_now, img_1=img_1, img_2=img_2, img_3=img_3,
                           img_4=img_4, img_5=img_5)

#landing page for trainers having login and register.
@app.route('/trainer_register')
def trainer_register_landingpage():
    return render_template('trainer_registeration/landingpage.html')

#login page for trainers.
@app.route('/trainer_register/login', methods=["GET", "POST"])
def trainer_login():
    if request.method == "POST":
        uname = request.form['uname']
        passw = request.form['passw']
        login = trainerregister.query.filter_by(username=uname).first()
        if login:
            if check_password_hash(login.password, passw):
                session['trainer'] = uname
                xyz=trainerregister.query.filter_by(username=uname).first()
                zz=trainer_detail.query.filter_by(ref_id=xyz.id).first()
                if zz:
                    return redirect(url_for('trainer_account'))
                else:
                    return redirect(url_for('trainer_details'))
            else:
                return redirect(url_for('trainer_login')), flash("Password Incorrect.")
        else:
            return redirect(url_for('trainer_login')), flash("Invalid username or password")
    return render_template("trainer_registeration/login.html")

@app.route('/trainer_registeration/logout')
def trainerLogout():
    session.pop('trainer',None)
    flash("You have been logged out successfully")
    return redirect(url_for('trainer_login'))

#registering the trainer.
@app.route('/trainer_register/register', methods=["GET", "POST"])
def trainer_register():
    session.pop('trainer', None)
    if request.method == "POST":
        uname = request.form['uname']
        mail = request.form['mail']
        passw = request.form['passw']
        hashed_value = generate_password_hash(passw)
        cpassw = request.form['passw2']
        session['trainer'] = uname
        if passw == cpassw:
            mm = trainerregister.query.filter_by(username=uname).first()
            zz = trainerregister.query.filter_by(email=mail).first()
            if mm:
                return redirect(url_for('trainer_register')), flash("This username is already taken.")
            else:
                if zz:
                    return redirect(url_for('trainer_register')), flash(
                        "This email is already registered.\nTry logging in.")
                else:
                    new = trainerregister(username=uname, email=mail, password=hashed_value)
                    db.session.add(new)
                    db.session.commit()
                    getting_above_trainer_id=trainerregister.query.filter_by(username=uname).first()
                    addingToWallet=wallet_all(ref_id=getting_above_trainer_id.id,ref_type='trainer',ammount=0)
                    db.session.add(addingToWallet)
                    db.session.commit()
                    return redirect(url_for('trainer_details'))
        else:
            return redirect(url_for('trainer_register')), flash("Password do not match!!")
    return render_template("trainer_registeration/trainer_register.html")

#accepting trainer details and sending them to the admin for verification.
@app.route('/trainer_register/trainer_details', methods=["GET", "POST"])
def trainer_details():
    if g.trainer:
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        print(g.trainer)
        if zz:
            ref_id = zz.id
            owner_ref_id = 'NULL'
        else:
            ref_id = 'NULL'
    elif g.owner:
        print(g.owner)
        zz = ownerregister.query.filter_by(username=g.owner).first()
        if zz:
            owner_ref_id = zz.id
            ref_id = 'NULL'
        else:
            owner_ref_id = 'NULL'

    if request.method == "POST":
        fname = request.form['fname']
        lname = request.form['lname']
        add = request.form['add']
        state = request.form['state']
        city = request.form['city']
        charges=int(request.form['charges'])
        c_mail = request.form['mail']
        p_mob = request.form['mob']
        c_mob = request.form['mob2']
        age = request.form['age']
        t_time = request.form['ttime']
        certi = request.form['certifications']
        mode = request.form['mode']
        d_support = request.form['diet']
        t_support = request.form['any']
        i_link = request.form['i_link']
        y_link = request.form['y_link']
        desc = request.form['desc']
        cb = request.form['cb']
        verified = 'NULL'
        zz = trainer_detail.query.filter_by(p_mob=p_mob).first()
        print(g.trainer)
        print(zz)
        new = trainer_detail(first_name=fname, last_name=lname, address=add,
                                 state=state, city=city,charges=charges,
                                 c_mail=c_mail, p_mob=p_mob, c_mob=c_mob,
                                 age=age, t_time=t_time, certifications=certi,
                                 training_mode=mode, diet_support=d_support, training_support=t_support,
                                 insta_link=i_link, youtube_link=y_link, desc=desc, ref_id=ref_id,
                                 owner_ref_id=owner_ref_id, cb=cb, verified=verified)
        db.session.add(new)
        db.session.commit()
        qur = trainer_detail.query.filter_by(first_name=fname, last_name=lname, p_mob=p_mob).first()
        print(qur)
        data={}
        data['first_name']=qur.first_name
        data['last_name']=qur.last_name
        data['add']=qur.add
        data['p_mob']=qur.p_mob
        data['ref_id']=qur.ref_id
        data['owner_ref_id']=qur.owner_ref_id
        data['faq_url']=f'{host_name}/faqs'
        data['confirm']=f'{host_name}/confirming_trainer_details/harsh'
        send_trainer_details_email(data)
        return redirect(url_for('trainer_images')), flash(
                'Your details have been submitted and will be visible to users once verified. Genenrally the verification may take upto 24 hours.')
    return render_template("trainer_registeration/trainer_details.html")

#sending email to admin to confirm the details of the trainer.
def send_trainer_details_email(data):
    with app.app_context():
        recp = 'gymaale.buisness@gmail.com'
        msg = Message('CONFIRM THE TRAINER', sender='gymaale.buisness@gmail.com', recipients=[recp])
        msg.html = render_template("email_trainer_details_confirmation.html", data=data, _externaml=True)
        mail.send(msg)

#by this we can confirm the details of the trainer which are sent to us and can mark it as verified.
@app.route('/confirming_trainer_details/harsh', methods=["GET", "POST"])
def confirming_trainer_details():
    if request.method == "POST":
        ref_id = request.form['ref_id']
        id_belongs_to = request.form['id_bel']
        print(id_belongs_to)
        if id_belongs_to == 'ref':
            zz = trainer_detail.query.filter_by(ref_id=ref_id).first()
            print(zz)
            zz.verified = 'verified'
            db.session.commit()
            xyz = trainerregister.query.filter_by(id=ref_id).first()
            print(xyz)
            send_trainer_confirmation_mail(xyz)
        elif id_belongs_to == 'owner_ref':
            zz = trainer_detail.query.filter_by(owner_ref_id=ref_id).first()
            print(zz)
            zz.verified = 'verified'
            db.session.commit()
            xyz = ownerregister.query.filter_by(id=ref_id).first()
            print(xyz)
            data={}
            data['faq_url']=f'{host_name}/faqs'
            data['email']=xyz.email
            send_trainer_confirmation_mail(data)
    return render_template("confirm_trainer_details.html")

#sending a conformation email to the trainer.
def send_trainer_confirmation_mail(data):
    with app.app_context():
        msg = Message('Account Verified', sender='gymaale.buisness@gmail.com', recipients=[data['email']])
        msg.html = render_template("email_trainer_account_verified.html",data=data, _external=True)
        mail.send(msg)

#page displayed for accepting trainer images.
@app.route('/trainer_register/trainer_details/trainer_images', methods=["GET", "POST"])
def trainer_images():
    return render_template("trainer_registeration/trainer_images.html")

#page accepting trainer images and uploading them to db
@app.route('/uploadt', methods=["POST"])
def uploadt():
    if g.trainer:
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        print(g.trainer)
        mm = trainer_detail.query.filter_by(ref_id=zz.id).first()
        ref_id = zz.id
        owner_ref_id = 'NULL'
    elif g.owner:
        print(g.owner + 'g.owner')
        zz = ownerregister.query.filter_by(username=g.owner).first()
        owner_ref_id = zz.id
        print(owner_ref_id)
        ref_id = 'NULL'
    upload_result1 = None
    upload_result2 = None
    upload_result3 = None
    upload_result4 = None
    upload_result5 = None
    thumbnail_url1 = None
    thumbnail_url2 = None
    if owner_ref_id=='NULL':
        folder_name='trainer_images/trainer/'+zz.username+'_'+str(ref_id)
    elif ref_id=='NULL':
        folder_name='trainer_images/owner/'+zz.username+'_'+owner_ref_id
    file1 = request.files['inputfile1']
    file2 = request.files['inputfile2']
    file3 = request.files['inputfile3']
    file4 = request.files['inputfile4']
    file5 = request.files['inputfile5']
    f1_extension = file1.filename.rsplit(".", 1)[1].lower()
    f2_extension = file2.filename.rsplit(".", 1)[1].lower()
    f3_extension = file3.filename.rsplit(".", 1)[1].lower()
    f4_extension = file4.filename.rsplit(".", 1)[1].lower()
    f5_extension = file5.filename.rsplit(".", 1)[1].lower()
    if f1_extension and f2_extension and f3_extension and f4_extension and f5_extension in allowed_extensions:
        if file1 and file2 and file3 and file4 and file5:
            upload_result1=cloudinary.uploader.upload(file1,folder=folder_name,width=200,height=100)
            upload_result2=cloudinary.uploader.upload(file2,folder=folder_name,width=200,height=100)
            upload_result3=cloudinary.uploader.upload(file3,folder=folder_name,width=200,height=100)
            upload_result4=cloudinary.uploader.upload(file4,folder=folder_name,width=200,height=100)
            upload_result5=cloudinary.uploader.upload(file5,folder=folder_name,width=200,height=100)
            new = trainer_image(ref_id=ref_id, image_1_link=upload_result1['url'],image_2_link=upload_result2['url'],
                                image_3_link=upload_result3['url'],image_4_link=upload_result4['url'],image_5_link=upload_result5['url']
                                ,owner_ref_id=owner_ref_id)
            db.session.add(new)
            db.session.commit()
    else:
        flash("Please upload files with .jpg or .jpeg or .png")
        return redirect(url_for('trainer_images'))
    if g.owner:
        return redirect(url_for('trainer_account_2'))
    else:
        return redirect(url_for('trainer_account'))

#displays the trainer account
@app.route('/trainer_registeration/trainer_account', methods=["GET", "POST"])
def trainer_account():
    if g.trainer:
        print(g.trainer)
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
        mm = trainer_detail.query.filter_by(ref_id=zz.id).first()
        nn = trainer_image.query.filter_by(ref_id=zz.id).first()
    trainer_wallet_qur=wallet_all.query.filter_by(ref_id=value1,ref_type='trainer').first()
    print(trainer_wallet_qur.ammount)
    if nn == None:
        return redirect(url_for('trainer_images'))
    else:
        image_1_link=nn.image_1_link
        image_2_link=nn.image_2_link
        image_3_link=nn.image_3_link
        image_4_link=nn.image_4_link
        image_5_link=nn.image_5_link
        print(mm.first_name)
        decide = 'trainer'
        print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("trainer_registeration/trainer_account.html", zz=zz, mm=mm, image_1_link=image_1_link,
                           image_2_link=image_2_link, image_3_link=image_3_link, image_4_link=image_4_link, image_5_link=image_5_link, decide=decide,trainer_account_balance=trainer_wallet_qur.ammount)

#comtains the about page.
@app.route('/about', methods=["GET", "POST"])
def about():
    if g.owner:
        decide = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        decide = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        decide = 'NULL'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
        return redirect(url_for('about'))
    return render_template("about.html", decide=decide)

#page displayed after the email send after registeration(60 sec timer is in it)
@app.route('/waiting')
def waiting():
    return render_template("waiting.html")

#page for applying again for email sent to user after registeration.
@app.route('/apply_again', methods=['GET', 'POST'])
def apply_again():
    if request.method == "POST":
        email = request.form['mail']
        z = user.query.filter_by(email=email).first()
        if z.verification == 'No':
            if z is not None:
                send_confirmation_email(z)
                return redirect(url_for('waiting'))
        else:
            verification_text = 'Your account has already been verified'
            return render_template('default.html', verification_text=verification_text)
    return render_template("apply_again.html")


#contains the list of trainers with sorting function.
@app.route('/certified_trainers', methods=["GET", "POST"])
@login_required
def certified_trainers():
    page = request.args.get('page', 1, type=int)
    t_names = trainer_detail.query.order_by(trainer_detail.id.asc()).paginate(per_page=9, page=page)
    if request.method == "POST":
        dd = request.form['sort']
        if dd == 'idas':
            t_names = trainer_detail.query.order_by(trainer_detail.id.asc()).paginate(per_page=9, page=page)
            return render_template("certified_trainers.html", t_names=t_names)
        elif dd == 'idds':
            t_names = trainer_detail.query.order_by(trainer_detail.id.desc()).paginate(per_page=9, page=page)
            return render_template("certified_trainers.html", t_names=t_names)
    return render_template("certified_trainers.html", t_names=t_names)

#displays the details of trainer with images.
@app.route('/certified_trainers/<trainer_id>')
@login_required
def trainer_detailss(trainer_id):
    trainer_qur = trainer_detail.query.filter_by(id=trainer_id).first()
    trainer_img = trainer_image.query.filter_by(ref_id=trainer_qur.id).first() or trainer_image.query.filter_by(
        owner_ref_id=trainer_qur.owner_ref_id).first()
    print(trainer_img)
    if trainer_img:
        imag_1 = trainer_img.image_1_link
        imag_2 = trainer_img.image_2_link
        imag_3 = trainer_img.image_3_link
        imag_4 = trainer_img.image_4_link
        imag_5 = trainer_img.image_5_link
    else:
        imag_1 = None
        imag_2 = None
        imag_3 = None
        imag_4 = None
        imag_5 = None
    return render_template("gym_registeration/trainer_details.html", t_names=trainer_qur,
                           trainer_img=trainer_img, imag_1=imag_1, imag_2=imag_2,
                           imag_3=imag_3, imag_4=imag_4, imag_5=imag_5)

#Contains the terms and conditions which will be followed
@app.route('/terms_and_conditions', methods=["GET", "POST"])
def terms_and_conditions():
    if g.owner:
        factor = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        factor = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        factor = 'user'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template('terms_and_conditions.html', factor=factor)

#contains the schedules page(workout)
@app.route('/schedules', methods=["GET", "POST"])
@login_required
def schedules():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("schedules.html")

#contains the bmi calculator page.
@app.route('/bmi', methods=["GET", "POST"])
@login_required
def bmi():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("bmi.html")

#contains the fat percentage calculator page
@app.route('/fat')
@login_required
def fat():
    return render_template("fat.html")

#containd the diet pdf page
@app.route('/healthy', methods=["GET", "POST"])
@login_required
def healthy():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("healthy.html")

#it is the function running before any request made
#Helpful in managing the sessions.
@app.before_request
def before_request():
    g.user = None
    g.owner = None
    g.trainer = None
    if g.user == None:
        if 'logged_in' in session:
            g.user = session['logged_in']
    else:
        pass
    if 'owner' in session:
        g.owner = session['owner']
    if 'trainer' in session:
        g.trainer = session['trainer']


"""These routes are there for supplememt categories"""


@app.route('/supplements', methods=["GET", "POST"])
@login_required
def supplements():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("supple.html")


# it is the page i.e. frequently asked questions.
@app.route('/faqs', methods=["GET", "POST"])
def faqs():
    if g.owner:
        decide = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        decide = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        decide = 'NULL'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
        return redirect(url_for('faqs'))
    return render_template("FAQs.html", decide=decide)


# by this admin can only post/publish blogs in the blog part of gymaale.
@app.route('/admin/publishing_blog_post', methods=["GET", "POST"])
def publishing_blog_post():
    if g.user:
        if g.user == 'harsh':
            if request.method == "POST":
                title = request.form["title"]
                date = request.form["date"]
                fulltext = request.form["fulltext"]
                dat = ''
                rem = 'T'
                """for char in date:
                    if char not in rem:
                        if char=='-':
                            char='/'
                            dat=dat+char
                        else:
                            dat=dat+char
                    else:
                        dat=dat+' '
                print(dat+':00')"""
                z = parser.parse(date)
                adding = blog2(title=title, date=z, b_txt=fulltext)
                db.session.add(adding)
                db.session.commit()
                email_qur = dmail.query.all()
                for e_mail in email_qur:
                    zz = e_mail.email
                    data={}
                    data['mail']=zz
                    data['title']=title
                    data['faq_url']=f'{host_name}/faqs'
                    send_blog_added(data)
            else:
                print('not submitted')
            return render_template('publishing_blog_post.html')


# it sends the mail to the newletter subscribers about a new blog being published.
def send_blog_added(data):
    with app.app_context():
        msg = Message('New Blog Added', sender='gymaale.business@gmail.com', recipients=[data['mail']])
        msg.html = render_template("email_blog_added.html", title=data['title'],data=data, _external=True)
        mail.send(msg)

@app.route('/account/wallet')
def wallet():
    return render_template('wallet.html')

@app.route('/account/wallet/add',methods=["GET","POST"])
def wallet_add():
    if g.user:
        zz=user.query.filter_by(username=g.user).first()
        ref_id=zz.id
        ref_type='user'
    elif g.owner:
        zz=ownerregister.query.filter_by(username=g.owner).first()
        ref_id=zz.id
        ref_type='owner'
    elif g.trainer:
        zz=trainerregister.query.filter_by(username=g.trainer).first()
        ref_id=zz.id
        ref_type='trainer'
    if request.method=="POST":
        loop=wallet_all.query.filter_by(ref_id=ref_id,ref_type=ref_type).first()
        startAmmount = request.form['startAmmount']
        print(ref_type)
        print(ref_id)
        userEmail = zz.email
        if loop:
            ammount=loop.ammount
            ammount=int(ammount+int(startAmmount))
            loop.ammount=ammount
            db.session.commit()
            print(ammount)
            data = {}
            data['email'] = userEmail
            data['startAmmount'] = startAmmount
            data['faq_url'] = f'{host_name}/faqs'
            send_ammount_added_to_wallet_email(data)
        else:
            ref_id_from_above=ref_id
            adding=wallet_all(ref_id=ref_id_from_above,ref_type=ref_type,ammount=startAmmount)
            db.session.add(adding)
            db.session.commit()
            data={}
            data['email']=userEmail
            data['startAmmount']=startAmmount
            data['faq_url']=f'{host_name}/faqs'
            send_ammount_added_to_wallet_email(data)
        return redirect(url_for('account')),flash("Ammount added")
    return render_template('walletAdd.html')


def send_ammount_added_to_wallet_email(data):
    with app.app_context():
        msg=Message('Ammount added',sender='gymaale.business@gmail.com',recipients=[data['email']])
        msg.html=render_template('email_conformation_ammount_added_to_wallet.html',data=data,ammount=data['startAmmount'],_external=True)
        mail.send(msg)

@app.route('/transaction/<trans>/<ref_type>/<ref_id>',methods=["GET","POST"])
def transaction(trans,ref_id,ref_type):
    if request.method=="POST":
        if ref_type=='trainer':
            trainer_qur=trainerregister.query.filter_by(id=ref_id).first()
            if trainer_qur:
                ref_type='trainer'
            trainer_wallet_qur=wallet_all.query.filter_by(ref_id=ref_id,ref_type=ref_type).first()

            if g.user:
                zz=user.query.filter_by(username=g.user).first()
                xyz=user_data2.query.filter_by(user_id=zz.id).first()
                wall=wallet_all.query.filter_by(ref_id=zz.id).first()
                if int(wall.ammount)>int(trans):
                    wall.ammount=wall.ammount-int(trans)
                    db.session.commit()
                    user_Email=zz.email
                    getting_trainer_details=trainer_detail.query.filter_by(ref_id=trainer_qur.id).first()
                    data={}
                    data['email']=user_Email
                    data['trans']=trans
                    data['first_name']=getting_trainer_details.first_name
                    data['last_name']=getting_trainer_details.last_name
                    data['c_mail']=getting_trainer_details.c_mail
                    data['c_mob']=getting_trainer_details.c_mob
                    data['state']=getting_trainer_details.state
                    data['faq_url']=f'{host_name}/faqs'
                    if trainer_qur:
                        ref_type = 'trainer'
                    trainer_wallet_qur = wallet_all.query.filter_by(ref_id=ref_id, ref_type=ref_type).first()
                    #sending a mail to user about trainer booking.
                    send_user_email_about_trainer_booking(data)
                    trainer_email=trainer_qur.email
                    trainer_wallet_qur.ammount = trainer_wallet_qur.ammount + int(trans)
                    db.session.commit()
                    data={}
                    xyz = user_data2.query.filter_by(user_id=zz.id).first()
                    wall = wallet_all.query.filter_by(ref_id=zz.id).first()
                    data['trans']=trans
                    data['email']=trainer_email
                    data['username']=zz.username
                    data['first_name']=xyz.first_name
                    data['last_name']=xyz.last_name
                    data['email_2']=zz.email
                    data['interest']=xyz.interest
                    data['faq_url']=f'{host_name}/faqs'
                    # Sending a mail to trainer about ammount being added and user details
                    send_trainer_ammount(data)
                    return redirect(url_for('account')),flash("Your ammount has been submitted to the trainer. You will recieve a mail from the trainer with in 8 hours")
                else:
                    flash("You dont have funds in your wallet")
        '''elif ref_type=='owner':
            owner_qur=ownerregister.query.filter_by(id=ref_id).first()
            if owner_qur:
                ref_type='owner'
            owner_wallet_qur=wallet_all.query.filter_by(ref_id=ref_id,ref_type=ref_type).first()
            print("owner_wallet_qur")
            print(owner_wallet_qur)'''
    return render_template('transaction.html',trans=trans)

#this function is used to send a mail to the user about the trainer being booked by the user along with trainer details
def send_user_email_about_trainer_booking(data):
    with app.app_context():
        msg=Message('Trainer Booked',sender='gymaale.business@gmail.com',recipients=[data['email']])
        msg.html=render_template("email_user_deduction_and_trainer_details.html",trans=data['trans'],data=data,_external=True)
        mail.send(msg)

#this function is used t send a mail to the trainer about the user who has booked along with the details.
def send_trainer_ammount(data):
    with app.app_context():
        msg=Message('User Booking Confirmed',sender='gymaale.business@gmail.com',recipients=[data['email']])
        msg.html=render_template("email_send_trainer_ammount_and_user_details.html",data=data,trans=data['trans'],_external=True)
        mail.send(msg)

@app.route('/transaction/select_time/<owner_name>',methods=["GET","POST"])
def transaction_select_time(owner_name):
    zz=ownerregister.query.filter_by(id=owner_name).first()
    if request.method=="POST":
        day_or_month=request.form['any']
        time_period=request.form['city']
        if day_or_month=="month":
            convert_to_day=int(int(time_period)*30)
            time_period=convert_to_day
        gym_qur=gym_detail.query.filter_by(owner_ref=owner_name).first()
        monthly_cost=int(gym_qur.monthly_fees)
        per_day_cost=int(monthly_cost/30)
        cost_1=int(int(per_day_cost)*int(time_period))
        rounding=int(cost_1%10)
        to_be_added=10-rounding
        total_cost=int(cost_1)+int(to_be_added)
        user_qur=user.query.filter_by(username=g.user).first()
        user_wallet_qur=wallet_all.query.filter_by(ref_id=user_qur.id,ref_type='user').first()
        owner_wallet_qur=wallet_all.query.filter_by(ref_id=owner_name,ref_type='owner').first()
        if user_wallet_qur.ammount>total_cost:
            user_wallet_qur.ammount=user_wallet_qur.ammount-total_cost
            owner_wallet_qur.ammount=owner_wallet_qur.ammount+total_cost
            db.session.commit()
            mm=random.randrange(000000,999999)
            s_code=mm
            user_qur = user.query.filter_by(username=g.user).first()
            user_wallet_qur = wallet_all.query.filter_by(ref_id=user_qur.id, ref_type='user').first()
            owner_wallet_qur = wallet_all.query.filter_by(ref_id=owner_name, ref_type='owner').first()
            data={}
            data['s_code']=s_code
            data['total_cost']=total_cost
            data['email']=zz.email
            data['time_period']=time_period
            data['faq_url']=f'{host_name}/faqs'
            data['gym_name']=gym_qur.gym_name
            data['address_1']=gym_qur.address_1
            data['address_2']=gym_qur.address_2
            data['city']=gym_qur.city
            data['state']=gym_qur.state
            data['postal_code']=gym_qur.postal_code
            data['contact']=gym_qur.contact_number
            data['m_open']=gym_qur.m_open
            data['m_close']=gym_qur.m_close
            data['e_open']=gym_qur.e_open
            data['e_close']=gym_qur.e_close
            send_user_mail_gym_booked(data)
            data={}
            data['s_code']=s_code
            data['total_cost']=total_cost
            data['time_period']=time_period
            data['username']=user_qur.username
            data['email']=user_qur.email
            data['faq_url']=f'{host_name}/faqs'
            send_gym_owner_mail_user_booked_gym(data)
            return redirect(url_for('account'))
        else:
            flash("You don't have enough funds in your account.")
    return render_template("gym_time_selection.html")

def send_user_mail_gym_booked(data):
    with app.app_context():
        msg=Message('Gym Booked',sender='gymaale.business@gmail.com',recipients=[data['email']])
        msg.html=render_template("email_user_gym_booked.html",time_period=data['time_period'],s_code=data['s_code'],total_cost=data['total_cost'],data=data,_external=True)
        mail.send(msg)


def send_gym_owner_mail_user_booked_gym(data):
    with app.app_context():
        msg=Message('User Booked Gym',sender='gymaale.business@gmail.com',recipients=[data['email']])
        msg.html=render_template("email_gym_owner_mail_user_booked_gym.html",time_period=data['time_period'],data=data,s_code=data['s_code'],total_cost=data['total_cost'],_external=True)
        mail.send(msg)

'''
@app.route('/trainer_registeration/trainer_account/wallet')
def wallet():
    return render_template('trainer_wallet.html')

@app.route('/trainer_registeration/trainer_account/wallet/add')
def trainer_wallet_add():
    if g.owner:
        zz=trainerregister.query.filter_by(username=g.trainer).first()
        ref_type='trainer'
    return redirect(url_for(''))
'''
@app.route('/bcaa')
@login_required
def bcaa():
    return render_template("supple/bcaa.html")


@app.route('/cm')
@login_required
def cm():
    return render_template("supple/cm.html")


@app.route('/pp')
@login_required
def pp():
    return render_template("supple/pp.html")


@app.route('/pw')
@login_required
def pw():
    return render_template("supple/pw.html")


@app.route('/wg')
@login_required
def wg():
    return render_template("supple/wg.html")


"""These routes are for the trainers which are available for training."""


@app.route('/yash_sharma')
@login_required
def Yash_sharma():
    return render_template("trainers/ys.html")


@app.route('/sourav_singh_rajput')
@login_required
def sourav_singh_rajput():
    return render_template("trainers/ssr.html")


@app.route('/zaid_khan')
@login_required
def zaid_khan():
    return render_template("trainers/zk.html")


@app.route('/yash_anand')
@login_required
def yash_anand():
    return render_template("trainers/ya.html")


@app.route('/rohit_khatri')
@login_required
def rohit_khatri():
    return render_template("trainers/rk.html")


@app.route('/akshat_mathur')
@login_required
def akshat_mathur():
    return render_template("trainers/am.html")


"""These routes are for different supplements in bcaa which are provided with us."""


@app.route('/bcaa/asit')
@login_required
def bcaa_asit():
    return render_template("supple/bcaa/asit.html")


@app.route('/bcaa/muscleblaze')
@login_required
def bcaa_muscleblaze():
    return render_template("supple/bcaa/muscleblaze.html")


@app.route('/bcaa/myprotien')
@login_required
def bcaa_myprotien():
    return render_template("supple/bcaa/myprotien.html")


"""These routes are for different supplements in Creatine monohydrate which are provided with us."""


@app.route('/cm/asit')
@login_required
def cm_asit():
    return render_template("supple/cm/asit.html")


@app.route('/cm/muscleblaze')
@login_required
def cm_muscleblaze():
    return render_template("supple/cm/muscleblaze.html")


@app.route('/cm/myprotien')
@login_required
def cm_myprotien():
    return render_template("supple/cm/myportien.html")


"""These routes are for different supplements in  Protien Powder which are provided with us."""


@app.route('/pp/musclepharm')
@login_required
def pp_musclepharm():
    return render_template("supple/pp/musclepharm.html")


@app.route('/pp/nutrabay')
@login_required
def pp_nutrabay():
    return render_template("supple/pp/nutrabay.html")


@app.route('/pp/on')
@login_required
def pp_on():
    return render_template("supple/pp/on.html")


"""These routes are for different supplements in Pre Workout which are provided with us."""


@app.route('/pw/musclepharm')
@login_required
def pw_musclepharm():
    return render_template("supple/pw/musclepharm.html")


@app.route('/pw/muscleblaze')
@login_required
def pw_muscleblaze():
    return render_template("supple/pw/muscleblaze.html")


@app.route('/pw/on')
@login_required
def pw_on():
    return render_template("supple/pw/on.html")


"""These routes are for different supplements in Weight Gainer which are provided with us."""


@app.route('/wg/muscleblaze')
@login_required
def wg_muscleblaze():
    return render_template("supple/wg/muscleblaze.html")


@app.route('/wg/myprotien')
@login_required
def wg_myprotien():
    return render_template("supple/wg/myprotien.html")


@app.route('/wg/xtreme')
@login_required
def wg_xtreme():
    return render_template("supple/wg/xtreme.html")


@app.route('/services', methods=["GET", "POST"])
@login_required
def services():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("services.html")


@app.route('/contact', methods=["GET", "POST"])
def contact():
    if g.owner:
        decide = 'owner'
        zz = ownerregister.query.filter_by(username=g.owner).first()
        value1 = zz.id
    elif g.trainer:
        decide = 'trainer'
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
    else:
        decide = 'NULL'
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("contact.html", decide=decide)


@app.route('/gym_accessories', methods=["GET", "POST"])
@login_required
def gym_accessories():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("gym_accessories.html")


@app.route('/offers', methods=["GET", "POST"])
@login_required
def offers():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("offers.html")


admin.add_view(MyModelView(user, db.session))
admin.add_view(MyModelView(dmail, db.session))
admin.add_view(MyModelView(user_data2, db.session))
admin.add_view(MyModelView(image, db.session))
admin.add_view(MyModelView(blog2, db.session))
admin.add_view(MyModelView(ownerregister, db.session))
admin.add_view(MyModelView(owner_detail, db.session))
admin.add_view(MyModelView(gym_detail, db.session))
admin.add_view(MyModelView(gym_image, db.session))
admin.add_view(MyModelView(trainerregister, db.session))
admin.add_view(MyModelView(trainer_detail, db.session))
admin.add_view(MyModelView(trainer_image, db.session))
admin.add_view(MyModelView(wallet_all,db.session))

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
