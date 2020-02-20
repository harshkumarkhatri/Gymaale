from flask import Flask, send_file, render_template, request, flash, redirect, url_for, session, logging, request, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user, \
    AnonymousUserMixin
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
from werkzeug.utils import secure_filename
import random
import os
import sqlite3
import smtplib
from smtplib import SMTPException, SMTP
from flask_mail import Mail, Message
from flask_wtf import Form, FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from io import BytesIO
import webbrowser
import base64
from base64 import b64encode
import webbrowser
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
# import socket
# socket.getaddrinfo('170.16.4.100', 3128)


from dateutil import parser

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gymaale.buisness@gmail.com'
app.config['MAIL_PASSWORD'] = 'harsh96722@'
mail = Mail(app)

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
        # print(mm)
        # print(mm.username)
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
    image1 = db.Column(db.LargeBinary)
    image2 = db.Column(db.LargeBinary)
    image3 = db.Column(db.LargeBinary)
    image4 = db.Column(db.LargeBinary)
    image5 = db.Column(db.LargeBinary)

    def __init__(self, ref_id, image1, image2, image3, image4, image5):
        if ref_id:
            self.ref_id = ref_id
        else:
            self.ref_id = None
        if image1:
            self.image1 = image1
        else:
            self.image1 = None
        if image2:
            self.image2 = image2
        else:
            self.image2 = None
        if image3:
            self.image3 = image3
        else:
            self.image3 = None
        if image4:
            self.image4 = image4
        else:
            self.image4 = None
        if image5:
            self.image5 = image5
        else:
            self.image5 = None


class trainer_image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref_id = db.Column(db.Integer)
    owner_ref_id = db.Column(db.Integer)
    image1 = db.Column(db.LargeBinary)
    image2 = db.Column(db.LargeBinary)
    image3 = db.Column(db.LargeBinary)
    image4 = db.Column(db.LargeBinary)
    image5 = db.Column(db.LargeBinary)

    def __init__(self, ref_id, owner_ref_id, image1, image2, image3, image4, image5):
        if ref_id:
            self.ref_id = ref_id
        else:
            self.ref_id = None
        if owner_ref_id:
            self.owner_ref_id = owner_ref_id
        else:
            self.owner_ref_id = None
        if image1:
            self.image1 = image1
        else:
            self.image1 = None
        if image2:
            self.image2 = image2
        else:
            self.image2 = None
        if image3:
            self.image3 = image3
        else:
            self.image3 = None
        if image4:
            self.image4 = image4
        else:
            self.image4 = None
        if image5:
            self.image5 = image5
        else:
            self.image5 = None


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
    data = db.Column(db.LargeBinary)

    def __init__(self, user_id, ibt, file_name, data):
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
        if data:
            self.data = data
        else:
            self.data = None


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


# this class doesnt has any table in our database.
class EditProfileForm(user):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')


class trainer_detail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    address = db.Column(db.String(200))
    state = db.Column(db.String(40))
    city = db.Column(db.String(40))
    charges = db.Column(db.Integer)
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

    def __init__(self, first_name, last_name, address, state, city, charges, c_mail, p_mob, c_mob, age, t_time,
                 certifications,
                 training_mode
                 , diet_support, training_support, insta_link, youtube_link, desc, ref_id, owner_ref_id, cb, verified):
        self.first_name = first_name
        self.last_name = last_name
        self.address = address
        self.state = state
        self.city = city
        self.charges = charges
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
    id = db.Column(db.Integer, primary_key=True)
    ref_id = db.Column(db.Integer)
    ref_type = db.Column(db.String(40))
    ammount = db.Column(db.Integer)


"""class blog(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100),nullable=False)
    date_posted=db.Column(db.DateTime,nullable=False, default=datetime.utcnow)
    content=db.Column(db.Text,nullable=False)

    def __repr__(self):
        return user('{self.title}','{sel.date_posted}','{self.content}')
"""


# this class doesnt has any tables in our database.
class RequestResetForm(FlaskForm):
    email = db.Column(db.String(120))
    submit = SubmitField('Request Password Reset')


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


def send_reset_email(z):
    token = z.get_reset_token()
    msg = Message('Password Reset Request', sender='gymaale.buisness@gmail.com', recipients=[z.email])
    msg.html = render_template("email_message_for_reset.html", z=z, token=token, _external=True)
    mail.send(msg)


def send_confirmation_email(z):
    token = z.get_confirmation_token()
    msg = Message('Email Confirmation', sender='gymaale.buisness@gmail.com', recipients=[z.email])
    msg.html = render_template("email_message.html", z=z, token=token, _external=True)
    mail.send(msg)


@app.route('/forgot_request', methods=["GET", "POST"])
def forgot_request():
    if request.method == "POST":
        cmail = request.form['cmail']
        z = user.query.filter_by(email=cmail).first()
        if z is not None:
            send_reset_email(z)
            flash("EMAIL SENT")
            return redirect(url_for('login'))
            # return "success"
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
        send_password_reset_successful(value2)
        return redirect(url_for('login'))
    return render_template("reset_password.html")


def send_password_reset_successful(value2):
    msg = Message('Password reset successful', sender='gymaale.business@gmail.com', recipients=[value2])
    msg.html = render_template("email_password_reset_successful.html", _external=True)
    mail.send(msg)


@app.route('/main', methods=["GET", "POST"])
@login_required
def main():
    b_posts = blog2.query.all()
    # for b_post in b_posts:
    # for b_post in b_posts:
    #   value=b_post.title
    #  value2=b_post.date
    # value3=b_post.b_txt
    # print(value)
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
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
            # print(fir_name,la_name,addr,umar,pref,at,exp,upd,iid)
            todo = user_data2(first_name=fir_name, last_name=la_name, address=addr, age=umar, interest=pref,
                              already_gymming=at, time=exp, update=upd, user_id=iid)
            db.session.add(todo)
            db.session.commit()
            return redirect(url_for('main')), flash("Data submitted successfully")
    return render_template("know.html")


# currently not in use
"""
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('change_uname.html', title='Edit Profile',
                           form=form)
"""


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

            # flash(f'Account created successfully.', 'success')
            db.session.add(register)
            db.session.commit()
            getting_above_user_id = user.query.filter_by(username=uname).first()
            addingToWallet = wallet_all(ref_id=getting_above_user_id.id, ref_type='user', ammount=0)
            db.session.add(addingToWallet)
            db.session.commit()
            z = user.query.filter_by(email=mail).first()
            if z is not None:
                send_confirmation_email(z)
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
            send_admin_email(m, uname, passw, email, sec_code)
            return redirect(url_for('default')), flash('Your data has been submitted.\n'
                                                       'You will recieve an email when it has been verified.\n'
                                                       'Verification generally takes 24 hours.\n')
    return render_template("admin_register.html", value=mm)


def send_admin_email(m, uname, passw, email, sec_code):
    # print(m,uname,passw,email,sec_code)
    msg = Message('Admin Verification', sender='gymaale.buisness@gmail.com', recipients=[m])
    msg.html=render_template('email_admin_to_verify_user_As_Admin.html',email=email,uname=uname,passw=passw,sec_code=sec_code,_external=True)
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
        send_user_email(mm)
        return redirect(url_for('default')), flash('The user has been added as an admin.')
    return render_template("user_as_admin.html")


def send_user_email(mm):
    msg = Message('Admin Account Verification', sender='gymaale.buisness@gmail.com', recipients=[mm.email])
    msg.html=render_template('email_user_confirmed_as _admin.html',_external=True)
    mail.send(msg)


@app.route('/admin')
def admin__():
    return redirect("http://localhost:5000/admin", code=302)


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
        # print(dname)
        login = user.query.filter_by(username=dname).first()
        if login:
            # print('login')
            # print(login)
            # print(login.username)
            if check_password_hash(login.password, passw):
                #   print('check')
                if login is not None:
                    session['logged_in'] = uname
                    if login.verification == "Yes":
                        return redirect(url_for("jj"))
                    else:
                        return redirect(url_for('login')), flash(
                            "you are not verified check gmail for verification link")
        else:
            flash('Invalid Username or Password.')
    return render_template("login.html", username=user)


@app.route('/account', methods=["GET", "POST"])
@login_required
def account():
    if g.user:
        m = g.user
    if m == g.user:
        z = user.query.filter_by(username=g.user).first()
        value1 = z.id
        # print(z.id)
        zz = user_data2.query.filter_by(user_id=z.id).first()
        # print(zz)
        xyz = image.query.filter_by(user_id=z.id).first()
        imag = base64.b64encode(xyz.data).decode('ascii')
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
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("account.html", value=m, value2=z.email, value3=value3, value4=value4,
                           value5=value5, value6=value6, value7=value7, value8=value8,
                           wallet_ammount=wallet_qur.ammount, value9=value9, imag=imag)


@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    if g.user:
        z = user.query.filter_by(username=g.user).first()
        # value1=z.username
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
                # db.session.delete(mm)
                """hashed_value = generate_password_hash(npass)
                nu = user(username=g.user, password=hashed_value, email=value2)
                db.session.add(nu)
                db.session.commit()"""
                # m = session.password.data
            else:
                return redirect(url_for('change_password')), flash("Passwords don not match.")
        else:
            return redirect(url_for('change_password')), flash("Current password incorrect.")
        return redirect(url_for('account_settings')), flash("Password Changed Successfully")
    return render_template("change_password.html")


# currently not working
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


# making session sustain for 5 days
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


"""@app.route('/test')
def my_page():
    return webbrowser.open_new_tab('http://gmail.com')"""


def send_user_account_creation_email(mm):
    msg = Message('Account Created', sender='gymaale.business@gmail.com', recipients=[mm.email])
    msg.html = render_template("email_user_account_creation_congratulating.html", mm=mm)
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
                send_user_account_creation_email(mm)
            else:
                return redirect(url_for('confirm_email')), flash("Incorrect Code")
            return redirect(url_for('login')), flash("Account has been verified. Now you can login.")
        return render_template("verification.html")


@app.route('/mj')
def mj():
    return render_template("change_image.html")


@app.route('/change_image', methods=["GET", "POST"])
def change_image():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
        value2 = zz.username
    file = request.files['inputfile']
    #   print(file.filename)
    zz = file.filename
    if not "." in zz:
        return redirect(url_for('mj')), flash("Please choose an image")
    else:
        qur = image.query.filter_by(user_id=value1, ibt=value2).first()
        qur.data = file.read()
        db.session.commit()
        """image_string = base64.b64encode(image.read())
        newfile = image(file_name=file.filename, ibt=value2, user_id=value1, data=file.read())
        db.session.add(newfile)
        db.session.commit()"""
        return redirect(url_for('account_settings')), flash("Profile changed successfully.")


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
        # print(imail)
        # print(iid)
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
    # va=image.query.filter_by(user_id=value1).first()
    # if va:
    #    return redirect(url_for('user_data'))
    # else:
    file = request.files['inputfile']
    print(file)
    newfile = image(file_name=file.filename, ibt=value2, user_id=value1, data=file.read())
    db.session.add(newfile)
    db.session.commit()
    # image=request.files["image"]
    # return redirect(url_for('user_data'))
    return redirect(url_for('user_data'))


@app.route("/show")
def show(id):
    obj = image.query.filter_by(user_id=id).first()
    #  print(obj)
    iimage = b64encode(obj.data).decode("utf-8")
    # print(iimage)
    return render_template("faltu2.html", obj=obj, image=iimage)


@app.route('/img')
def img():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    #  print(zz, value1)
    file_data = image.query.filter_by(user_id=value1).first()
    # print(file_data)
    id = value1
    show(id)
    # up_file=file_data.data
    # return send_file(BytesIO(file_data.data),attachment_filename='user.img')
    return render_template("faltu2.html")


@app.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        f.save(secure_filename(f.filename))
        return 'file uploaded successfully'


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
        # print(imail)
        # print(iid)
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
        # print(imail)
        # print(iid)
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
        # print(imail)
        # print(iid)
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
                    getting_above_entry_id = ownerregister.query.filter_by(username=uname).first()
                    addingToWallet = wallet_all(ref_id=getting_above_entry_id.id, ref_type='owner', ammount=0)
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
        # print(mnn)
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
            # print(any_other_gym)
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
        # print(mnn)
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
                send_gym_creation_congratulating(xyz, 'first')
            return redirect(url_for('gym_images'))
    return render_template("gym_registeration/gym_details.html")


def send_gym_creation_congratulating(xyz, mmm):
    print(xyz)
    print(mmm)
    msg = Message('Gym Registeration', sender='gymaale.buisness@gmail.com', recipients=[xyz.email])
    msg.html = render_template("email_gym_creation_congratulating.html", _external=True, mmm=mmm)
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
    file1 = request.files['inputfile1']
    file2 = request.files['inputfile2']
    file3 = request.files['inputfile3']
    file4 = request.files['inputfile4']
    file5 = request.files['inputfile5']
    #  print(file1.filename)
    # print(file2.filename)
    # print(file3.filename)
    # print(file4.filename)
    # print(file5.filename)
    mm = gym_image(ref_id=ref, image1=file1.read(), image2=file2.read(), image3=file3.read(),
                   image4=file4.read(), image5=file5.read())
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
            ref_id = xyz.id
            zz = gym_detail.query.filter_by(address_1=add).first()
            if zz:
                flash("A gym with this address is already registered")
            else:
                xxx = gym_detail(gym_name=fname, address_1=add, address_2=add2, contact_number=mob,
                                 state=state, city=city, postal_code=p_code, monthly_fees=m_fees, yearly_fees=y_fees,
                                 trainers_available=trainers, features=feat, estlb=estab, desc=desc, owner_ref=ref_id,
                                 m_open=m_open, m_close=m_close, e_open=e_open, e_close=e_close)
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
        # print(imail)
        # print(iid)
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
        image_1 = base64.b64encode(qur.image1).decode('ascii')
        image_2 = base64.b64encode(qur.image2).decode('ascii')
        image_3 = base64.b64encode(qur.image3).decode('ascii')
        image_4 = base64.b64encode(qur.image4).decode('ascii')
        image_5 = base64.b64encode(qur.image5).decode('ascii')
        print(xy)
        for i in mmm:
            print(i)

    wallet_qur = wallet_all.query.filter_by(ref_id=zz.id, ref_type='owner').first()
    print(zz.id)
    print(wallet_qur)
    if wallet_qur == None:
        ammount_to_be_displayed = 0
    else:
        ammount_to_be_displayed = wallet_qur.ammount
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
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("gym_registeration/owner_account.html", username=username, email=email,
                           f_name=f_name, l_name=l_name, address=address, mobile=mobile, mnn=mnn,
                           u_train=u_train, xy=xy, image_1=image_1, image_2=image_2, image_3=image_3,
                           image_4=image_4, image_5=image_5, wallet_ammount=ammount_to_be_displayed)


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
        image_1 = base64.b64encode(dd.image1).decode('ascii')
        image_2 = base64.b64encode(dd.image2).decode('ascii')
        image_3 = base64.b64encode(dd.image3).decode('ascii')
        image_4 = base64.b64encode(dd.image4).decode('ascii')
        image_5 = base64.b64encode(dd.image5).decode('ascii')
        decide = 'owner'
        print('executing this')
        print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
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


# page for changing the owner details
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


# page for selecting the gym if multiple gyms are there.
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


# page for changing the details of gym
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


# show all the various options for gyms available to us.
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
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("various_gym.html", g_names=g_names)


# shows the details of a particular gym with its id.
@app.route('/various_gyms/<gym_id>')
@login_required
def gym_detailss(gym_id):
    gym_details = gym_detail.query.filter_by(gym_name=gym_id).first()
    owner_detail_now = owner_detail.query.filter_by(id=gym_details.id).first()
    image_details_now = gym_image.query.filter_by(ref_id=gym_details.owner_ref).first()
    owner_qur = ownerregister.query.filter_by(id=gym_details.owner_ref).first()
    print(owner_qur)
    img_1 = base64.b64encode(image_details_now.image1).decode('ascii')
    img_2 = base64.b64encode(image_details_now.image2).decode('ascii')
    img_3 = base64.b64encode(image_details_now.image3).decode('ascii')
    img_4 = base64.b64encode(image_details_now.image4).decode('ascii')
    img_5 = base64.b64encode(image_details_now.image5).decode('ascii')
    owner_name = 'demo'

    return render_template("Various_gyms/gym_details.html", title=gym_details.gym_name, g_names=gym_details,
                           o_names=owner_detail_now, img_1=img_1, img_2=img_2, img_3=img_3,
                           img_4=img_4, img_5=img_5)


# landing page for trainers having login and register.
@app.route('/trainer_register')
def trainer_register_landingpage():
    return render_template('trainer_registeration/landingpage.html')


# login page for trainers.
@app.route('/trainer_register/login', methods=["GET", "POST"])
def trainer_login():
    if request.method == "POST":
        uname = request.form['uname']
        passw = request.form['passw']
        login = trainerregister.query.filter_by(username=uname).first()
        if login:
            if check_password_hash(login.password, passw):
                session['trainer'] = uname
                xyz = trainerregister.query.filter_by(username=uname).first()
                zz = trainer_detail.query.filter_by(ref_id=xyz.id).first()
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
    session.pop('trainer', None)
    flash("You have been logged out successfully")
    return redirect(url_for('trainer_login'))


# registering the trainer.
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
                    getting_above_trainer_id = trainerregister.query.filter_by(username=uname).first()
                    addingToWallet = wallet_all(ref_id=getting_above_trainer_id.id, ref_type='trainer', ammount=0)
                    db.session.add(addingToWallet)
                    db.session.commit()
                    return redirect(url_for('trainer_details'))
        else:
            return redirect(url_for('trainer_register')), flash("Password do not match!!")
    return render_template("trainer_registeration/trainer_register.html")


# accepting trainer details and sending them to the admin for verification.
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
        charges = int(request.form['charges'])
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
                             state=state, city=city, charges=charges,
                             c_mail=c_mail, p_mob=p_mob, c_mob=c_mob,
                             age=age, t_time=t_time, certifications=certi,
                             training_mode=mode, diet_support=d_support, training_support=t_support,
                             insta_link=i_link, youtube_link=y_link, desc=desc, ref_id=ref_id,
                             owner_ref_id=owner_ref_id, cb=cb, verified=verified)
        db.session.add(new)
        db.session.commit()
        qur = trainer_detail.query.filter_by(first_name=fname, last_name=lname, p_mob=p_mob).first()
        print(qur)
        send_trainer_details_email(qur)
        return redirect(url_for('trainer_images')), flash(
            'Your details have been submitted and will be visible to users once verified. Genenrally the verification may take upto 24 hours.')
    return render_template("trainer_registeration/trainer_details.html")


# sending email to admin to confirm the details of the trainer.
def send_trainer_details_email(qur):
    print(qur.first_name)
    recp = 'gymaale.buisness@gmail.com'
    msg = Message('CONFIRM THE TRAINER', sender='gymaale.buisness@gmail.com', recipients=[recp])
    msg.html = render_template("email_trainer_details_confirmation.html", qur=qur, _externaml=True)
    mail.send(msg)


# by this we can confirm the details of the trainer which are sent to us and can mark it as verified.
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
            send_trainer_confirmation_mail(xyz)
    return render_template("confirm_trainer_details.html")


# sending a conformation email to the trainer.
def send_trainer_confirmation_mail(xyz):
    msg = Message('Account Verified', sender='gymaale.buisness@gmail.com', recipients=[xyz.email])
    msg.html = render_template("email_trainer_account_verified.html", _external=True)
    mail.send(msg)


# page displayed for accepting trainer images.
@app.route('/trainer_register/trainer_details/trainer_images', methods=["GET", "POST"])
def trainer_images():
    return render_template("trainer_registeration/trainer_images.html")


# page accepting trainer images and uploading them to db
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
    file1 = request.files['inputfile1']
    file2 = request.files['inputfile2']
    file3 = request.files['inputfile3']
    file4 = request.files['inputfile4']
    file5 = request.files['inputfile5']
    new = trainer_image(ref_id=ref_id, image1=file1.read(), image2=file2.read(), image3=file3.read(),
                        image4=file4.read(), image5=file5.read(), owner_ref_id=owner_ref_id)
    db.session.add(new)
    db.session.commit()
    if g.owner:
        return redirect(url_for('trainer_account_2'))
    else:
        return redirect(url_for('trainer_account'))


# displays the trainer account
@app.route('/trainer_registeration/trainer_account', methods=["GET", "POST"])
def trainer_account():
    if g.trainer:
        print(g.trainer)
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        value1 = zz.id
        mm = trainer_detail.query.filter_by(ref_id=zz.id).first()
        nn = trainer_image.query.filter_by(ref_id=zz.id).first()
    trainer_wallet_qur = wallet_all.query.filter_by(ref_id=value1, ref_type='trainer').first()
    print(trainer_wallet_qur.ammount)
    if nn == None:
        return redirect(url_for('trainer_images'))
    else:
        image_1 = base64.b64encode(nn.image1).decode('ascii')
        image_2 = base64.b64encode(nn.image2).decode('ascii')
        image_3 = base64.b64encode(nn.image3).decode('ascii')
        image_4 = base64.b64encode(nn.image4).decode('ascii')
        image_5 = base64.b64encode(nn.image5).decode('ascii')
        print(mm.first_name)
        decide = 'trainer'
        print(decide)
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("trainer_registeration/trainer_account.html", zz=zz, mm=mm, image_1=image_1,
                           image_2=image_2, image_3=image_3, image_4=image_4, image_5=image_5, decide=decide,
                           trainer_account_balance=trainer_wallet_qur.ammount)


# comtains the about page.
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


# page displayed after the email send after registeration(60 sec timer is in it)
@app.route('/waiting')
def waiting():
    return render_template("waiting.html")


# page for applying again for email sent to user after registeration.
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


# waste page
@app.route('/una')
def una():
    return render_template("una.html")


# contains the list of trainers with sorting function.
@app.route('/certified_trainers', methods=["GET", "POST"])
@login_required
def certified_trainers():
    page = request.args.get('page', 1, type=int)
    t_names = trainer_detail.query.order_by(trainer_detail.id.asc()).paginate(per_page=9, page=page)
    if request.method == "POST":
        dd = request.form['sort']
        # idas=id ascending and idds=id desending
        if dd == 'idas':
            t_names = trainer_detail.query.order_by(trainer_detail.id.asc()).paginate(per_page=9, page=page)
            return render_template("certified_trainers.html", t_names=t_names)
        elif dd == 'idds':
            t_names = trainer_detail.query.order_by(trainer_detail.id.desc()).paginate(per_page=9, page=page)
            return render_template("certified_trainers.html", t_names=t_names)
    return render_template("certified_trainers.html", t_names=t_names)


# displays the details of trainer with images.
@app.route('/certified_trainers/<trainer_id>')
@login_required
def trainer_detailss(trainer_id):
    trainer_qur = trainer_detail.query.filter_by(id=trainer_id).first()
    trainer_img = trainer_image.query.filter_by(ref_id=trainer_qur.id).first() or trainer_image.query.filter_by(
        owner_ref_id=trainer_qur.owner_ref_id).first()
    print(trainer_img)
    if trainer_img:
        imag_1 = base64.b64encode(trainer_img.image1).decode('ascii')
        imag_2 = base64.b64encode(trainer_img.image2).decode('ascii')
        imag_3 = base64.b64encode(trainer_img.image3).decode('ascii')
        imag_4 = base64.b64encode(trainer_img.image4).decode('ascii')
        imag_5 = base64.b64encode(trainer_img.image5).decode('ascii')
    else:
        imag_1 = None
        imag_2 = None
        imag_3 = None
        imag_4 = None
        imag_5 = None
    return render_template("gym_registeration/trainer_details.html", t_names=trainer_qur,
                           trainer_img=trainer_img, imag_1=imag_1, imag_2=imag_2,
                           imag_3=imag_3, imag_4=imag_4, imag_5=imag_5)


# Contains the terms and conditions which will be followed
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
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template('terms_and_conditions.html', factor=factor)


# contains the schedules page(workout)
@app.route('/schedules', methods=["GET", "POST"])
@login_required
def schedules():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("schedules.html")


# contains the bmi calculator page.
@app.route('/bmi', methods=["GET", "POST"])
@login_required
def bmi():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("bmi.html")


# contains the fat percentage calculator page
@app.route('/fat')
@login_required
def fat():
    return render_template("fat.html")


# containd the diet pdf page
@app.route('/healthy', methods=["GET", "POST"])
@login_required
def healthy():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
        adding = dmail(email=imail, owner_id=iid)
        db.session.add(adding)
        db.session.commit()
    return render_template("healthy.html")


# it is the function running before any request made
# Helpful in managing the sessions.
@app.before_request
def before_request():
    g.user = None
    g.owner = None
    g.trainer = None
    # g.ownerregisterr=None
    # if g.ownerregisterr==None:
    #   if 'logged_in_2' in session:
    #      g.ownerregisterr=session['logged_in_2']
    # else:
    #   pass
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
        # print(imail)
        # print(iid)
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
                    send_blog_added(zz, title)
            else:
                print('not submitted')
            return render_template('publishing_blog_post.html')


# it sends the mail to the newletter subscribers about a new blog being published.
def send_blog_added(zz, title):
    msg = Message('New Blog Added', sender='gymaale.business@gmail.com', recipients=[zz])
    msg.html = render_template("email_blog_added.html", title=title, _external=True)
    mail.send(msg)


@app.route('/account/wallet')
def wallet():
    return render_template('wallet.html')


@app.route('/account/wallet/add', methods=["GET", "POST"])
def wallet_add():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        ref_id = zz.id
        ref_type = 'user'
    elif g.owner:
        zz = ownerregister.query.filter_by(username=g.owner).first()
        ref_id = zz.id
        ref_type = 'owner'
    elif g.trainer:
        zz = trainerregister.query.filter_by(username=g.trainer).first()
        ref_id = zz.id
        ref_type = 'trainer'
    if request.method == "POST":
        loop = wallet_all.query.filter_by(ref_id=ref_id, ref_type=ref_type).first()
        startAmmount = request.form['startAmmount']
        print(ref_type)
        print(ref_id)
        userEmail = zz.email
        if loop:
            ammount = loop.ammount
            ammount = int(ammount + int(startAmmount))
            loop.ammount = ammount
            db.session.commit()
            print(ammount)
            send_ammount_added_to_wallet_email(startAmmount, userEmail)
        else:
            ref_id_from_above = ref_id
            adding = wallet_all(ref_id=ref_id_from_above, ref_type=ref_type, ammount=startAmmount)
            db.session.add(adding)
            db.session.commit()

            send_ammount_added_to_wallet_email(startAmmount, userEmail)
        return redirect(url_for('account')), flash("Ammount added")
    return render_template('walletAdd.html')


def send_ammount_added_to_wallet_email(startAmmount, userEmail):
    print(startAmmount)
    print(userEmail)
    msg = Message('Ammount added', sender='gymaale.business@gmail.com', recipients=[userEmail])
    msg.html = render_template('email_conformation_ammount_added_to_wallet.html', ammount=startAmmount, _external=True)
    mail.send(msg)


@app.route('/transaction/<trans>/<ref_type>/<ref_id>', methods=["GET", "POST"])
def transaction(trans, ref_id, ref_type):
    print(ref_id)
    print(ref_type)
    print(trans)
    if request.method == "POST":
        if ref_type == 'trainer':
            trainer_qur = trainerregister.query.filter_by(id=ref_id).first()
            if trainer_qur:
                ref_type = 'trainer'
            trainer_wallet_qur = wallet_all.query.filter_by(ref_id=ref_id, ref_type=ref_type).first()
            print("trainer_wallet_qur")
            print(trainer_wallet_qur)

            if g.user:
                zz = user.query.filter_by(username=g.user).first()
                xyz = user_data2.query.filter_by(user_id=zz.id).first()
                wall = wallet_all.query.filter_by(ref_id=zz.id).first()
                if int(wall.ammount) > int(trans):
                    wall.ammount = wall.ammount - int(trans)
                    print(wall.ammount)
                    db.session.commit()
                    user_Email = zz.email
                    getting_trainer_details = trainer_detail.query.filter_by(ref_id=trainer_qur.id).first()
                    print(getting_trainer_details.first_name)
                    # sending a mail to user about trainer booking.
                    send_user_email_about_trainer_booking(user_Email, getting_trainer_details, trans)
                    trainer_email = trainer_qur.email
                    trainer_wallet_qur.ammount = trainer_wallet_qur.ammount + int(trans)
                    print(trainer_wallet_qur)
                    db.session.commit()
                    # Sending a mail to trainer about ammount being added and user details
                    send_trainer_ammount(zz, xyz, trans, trainer_email)
                    return redirect(url_for('account')), flash(
                        "Your ammount has been submitted to the trainer. You will recieve a mail from the trainer with in 8 hours")
                else:
                    flash("You dont have funds in your wallet")
        '''elif ref_type=='owner':
            owner_qur=ownerregister.query.filter_by(id=ref_id).first()
            if owner_qur:
                ref_type='owner'
            owner_wallet_qur=wallet_all.query.filter_by(ref_id=ref_id,ref_type=ref_type).first()
            print("owner_wallet_qur")
            print(owner_wallet_qur)'''
    return render_template('transaction.html', trans=trans)


# this function is used to send a mail to the user about the trainer being booked by the user along with trainer details
def send_user_email_about_trainer_booking(user_Email, getting_trainer_details, trans):
    msg = Message('Trainer Booked', sender='gymaale.business@gmail.com', recipients=[user_Email])
    msg.html = render_template("email_user_deduction_and_trainer_details.html", trans=trans,
                               t_details=getting_trainer_details, _external=True)
    mail.send(msg)


# this function is used t send a mail to the trainer about the user who has booked along with the details.
def send_trainer_ammount(zz, xyz, trans, trainer_email):
    msg = Message('User Booking Confirmed', sender='gymaale.business@gmail.com', recipients=[trainer_email])
    msg.html = render_template("email_send_trainer_ammount_and_user_details.html", zz=zz, xyz=xyz, trans=trans,
                               _external=True)
    mail.send(msg)


@app.route('/transaction/select_time/<owner_name>', methods=["GET", "POST"])
def transaction_select_time(owner_name):
    print(owner_name)
    zz = ownerregister.query.filter_by(id=owner_name).first()
    print(zz.username)
    if request.method == "POST":
        day_or_month = request.form['any']
        time_period = request.form['city']
        if day_or_month == "month":
            convert_to_day = int(int(time_period) * 30)
            time_period = convert_to_day
        gym_qur = gym_detail.query.filter_by(owner_ref=owner_name).first()
        monthly_cost = int(gym_qur.monthly_fees)
        per_day_cost = int(monthly_cost / 30)
        cost_1 = int(int(per_day_cost) * int(time_period))
        rounding = int(cost_1 % 10)
        to_be_added = 10 - rounding
        total_cost = int(cost_1) + int(to_be_added)
        print(g.user)
        user_qur = user.query.filter_by(username=g.user).first()
        user_wallet_qur = wallet_all.query.filter_by(ref_id=user_qur.id, ref_type='user').first()
        owner_wallet_qur = wallet_all.query.filter_by(ref_id=owner_name, ref_type='owner').first()
        print(owner_wallet_qur.ammount)
        print(user_wallet_qur.ammount)
        if user_wallet_qur.ammount > total_cost:
            user_wallet_qur.ammount = user_wallet_qur.ammount - total_cost
            owner_wallet_qur.ammount = owner_wallet_qur.ammount + total_cost
            db.session.commit()
            mm = random.randrange(000000, 999999)
            s_code = mm
            send_user_mail_gym_booked(s_code, total_cost, gym_qur, zz, time_period)
            send_gym_owner_mail_user_booked_gym(s_code, total_cost, user_qur, time_period)
            print("success")
            print(user_wallet_qur.ammount)
            print(owner_wallet_qur.ammount)
            return redirect(url_for('account'))
        else:
            flash("You don't have enough funds in your account.")
    return render_template("gym_time_selection.html")


def send_user_mail_gym_booked(s_code, total_cost, gym_qur, zz, time_period):
    msg = Message('Gym Booked', sender='gymaale.business@gmail.com', recipients=[zz.email])
    msg.html = render_template("email_user_gym_booked.html", time_period=time_period, s_code=s_code,
                               total_cost=total_cost, gym_qur=gym_qur, _external=True)
    mail.send(msg)


def send_gym_owner_mail_user_booked_gym(s_code, total_cost, user_qur, time_period):
    msg = Message('User Booked Gym', sender='gymaale.business@gmail.com', recipients=[user_qur.email])
    msg.html = render_template("email_gym_owner_mail_user_booked_gym.html", time_period=time_period, user_qur=user_qur,
                               s_code=s_code, total_cost=total_cost, _external=True)
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


"""These routes are for the various gyms which are available in our app."""

"""
@app.route('/d3_fitness')
@login_required
def d3_fitness():
    return render_template("various_gyms/3d_fitness.html", pub_key=pub_key)


@app.route('/champion_gym')
@login_required
def champion_gym():
    return render_template("various_gyms/champion_gym.html")


@app.route('/fitness_care')
@login_required
def fitness_care():
    return render_template("various_gyms/fitness_care.html")


@app.route('/fitness_club')
@login_required
def fitness_club():
    return render_template("various_gyms/fitness_club.html")


@app.route('/fitness_square')
@login_required
def fitness_square():
    return render_template("various_gyms/fitness_square.html")


@app.route('/gold')
@login_required
def gold():
    return render_template("various_gyms/gold.html")


@app.route('/joggers_park')
@login_required
def joggers_park():
    return render_template("various_gyms/joggers_park.html")


@app.route('/reboot_fitness')
@login_required
def reboot_fitness():
    return render_template("various_gyms/reboot_fitness.html")


@app.route('/world_fitness')
@login_required
def world_fitness():
    return render_template("various_gyms/world_fitness.html")"""

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


"""@app.route('/pay', methods=['POST'])
def pay():
    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])
    charge = stripe.Charge.create(
        customer=customer.id,
        amount=19900,
        currency='inr',
        description='Successful Transaction'
    )
    return redirect(url_for('d3_fitness'))


@app.route('/forgot_password')
@login_required
def forgot_password():
    return render_template("forgot_request.html")
"""


@app.route('/services', methods=["GET", "POST"])
@login_required
def services():
    if g.user:
        zz = user.query.filter_by(username=g.user).first()
        value1 = zz.id
    if request.method == "POST":
        imail = request.form["imail"]
        iid = value1
        # print(imail)
        # print(iid)
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
        # print(imail)
        # print(iid)
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
        # print(imail)
        # print(iid)
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
        # print(imail)
        # print(iid)
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
admin.add_view(MyModelView(wallet_all, db.session))

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
