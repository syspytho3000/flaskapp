from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from geopy.distance import geodesic
import os
import logging

app = Flask(__name__)

# Hardcoding configuration settings
app.config['SECRET_KEY'] = 'myfirstsecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'michaelbaldwin780@gmail.com'
app.config['MAIL_PASSWORD'] = 'zjojeoolhipmiahv'
app.config['SECURITY_PASSWORD_SALT'] = 'myfirstsaltypassword'

db = SQLAlchemy(app)
mail = Mail(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s %(message)s')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        logging.info(f'User {email} logged in successfully.')
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    else:
        logging.warning(f'Failed login attempt for user {email}.')
        flash('Login failed. Check your email and password.', 'danger')
        return redirect(url_for('index'))

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    if password != confirm_password:
        logging.warning(f'Signup failed for user {email}. Passwords do not match.')
        flash('Passwords do not match!', 'danger')
        return redirect(url_for('index'))
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    token = generate_confirmation_token(email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    send_confirmation_email(email, confirm_url)
    logging.info(f'User {email} signed up successfully.')
    flash('Signup successful! Please check your email for confirmation.', 'success')
    return redirect(url_for('index'))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('index'))

def send_confirmation_email(email, confirm_url):
    msg = Message('Signup Confirmation', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Thank you for signing up! Please confirm your email by clicking on the following link: {confirm_url}'
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(email)
            reset_url = url_for('reset_with_token', token=token, _external=True)
            send_reset_email(email, reset_url)
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('index'))
    return render_template('reset_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = confirm_token(token)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset_with_token', token=token))
        hashed_password = generate_password_hash(password, method='sha256')
        user = User.query.filter_by(email=email).first_or_404()
        user.password = hashed_password
        db.session.add(user)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('index'))
    return render_template('reset_with_token.html', token=token)

def send_reset_email(email, reset_url):
    msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'To reset your password, click the following link: {reset_url}'
    mail.send(msg)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.email = request.form.get('new_email')
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        else:
            flash('User not found.', 'danger')
        return redirect(url_for('profile'))
    return render_template('profile.html')

def is_within_geofence(user_location, center_location, radius_km):
    distance = geodesic(user_location, center_location).km
    return distance <= radius_km

@app.route('/dashboard')
def dashboard():
    gps_data = {'latitude': 52.268, 'longitude': -113.811}
    user_location = (gps_data['latitude'], gps_data['longitude'])
    center_location = (52.268, -113.811)  # Horizon House location
    radius_km = 100
    if is_within_geofence(user_location, center_location, radius_km):
        flash('You are within the geofenced area.', 'success')
    else:
        flash('You are outside the geofenced area.', 'danger')
    return render_template('dashboard.html', gps_data=gps_data)

@app.route('/gps-data')
def gps_data():
    # Placeholder for real-time GPS data
    gps_data = {'latitude': 52.268, 'longitude': -113.811}
    return jsonify(gps_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

