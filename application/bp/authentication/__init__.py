from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from  application.database import User
from application import db
from werkzeug.security import check_password_hash
from application.bp.authentication.forms import LoginForm

authentication = Blueprint('authentication', __name__, template_folder='templates')

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('User Not Found', 'danger')
        elif not check_password_hash(user.password, form.password.data):
            flash('Password Incorrect', 'danger')
        else:
            login_user(user)
            return redirect(url_for('homepage.dashboard'))
    return render_template('login.html', form=form)

@authentication.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('homepage.homepage'))

@authentication.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')