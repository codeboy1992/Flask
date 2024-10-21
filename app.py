from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import SignupForm, LoginForm
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

# Initialisation de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('signup'))
        else:
            # Si aucun utilisateur n'existe, le premier est défini comme admin
            is_admin = False
            if User.query.count() == 0:
                is_admin = True

            new_user = User(
                username=form.username.data,
                email=form.email.data,
                is_admin=is_admin
            )
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()  # Sauvegarde l'utilisateur dans la base de données

            flash('User successfully registered! Please log in.', 'success')
            return redirect(url_for('login', email=form.email.data))
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')

            # Redirige les administrateurs vers le admin_dashboard
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))  # Pour les utilisateurs non-admin
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        # Récupérer tous les utilisateurs triés par date d'inscription (par id ici, car id auto-incrémenté)
        users = User.query.order_by(User.id).all()
        return render_template('dashboard.html', user=current_user, users=users)
    else:
        # Récupérer le nombre d'utilisateurs et leurs usernames
        total_users = User.query.count()
        usernames = [user.username for user in User.query.all()]
        return render_template('dashboard.html', user=current_user, total_users=total_users, usernames=usernames)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Accès refusé. Vous n\'êtes pas administrateur.', 'danger')
        return redirect(url_for('dashboard'))

    # Récupérer tous les utilisateurs pour l'admin
    users = User.query.order_by(User.id).all()

    # Passer les utilisateurs et l'utilisateur connecté au template
    return render_template('admin_dashboard.html', user=current_user, users=users)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Vous n'êtes pas autorisé à effectuer cette action.", 'danger')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"L'utilisateur {user.username} a été supprimé avec succès.", 'success')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash("Vous n'êtes pas autorisé à effectuer cette action.", 'danger')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    form = SignupForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.is_admin = bool(form.is_admin.data)  # Corriger pour bien traiter la checkbox
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash(f"L'utilisateur {user.username} a été modifié avec succès.", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', form=form, user=user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Créer les tables si elles n'existent pas
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
