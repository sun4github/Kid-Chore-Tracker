import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature # For password reset tokens
from flask_mail import Mail, Message # For sending emails

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_weak_default_secret_key_change_me')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'another_weak_salt_change_me') # Salt for tokens

# --- Database Setup (MongoDB) ---
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = 'chore_tracker_db'

try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    users_collection = db.users
    tasks_collection = db.tasks
    deductions_collection = db.deductions
    # Ensure unique email for parents and unique username overall
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email", unique=True, partialFilterExpression={"role": "parent"})
    client.admin.command('ping')
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    exit()

# --- Email Configuration (Flask-Mail) ---
# --> IMPORTANT: Use environment variables for sensitive data! <--
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587)) # Default TLS port
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Use App Password for Gmail
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)

# --- Helper Functions ---

def get_token_serializer():
    """Gets the serializer for generating and verifying tokens."""
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def send_email(to_email, subject, template):
    """Sends an email using Flask-Mail."""
    try:
        msg = Message(
            subject,
            recipients=[to_email],
            html=template,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        print(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
        # Log the error properly in a real application
        # current_app.logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def calculate_summaries(kid_username):
    """Calculates financial summaries for a given kid. (Unchanged from previous version)"""
    total_earned = Decimal('0.00')
    total_punishment_raw = Decimal('0.00')
    total_spent = Decimal('0.00')
    total_invested = Decimal('0.00')
    two_places = Decimal('0.01')
    try:
        completed_tasks = tasks_collection.find({
            "assigned_kid_username": kid_username,
            "status": "complete"
        })
        for task in completed_tasks:
            payment_str = task.get('calculated_payment', '0')
            try:
                payment = Decimal(str(payment_str))
            except:
                payment = Decimal('0.00')
            if task.get('type') == 'rewarding':
                total_earned += payment
            elif task.get('type') == 'punishment':
                total_punishment_raw += payment

        kid_deductions = deductions_collection.find({
            "kid_username": kid_username
        })
        for deduction in kid_deductions:
            amount_str = deduction.get('amount', '0')
            try:
                amount = Decimal(str(amount_str))
            except:
                amount = Decimal('0.00')
            if deduction.get('category') == 'spending':
                total_spent += amount
            elif deduction.get('category') == 'investment':
                total_invested += amount

        total_punishment = abs(total_punishment_raw)
        total_balance = total_earned - (total_spent + total_invested + total_punishment)

        summaries = {
            'earned': total_earned.quantize(two_places, rounding=ROUND_HALF_UP),
            'punishment': total_punishment.quantize(two_places, rounding=ROUND_HALF_UP),
            'spent': total_spent.quantize(two_places, rounding=ROUND_HALF_UP),
            'invested': total_invested.quantize(two_places, rounding=ROUND_HALF_UP),
            'balance': total_balance.quantize(two_places, rounding=ROUND_HALF_UP)
        }
        return summaries
    except Exception as e:
        print(f"Error calculating summaries for {kid_username}: {e}")
        return {
            'earned': Decimal('0.00'), 'punishment': Decimal('0.00'),
            'spent': Decimal('0.00'), 'invested': Decimal('0.00'),
            'balance': Decimal('0.00')
        }

# --- Routes ---

@app.route('/')
def index():
    """Redirects to login page or appropriate dashboard."""
    if 'username' in session:
        if session.get('role') == 'parent':
            return redirect(url_for('parent_dashboard'))
        elif session.get('role') == 'kid':
            return redirect(url_for('kid_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login (Parent or Kid)."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # No login_type needed, role is determined from DB

        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('login'))

        try:
            user = users_collection.find_one({"username": username})

            if user and check_password_hash(user['password_hash'], password):
                session['username'] = user['username']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                # Redirect based on role stored in DB
                if user['role'] == 'parent':
                    return redirect(url_for('parent_dashboard'))
                else: # Kid
                    # Verify kid is associated with *a* parent (optional check)
                    if not user.get('associated_parent_username'):
                         flash('Kid account is not fully set up. Please contact your parent.', 'warning')
                         session.clear() # Log them out
                         return redirect(url_for('login'))
                    return redirect(url_for('kid_dashboard'))
            else:
                flash('Invalid username or password.', 'error')

        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login.', 'error')

        return redirect(url_for('login'))

    # GET request
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register_parent', methods=['POST'])
def register_parent():
    """Handles parent registration."""
    username = request.form.get('reg_username')
    password = request.form.get('reg_password')
    email = request.form.get('reg_email')

    if not all([username, password, email]):
        flash('Username, password, and email are required for parent registration.', 'error')
        return redirect(url_for('login'))

    # Basic email format validation (more robust validation is better)
    if '@' not in email or '.' not in email.split('@')[-1]:
         flash('Invalid email address format.', 'error')
         return redirect(url_for('login'))

    try:
        # Check username uniqueness
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('login'))

        # Check email uniqueness among parents
        existing_email = users_collection.find_one({"email": email, "role": "parent"})
        if existing_email:
            flash('Email address already registered by another parent.', 'error')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "username": username,
            "password_hash": hashed_password,
            "role": "parent",
            "email": email.lower() # Store email lowercase
        })
        flash('Parent registration successful! Please log in.', 'success')

    except Exception as e:
        print(f"Parent registration error: {e}")
        flash('An error occurred during registration.', 'error')

    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.clear() # Clear all session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- Password Reset Routes ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handles the request to reset a password."""
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email address is required.', 'error')
            return redirect(url_for('forgot_password'))

        try:
            parent_user = users_collection.find_one({"email": email.lower(), "role": "parent"})
            if parent_user:
                # Generate password reset token
                s = get_token_serializer()
                # Token expires in 1 hour (3600 seconds)
                token = s.dumps(email.lower(), salt=current_app.config['SECURITY_PASSWORD_SALT'])

                # Create reset link
                reset_url = url_for('reset_password_with_token', token=token, _external=True)

                # Render email body
                html_body = render_template('email/reset_password_email.html', reset_url=reset_url)

                # Send email
                if send_email(email.lower(), "Reset Your Chore Tracker Password", html_body):
                    flash('Password reset instructions have been sent to your email.', 'success')
                else:
                    flash('Failed to send password reset email. Please try again later or contact support.', 'error')
            else:
                # Don't reveal if email exists or not for security
                flash('If an account with that email exists, reset instructions have been sent.', 'info')

        except Exception as e:
            print(f"Forgot password error: {e}")
            flash('An error occurred. Please try again.', 'error')

        return redirect(url_for('login')) # Redirect to login regardless of outcome

    # GET request
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    """Handles password reset using a token."""
    s = get_token_serializer()
    try:
        # Verify token validity and expiration (max_age=3600 seconds)
        email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('Invalid password reset link.', 'error')
        return redirect(url_for('forgot_password'))
    except Exception as e:
        print(f"Token verification error: {e}")
        flash('Invalid password reset link.', 'error')
        return redirect(url_for('forgot_password'))

    # Token is valid, proceed with password reset form
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both password fields are required.', 'error')
            return render_template('reset_password.html', token=token) # Stay on page

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token) # Stay on page

        if len(new_password) < 6:
             flash('Password must be at least 6 characters long.', 'error')
             return render_template('reset_password.html', token=token) # Stay on page

        try:
            # Hash the new password
            hashed_password = generate_password_hash(new_password)
            # Update the user's password in the database
            result = users_collection.update_one(
                {"email": email, "role": "parent"},
                {"$set": {"password_hash": hashed_password}}
            )

            if result.matched_count == 1:
                flash('Your password has been successfully reset! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                 # Should not happen if token was valid, but handle defensively
                 flash('Could not find user account to update password.', 'error')
                 return redirect(url_for('login'))

        except Exception as e:
            print(f"Password reset update error: {e}")
            flash('An error occurred while resetting your password.', 'error')
            return render_template('reset_password.html', token=token) # Stay on page

    # GET request: Show the password reset form
    return render_template('reset_password.html', token=token)


# --- Parent Routes (Modified for Multi-Tenancy) ---

@app.route('/parent_dashboard')
def parent_dashboard():
    """Displays the parent dashboard, showing only their kids and tasks."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Please log in as a parent.', 'warning')
        return redirect(url_for('login'))

    parent_username = session['username']

    try:
        # Get ONLY the kids associated with this parent
        kids = list(users_collection.find({
            "role": "kid",
            "associated_parent_username": parent_username
        }))

        # Fetch tasks created by this parent
        tasks = list(tasks_collection.find({"parent_username": parent_username}).sort("entry_datetime", -1))

        # Calculate summaries ONLY for this parent's kids
        kids_summaries = {}
        for kid in kids:
             kids_summaries[kid['username']] = calculate_summaries(kid['username'])

        return render_template('parent_dashboard.html',
                               parent_username=parent_username,
                               tasks=tasks,
                               kids=kids, # Pass only associated kids
                               kids_summaries=kids_summaries)
    except Exception as e:
        print(f"Error loading parent dashboard: {e}")
        flash('Could not load dashboard data.', 'error')
        # Pass empty lists/dicts to avoid template errors
        return render_template('parent_dashboard.html', parent_username=parent_username, tasks=[], kids=[], kids_summaries={})


@app.route('/add_kid', methods=['POST'])
def add_kid():
    """Adds a new kid user associated with the logged-in parent."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    parent_username = session['username']
    kid_username = request.form.get('kid_username')
    kid_password = request.form.get('kid_password')

    if not kid_username or not kid_password:
        flash('Kid username and password are required.', 'error')
        return redirect(url_for('parent_dashboard'))

    if len(kid_password) < 4: # Simpler password requirement for kids?
         flash('Kid password must be at least 4 characters long.', 'error')
         return redirect(url_for('parent_dashboard'))

    try:
        # Check if username already exists (globally)
        existing_user = users_collection.find_one({"username": kid_username})
        if existing_user:
            flash(f'Username "{kid_username}" is already taken.', 'error')
            return redirect(url_for('parent_dashboard'))

        hashed_password = generate_password_hash(kid_password)
        users_collection.insert_one({
            "username": kid_username,
            "password_hash": hashed_password,
            "role": "kid",
            "associated_parent_username": parent_username # Link kid to parent
        })
        flash(f'Kid account "{kid_username}" created successfully!', 'success')

    except Exception as e:
        print(f"Error adding kid: {e}")
        flash('An error occurred while adding the kid account.', 'error')

    return redirect(url_for('parent_dashboard'))


@app.route('/add_task', methods=['POST'])
def add_task():
    """Adds a task, ensuring kid belongs to the parent."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    parent_username = session['username']
    assigned_kid_username = request.form.get('assigned_kid_username')

    # --- Validation: Ensure selected kid belongs to this parent ---
    kid_user = users_collection.find_one({
        "username": assigned_kid_username,
        "role": "kid",
        "associated_parent_username": parent_username
    })
    if not kid_user:
        flash(f'Invalid selection: Kid "{assigned_kid_username}" is not associated with your account.', 'error')
        return redirect(url_for('parent_dashboard'))
    # --- End Kid Validation ---

    try:
        task_type = request.form.get('task_type')
        description = request.form.get('description')
        monetary_value_str = request.form.get('monetary_value')
        deadline_str = request.form.get('deadline')

        # (Add back other validations: required fields, description length, value, deadline format)
        if not all([task_type, description, monetary_value_str, deadline_str]):
             flash('All task fields are required.', 'error')
             return redirect(url_for('parent_dashboard'))
        # ... other validations ...
        monetary_value = Decimal(monetary_value_str)
        deadline_dt = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)


        new_task = {
            "parent_username": parent_username, # Task creator
            "assigned_kid_username": assigned_kid_username, # Kid assigned
            "description": description,
            "monetary_value": str(monetary_value.quantize(Decimal('0.01'))),
            "type": task_type,
            "entry_datetime": datetime.now(timezone.utc),
            "deadline_datetime": deadline_dt,
            "status": "incomplete",
            "completion_level": 0,
            "completion_datetime": None,
            "calculated_payment": None
        }
        tasks_collection.insert_one(new_task)
        flash(f'{task_type.capitalize()} task added for {assigned_kid_username}!', 'success')

    except Exception as e:
        print(f"Error adding task: {e}")
        flash('An error occurred while adding the task.', 'error')

    return redirect(url_for('parent_dashboard'))


@app.route('/mark_complete/<task_id>', methods=['POST'])
def mark_complete(task_id):
    """Marks a task complete (Parent must have created it)."""
    if 'username' not in session or session.get('role') != 'parent':
        return redirect(url_for('login'))

    parent_username = session['username']
    # Find task ensuring it was created by this parent
    task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})

    if not task:
        flash('Task not found or you do not have permission.', 'error')
        return redirect(url_for('parent_dashboard'))

    # (Rest of the logic remains largely the same as before)
    try:
        level_str = request.form.get('completion_level')
        completion_level = int(level_str)
        if completion_level not in [25, 50, 100]: raise ValueError("Invalid level")

        if task['status'] == 'complete':
             flash('Task is already complete.', 'info')
             return redirect(url_for('parent_dashboard'))

        monetary_value = Decimal(task['monetary_value'])
        calculated_payment = (monetary_value * Decimal(completion_level / 100.0))
        if task['type'] == 'punishment': calculated_payment = -calculated_payment

        tasks_collection.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {
                "status": "complete", "completion_level": completion_level,
                "completion_datetime": datetime.now(timezone.utc),
                "calculated_payment": str(calculated_payment.quantize(Decimal('0.01')))
            }}
        )
        flash('Task marked as complete!', 'success')
    except Exception as e:
        print(f"Error marking complete: {e}")
        flash('Error marking task complete.', 'error')

    return redirect(url_for('parent_dashboard'))


@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id):
    """Deletes an incomplete task (Parent must have created it)."""
    if 'username' not in session or session.get('role') != 'parent':
        return redirect(url_for('login'))

    parent_username = session['username']
    # Find task ensuring it was created by this parent
    task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})

    if not task:
        flash('Task not found or you do not have permission.', 'error')
        return redirect(url_for('parent_dashboard'))

    if task['status'] == 'complete':
        flash('Cannot delete completed tasks.', 'error')
        return redirect(url_for('parent_dashboard'))

    try:
        tasks_collection.delete_one({"_id": ObjectId(task_id)})
        flash('Task deleted.', 'success')
    except Exception as e:
        print(f"Error deleting task: {e}")
        flash('Error deleting task.', 'error')

    return redirect(url_for('parent_dashboard'))


@app.route('/deduct_money', methods=['POST'])
def deduct_money():
    """Adds a deduction, ensuring kid belongs to the parent."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    parent_username = session['username']
    kid_username = request.form.get('deduct_kid_username')

    # --- Validation: Ensure selected kid belongs to this parent ---
    kid_user = users_collection.find_one({
        "username": kid_username,
        "role": "kid",
        "associated_parent_username": parent_username
    })
    if not kid_user:
        flash(f'Invalid selection: Kid "{kid_username}" is not associated with your account.', 'error')
        return redirect(url_for('parent_dashboard'))
    # --- End Kid Validation ---

    try:
        amount_str = request.form.get('deduct_amount')
        category = request.form.get('deduct_category')
        description = request.form.get('deduct_description', '')

        # (Add back other validations: required fields, category, amount format)
        if not all([amount_str, category]):
             flash('Amount and category required.', 'error')
             return redirect(url_for('parent_dashboard'))
        # ... other validations ...
        amount = Decimal(amount_str)
        if amount <= Decimal('0.00'): raise ValueError("Amount must be positive")


        new_deduction = {
            "parent_username": parent_username, # Parent initiating
            "kid_username": kid_username,       # Kid affected
            "amount": str(amount.quantize(Decimal('0.01'))),
            "category": category,
            "deduction_datetime": datetime.now(timezone.utc),
            "description": description
        }
        deductions_collection.insert_one(new_deduction)
        flash(f'Deduction recorded for {kid_username}.', 'success')

    except Exception as e:
        print(f"Error deducting money: {e}")
        flash('An error occurred while recording the deduction.', 'error')

    return redirect(url_for('parent_dashboard'))


# --- Kid Routes (Largely Unchanged) ---

@app.route('/kid_dashboard')
def kid_dashboard():
    """Displays the kid dashboard."""
    if 'username' not in session or session.get('role') != 'kid':
        flash('Please log in as a kid.', 'warning')
        return redirect(url_for('login'))

    kid_username = session['username']

    # Optional: Verify kid account is still valid and associated
    kid_user = users_collection.find_one({"username": kid_username, "role": "kid"})
    if not kid_user or not kid_user.get('associated_parent_username'):
         flash('Your account is not properly configured. Please contact your parent.', 'error')
         session.clear()
         return redirect(url_for('login'))

    try:
        summaries = calculate_summaries(kid_username)
        # Fetch tasks assigned TO this kid (regardless of who created them)
        tasks = list(tasks_collection.find({"assigned_kid_username": kid_username}).sort("entry_datetime", -1))

        return render_template('kid_dashboard.html',
                               kid_username=kid_username,
                               summaries=summaries,
                               tasks=tasks)
    except Exception as e:
        print(f"Error loading kid dashboard: {e}")
        flash('Could not load dashboard data.', 'error')
        return render_template('kid_dashboard.html', kid_username=kid_username, summaries=calculate_summaries(kid_username), tasks=[])


# --- Utility Filters (Unchanged) ---
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M %Z'):
    if value is None: return ""
    if isinstance(value, datetime):
        if value.tzinfo is None: value = value.replace(tzinfo=timezone.utc)
        return value.strftime(format)
    return value

@app.template_filter('currencyformat')
def currencyformat(value):
    try:
        dec_value = Decimal(str(value)) if not isinstance(value, Decimal) else value
        return "${:,.2f}".format(dec_value)
    except:
        return "$0.00"

# --- Run Application ---
if __name__ == '__main__':
    # Remember to set debug=False for production
    app.run(host='0.0.0.0', port=5000, debug=True)
