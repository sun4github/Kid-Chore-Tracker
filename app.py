import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP # Use Decimal for currency
from dotenv import load_dotenv # To load environment variables
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
    # Add index for tasks for faster lookups
    tasks_collection.create_index([("assigned_kid_username", 1), ("status", 1)])
    tasks_collection.create_index([("parent_username", 1), ("entry_datetime", -1)])
    # Add index for deductions
    deductions_collection.create_index([("kid_username", 1), ("category", 1)])

    client.admin.command('ping')
    print("Successfully connected to MongoDB.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    exit()

# --- Email Configuration (Flask-Mail) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)

# --- Helper Functions ---

def get_token_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def send_email(to_email, subject, template):
    try:
        msg = Message(subject, recipients=[to_email], html=template, sender=current_app.config['MAIL_DEFAULT_SENDER'])
        mail.send(msg)
        print(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
        return False

def calculate_summaries(kid_username):
    """Calculates financial summaries for a given kid."""
    total_earned = Decimal('0.00')
    # MODIFIED: total_punishment now comes from deductions
    total_punishment = Decimal('0.00')
    total_spent = Decimal('0.00')
    total_invested = Decimal('0.00')
    two_places = Decimal('0.01')

    try:
        # Calculate earnings from completed tasks
        completed_tasks = tasks_collection.find({
            "assigned_kid_username": kid_username,
            "status": "complete"
        })
        for task in completed_tasks:
            payment_str = task.get('calculated_payment', '0')
            try:
                payment = Decimal(str(payment_str))
                if payment > Decimal('0.00'): # Only sum positive payments as earnings
                    total_earned += payment
            except:
                pass # Ignore tasks with invalid payment

        # Calculate deductions (spending, investment, and NEW: penalty)
        kid_deductions = deductions_collection.find({ "kid_username": kid_username })
        for deduction in kid_deductions:
            amount_str = deduction.get('amount', '0')
            try:
                amount = Decimal(str(amount_str))
            except:
                amount = Decimal('0.00')

            category = deduction.get('category')
            if category == 'spending':
                total_spent += amount
            elif category == 'investment':
                total_invested += amount
            elif category == 'penalty': # NEW: Sum penalties for total punishment
                total_punishment += amount

        # Calculate total balance
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
        return {'earned': Decimal('0.00'), 'punishment': Decimal('0.00'), 'spent': Decimal('0.00'), 'invested': Decimal('0.00'), 'balance': Decimal('0.00')}

# --- Routes ---

# --- Login/Register/Logout/Password Reset Routes (Largely Unchanged) ---
@app.route('/')
def index():
    if 'username' in session:
        if session.get('role') == 'parent': return redirect(url_for('parent_dashboard'))
        elif session.get('role') == 'kid': return redirect(url_for('kid_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('login'))
        try:
            user = users_collection.find_one({"username": username})
            if user and check_password_hash(user['password_hash'], password):
                session['username'] = user['username']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                if user['role'] == 'parent': return redirect(url_for('parent_dashboard'))
                else:
                    if not user.get('associated_parent_username'):
                         flash('Kid account not fully set up.', 'warning'); session.clear(); return redirect(url_for('login'))
                    return redirect(url_for('kid_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
        except Exception as e:
            print(f"Login error: {e}"); flash('An error occurred during login.', 'error')
        return redirect(url_for('login'))
    if 'username' in session: return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register_parent', methods=['POST'])
def register_parent():
    username = request.form.get('reg_username')
    password = request.form.get('reg_password')
    email = request.form.get('reg_email')
    if not all([username, password, email]):
        flash('Username, password, and email are required.', 'error'); return redirect(url_for('login'))
    if '@' not in email or '.' not in email.split('@')[-1]:
         flash('Invalid email address format.', 'error'); return redirect(url_for('login'))
    try:
        if users_collection.find_one({"username": username}):
            flash('Username already exists.', 'error'); return redirect(url_for('login'))
        if users_collection.find_one({"email": email.lower(), "role": "parent"}):
            flash('Email already registered.', 'error'); return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password_hash": hashed_password, "role": "parent", "email": email.lower()})
        flash('Parent registration successful! Please log in.', 'success')
    except Exception as e:
        print(f"Parent registration error: {e}"); flash('An error occurred during registration.', 'error')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear(); flash('You have been logged out.', 'info'); return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email: flash('Email address is required.', 'error'); return redirect(url_for('forgot_password'))
        try:
            parent_user = users_collection.find_one({"email": email.lower(), "role": "parent"})
            if parent_user:
                s = get_token_serializer()
                token = s.dumps(email.lower(), salt=current_app.config['SECURITY_PASSWORD_SALT'])
                reset_url = url_for('reset_password_with_token', token=token, _external=True)
                html_body = render_template('email/reset_password_email.html', reset_url=reset_url)
                if send_email(email.lower(), "Reset Your Chore Tracker Password", html_body):
                    flash('Password reset instructions sent.', 'success')
                else:
                    flash('Failed to send password reset email.', 'error')
            else:
                flash('If account exists, reset instructions sent.', 'info') # Security: Don't confirm email existence
        except Exception as e:
            print(f"Forgot password error: {e}"); flash('An error occurred.', 'error')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    s = get_token_serializer()
    try: email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired: flash('Reset link expired.', 'error'); return redirect(url_for('forgot_password'))
    except BadTimeSignature: flash('Invalid reset link.', 'error'); return redirect(url_for('forgot_password'))
    except Exception as e: print(f"Token verification error: {e}"); flash('Invalid reset link.', 'error'); return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not new_password or not confirm_password: flash('Passwords required.', 'error'); return render_template('reset_password.html', token=token)
        if new_password != confirm_password: flash('Passwords do not match.', 'error'); return render_template('reset_password.html', token=token)
        if len(new_password) < 6: flash('Password too short (min 6 chars).', 'error'); return render_template('reset_password.html', token=token)
        try:
            hashed_password = generate_password_hash(new_password)
            result = users_collection.update_one({"email": email, "role": "parent"}, {"$set": {"password_hash": hashed_password}})
            if result.matched_count == 1: flash('Password reset successful! Please log in.', 'success'); return redirect(url_for('login'))
            else: flash('Could not find user account.', 'error'); return redirect(url_for('login'))
        except Exception as e: print(f"Password reset update error: {e}"); flash('Error resetting password.', 'error'); return render_template('reset_password.html', token=token)
    return render_template('reset_password.html', token=token)

# --- Parent Routes (Modified Task Logic) ---

@app.route('/parent_dashboard')
def parent_dashboard():
    if 'username' not in session or session.get('role') != 'parent':
        flash('Please log in as a parent.', 'warning'); return redirect(url_for('login'))
    parent_username = session['username']
    try:
        kids = list(users_collection.find({"role": "kid", "associated_parent_username": parent_username}))
        # Fetch tasks created by this parent
        tasks = list(tasks_collection.find({"parent_username": parent_username}).sort("entry_datetime", -1))
        kids_summaries = {kid['username']: calculate_summaries(kid['username']) for kid in kids}
        return render_template('parent_dashboard.html', parent_username=parent_username, tasks=tasks, kids=kids, kids_summaries=kids_summaries)
    except Exception as e:
        print(f"Error loading parent dashboard: {e}"); flash('Could not load dashboard data.', 'error')
        return render_template('parent_dashboard.html', parent_username=parent_username, tasks=[], kids=[], kids_summaries={})

@app.route('/add_kid', methods=['POST'])
def add_kid():
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']
    kid_username = request.form.get('kid_username')
    kid_password = request.form.get('kid_password')
    if not kid_username or not kid_password: flash('Kid username and password required.', 'error'); return redirect(url_for('parent_dashboard'))
    if len(kid_password) < 4: flash('Kid password too short (min 4 chars).', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        if users_collection.find_one({"username": kid_username}):
            flash(f'Username "{kid_username}" is already taken.', 'error'); return redirect(url_for('parent_dashboard'))
        hashed_password = generate_password_hash(kid_password)
        users_collection.insert_one({"username": kid_username, "password_hash": hashed_password, "role": "kid", "associated_parent_username": parent_username})
        flash(f'Kid account "{kid_username}" created!', 'success')
    except Exception as e:
        print(f"Error adding kid: {e}"); flash('Error adding kid account.', 'error')
    return redirect(url_for('parent_dashboard'))

@app.route('/add_task', methods=['POST'])
def add_task():
    """Adds a task with optional penalty."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error'); return redirect(url_for('login'))

    parent_username = session['username']
    assigned_kid_username = request.form.get('assigned_kid_username')
    description = request.form.get('description')
    monetary_value_str = request.form.get('monetary_value')
    deadline_str = request.form.get('deadline')
    # NEW: Get penalty fields
    has_punishment = request.form.get('has_punishment') == 'true' # Checkbox value is 'true' if checked
    punishment_value_str = request.form.get('punishment_value')

    # --- Validation ---
    if not all([assigned_kid_username, description, monetary_value_str, deadline_str]):
        flash('Kid, description, reward value, and deadline required.', 'error'); return redirect(url_for('parent_dashboard'))

    kid_user = users_collection.find_one({"username": assigned_kid_username, "role": "kid", "associated_parent_username": parent_username})
    if not kid_user:
        flash(f'Invalid kid selection.', 'error'); return redirect(url_for('parent_dashboard'))

    if len(description) > 1000: flash('Description too long.', 'error'); return redirect(url_for('parent_dashboard'))

    try: # Validate reward value
        monetary_value = Decimal(monetary_value_str)
        if monetary_value < Decimal('0.00'): raise ValueError("Value cannot be negative")
    except Exception: flash('Invalid reward value.', 'error'); return redirect(url_for('parent_dashboard'))

    try: # Validate deadline
        deadline_dt = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
    except ValueError: flash('Invalid deadline format.', 'error'); return redirect(url_for('parent_dashboard'))

    punishment_value = None
    if has_punishment:
        if not punishment_value_str:
             flash('Punishment amount is required if penalty checkbox is checked.', 'error'); return redirect(url_for('parent_dashboard'))
        try: # Validate punishment value
            punishment_value_decimal = Decimal(punishment_value_str)
            if punishment_value_decimal < Decimal('0.00'): raise ValueError("Value cannot be negative")
            punishment_value = str(punishment_value_decimal.quantize(Decimal('0.01'))) # Store as string
        except Exception: flash('Invalid punishment value.', 'error'); return redirect(url_for('parent_dashboard'))
    # --- End Validation ---

    try:
        new_task = {
            "parent_username": parent_username,
            "assigned_kid_username": assigned_kid_username,
            "description": description,
            "monetary_value": str(monetary_value.quantize(Decimal('0.01'))),
            # "type" field removed
            "entry_datetime": datetime.now(timezone.utc),
            "deadline_datetime": deadline_dt,
            "status": "incomplete", # Default status
            "completion_level": 0,
            "completion_datetime": None,
            "calculated_payment": None,
            "has_punishment": has_punishment, # NEW field
            "punishment_value": punishment_value # NEW field (stored as string or null)
        }
        tasks_collection.insert_one(new_task)
        flash(f'Task added for {assigned_kid_username}!', 'success')
    except Exception as e:
        print(f"Error adding task: {e}"); flash('Error adding task.', 'error')

    return redirect(url_for('parent_dashboard'))

@app.route('/mark_complete/<task_id>', methods=['POST'])
def mark_complete(task_id):
    """Marks a task complete (Parent must have created it)."""
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']
    task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))

    # Prevent marking already completed/failed tasks as complete again
    if task['status'] in ['complete', 'failed']:
         flash(f'Task is already marked as {task["status"]}.', 'info'); return redirect(url_for('parent_dashboard'))

    try:
        level_str = request.form.get('completion_level')
        completion_level = int(level_str)
        if completion_level not in [25, 50, 100]: raise ValueError("Invalid level")

        monetary_value = Decimal(task['monetary_value'])
        # REWARDING task logic only now
        calculated_payment = (monetary_value * Decimal(completion_level / 100.0))

        tasks_collection.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {
                "status": "complete", # Set status to complete
                "completion_level": completion_level,
                "completion_datetime": datetime.now(timezone.utc),
                "calculated_payment": str(calculated_payment.quantize(Decimal('0.01')))
            }}
        )
        flash('Task marked as complete!', 'success')
    except Exception as e:
        print(f"Error marking complete: {e}"); flash('Error marking task complete.', 'error')
    return redirect(url_for('parent_dashboard'))

# --- NEW ROUTE ---
@app.route('/mark_failed/<task_id>', methods=['POST'])
def mark_failed(task_id):
    """Marks a task as failed and applies penalty if applicable."""
    if 'username' not in session or session.get('role') != 'parent':
        flash('Unauthorized access.', 'error'); return redirect(url_for('login'))

    parent_username = session['username']
    task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))

    # Prevent marking already completed/failed tasks as failed again
    if task['status'] in ['complete', 'failed']:
         flash(f'Task is already marked as {task["status"]}.', 'info'); return redirect(url_for('parent_dashboard'))

    try:
        update_result = tasks_collection.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": {
                "status": "failed", # Set status to failed
                "completion_level": 0, # Reset completion level
                "completion_datetime": datetime.now(timezone.utc), # Record failure time
                "calculated_payment": "0.00" # No earnings for failed task
            }}
        )

        penalty_applied = False
        # Apply penalty if applicable by creating a deduction record
        if task.get('has_punishment') and task.get('punishment_value'):
            try:
                penalty_amount = Decimal(task['punishment_value'])
                if penalty_amount > Decimal('0.00'):
                    new_deduction = {
                        "parent_username": parent_username,
                        "kid_username": task['assigned_kid_username'],
                        "amount": str(penalty_amount.quantize(Decimal('0.01'))), # Store as string
                        "category": "penalty", # NEW category
                        "deduction_datetime": datetime.now(timezone.utc),
                        "description": f"Penalty for failed task: {task['description'][:50]}..." # Optional description
                    }
                    deductions_collection.insert_one(new_deduction)
                    penalty_applied = True
            except Exception as deduct_e:
                 print(f"Error creating penalty deduction for task {task_id}: {deduct_e}")
                 # Optionally flash a warning that penalty couldn't be applied

        if penalty_applied:
            flash('Task marked as failed and penalty applied!', 'warning')
        else:
            flash('Task marked as failed.', 'info')

    except Exception as e:
        print(f"Error marking task failed: {e}"); flash('Error marking task failed.', 'error')

    return redirect(url_for('parent_dashboard'))


@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id):
    """Deletes an INCOMPLETE task."""
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']
    task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))

    # Allow deletion ONLY if task is incomplete
    if task['status'] != 'incomplete':
        flash(f'Cannot delete a task that is already {task["status"]}.', 'error'); return redirect(url_for('parent_dashboard'))

    try:
        tasks_collection.delete_one({"_id": ObjectId(task_id)})
        flash('Task deleted.', 'success')
    except Exception as e:
        print(f"Error deleting task: {e}"); flash('Error deleting task.', 'error')
    return redirect(url_for('parent_dashboard'))


@app.route('/deduct_money', methods=['POST'])
def deduct_money():
    """Adds a manual deduction (spending or investment)."""
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']
    kid_username = request.form.get('deduct_kid_username')
    kid_user = users_collection.find_one({"username": kid_username, "role": "kid", "associated_parent_username": parent_username})
    if not kid_user: flash(f'Invalid kid selection.', 'error'); return redirect(url_for('parent_dashboard'))

    try:
        amount_str = request.form.get('deduct_amount')
        category = request.form.get('deduct_category') # Should be 'spending' or 'investment'
        description = request.form.get('deduct_description', '')
        if not all([amount_str, category]): flash('Amount and category required.', 'error'); return redirect(url_for('parent_dashboard'))
        if category not in ['spending', 'investment']: flash('Invalid category for manual deduction.', 'error'); return redirect(url_for('parent_dashboard'))
        amount = Decimal(amount_str)
        if amount <= Decimal('0.00'): raise ValueError("Amount must be positive")

        new_deduction = {
            "parent_username": parent_username, "kid_username": kid_username,
            "amount": str(amount.quantize(Decimal('0.01'))), "category": category,
            "deduction_datetime": datetime.now(timezone.utc), "description": description
        }
        deductions_collection.insert_one(new_deduction)
        flash(f'Deduction recorded for {kid_username}.', 'success')
    except Exception as e:
        print(f"Error deducting money: {e}"); flash('Error recording deduction.', 'error')
    return redirect(url_for('parent_dashboard'))


# --- Kid Routes ---
@app.route('/kid_dashboard')
def kid_dashboard():
    """Displays the kid dashboard."""
    if 'username' not in session or session.get('role') != 'kid':
        flash('Please log in as a kid.', 'warning'); return redirect(url_for('login'))
    kid_username = session['username']
    kid_user = users_collection.find_one({"username": kid_username, "role": "kid"})
    if not kid_user or not kid_user.get('associated_parent_username'):
         flash('Account not configured.', 'error'); session.clear(); return redirect(url_for('login'))
    try:
        summaries = calculate_summaries(kid_username)
        tasks = list(tasks_collection.find({"assigned_kid_username": kid_username}).sort("entry_datetime", -1))
        return render_template('kid_dashboard.html', kid_username=kid_username, summaries=summaries, tasks=tasks)
    except Exception as e:
        print(f"Error loading kid dashboard: {e}"); flash('Could not load dashboard data.', 'error')
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
    except: return "$0.00"

# --- Run Application ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) # Set debug=False for production
