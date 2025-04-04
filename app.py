import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timezone, timedelta
# Import Decimal exceptions for specific handling if needed, though basic checks often suffice
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from dotenv import load_dotenv # To load environment variables
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature # For password reset tokens
from flask_mail import Mail, Message # For sending emails

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Configuration ---
# ... (Same as v5) ...
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_weak_default_secret_key_change_me')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'another_weak_salt_change_me')

# --- Database Setup (MongoDB) ---
# ... (Same as v5, includes all collections and indexes) ...
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME = 'chore_tracker_db'
try:
    client = MongoClient(MONGO_URI); db = client[DB_NAME]
    users_collection = db.users; tasks_collection = db.tasks; deductions_collection = db.deductions
    spending_requests_collection = db.spending_requests; savings_goals_collection = db.savings_goals
    users_collection.create_index("username", unique=True); users_collection.create_index("email", unique=True, partialFilterExpression={"role": "parent"})
    tasks_collection.create_index([("assigned_kid_username", 1), ("status", 1)]); tasks_collection.create_index([("parent_username", 1), ("entry_datetime", -1)])
    deductions_collection.create_index([("kid_username", 1), ("category", 1)])
    spending_requests_collection.create_index([("kid_username", 1), ("status", 1)]); spending_requests_collection.create_index([("parent_username", 1), ("status", 1)])
    savings_goals_collection.create_index([("kid_username", 1), ("status", 1)])
    client.admin.command('ping'); print("Successfully connected to MongoDB.")
except Exception as e: print(f"Error connecting to MongoDB: {e}"); exit()

# --- Email Configuration (Flask-Mail) ---
# ... (Same as v5) ...
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com'); app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587)); app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'; app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'; app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME'); app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD'); app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
mail = Mail(app)

# --- Helper Functions (Unchanged) ---
def get_token_serializer(): # ... unchanged ...
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
def send_email(to_email, subject, template): # ... unchanged ...
    try: msg = Message(subject, recipients=[to_email], html=template, sender=current_app.config['MAIL_DEFAULT_SENDER']); mail.send(msg); print(f"Email sent successfully to {to_email}"); return True
    except Exception as e: print(f"Error sending email to {to_email}: {e}"); return False
def calculate_summaries(kid_username): # ... unchanged ...
    total_earned=Decimal('0.00'); total_punishment=Decimal('0.00'); total_spent=Decimal('0.00'); total_invested=Decimal('0.00'); two_places=Decimal('0.01')
    try:
        completed_tasks = tasks_collection.find({"assigned_kid_username": kid_username, "status": "complete"})
        for task in completed_tasks:
            payment_str = task.get('calculated_payment', '0'); payment = Decimal('0.00')
            try: payment = Decimal(str(payment_str))
            except: pass
            if payment > Decimal('0.00'): total_earned += payment
        kid_deductions = deductions_collection.find({ "kid_username": kid_username })
        for deduction in kid_deductions:
            amount_str = deduction.get('amount', '0'); amount = Decimal('0.00')
            try: amount = Decimal(str(amount_str))
            except: pass
            category = deduction.get('category')
            if category == 'spending': total_spent += amount
            elif category == 'investment': total_invested += amount
            elif category == 'penalty': total_punishment += amount
        total_balance = total_earned - (total_spent + total_invested + total_punishment)
        return {'earned': total_earned.quantize(two_places, rounding=ROUND_HALF_UP), 'punishment': total_punishment.quantize(two_places, rounding=ROUND_HALF_UP), 'spent': total_spent.quantize(two_places, rounding=ROUND_HALF_UP), 'invested': total_invested.quantize(two_places, rounding=ROUND_HALF_UP), 'balance': total_balance.quantize(two_places, rounding=ROUND_HALF_UP)}
    except Exception as e: print(f"Error calculating summaries for {kid_username}: {e}"); return {'earned': Decimal('0.00'), 'punishment': Decimal('0.00'), 'spent': Decimal('0.00'), 'invested': Decimal('0.00'), 'balance': Decimal('0.00')}

# --- Routes ---

# --- Login/Register/Logout/Password Reset Routes (Unchanged from v5) ---
# ... (These routes remain the same as app_v5.py) ...
@app.route('/')
def index(): # ... unchanged ...
    if 'username' in session:
        if session.get('role') == 'parent': return redirect(url_for('parent_dashboard'))
        elif session.get('role') == 'kid': return redirect(url_for('kid_dashboard'))
    return redirect(url_for('login'))
@app.route('/login', methods=['GET', 'POST'])
def login(): # ... unchanged ...
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password')
        if not username or not password: flash('Username and password are required.', 'error'); return redirect(url_for('login'))
        try:
            user = users_collection.find_one({"username": username})
            if user and check_password_hash(user['password_hash'], password):
                session['username'] = user['username']; session['role'] = user['role']; flash('Login successful!', 'success')
                if user['role'] == 'parent': return redirect(url_for('parent_dashboard'))
                else:
                    if not user.get('associated_parent_username'): flash('Kid account not fully set up.', 'warning'); session.clear(); return redirect(url_for('login'))
                    return redirect(url_for('kid_dashboard'))
            else: flash('Invalid username or password.', 'error')
        except Exception as e: print(f"Login error: {e}"); flash('An error occurred during login.', 'error')
        return redirect(url_for('login'))
    if 'username' in session: return redirect(url_for('index'))
    return render_template('login.html')
@app.route('/register_parent', methods=['POST'])
def register_parent(): # ... unchanged ...
    username = request.form.get('reg_username'); password = request.form.get('reg_password'); email = request.form.get('reg_email')
    if not all([username, password, email]): flash('Username, password, and email are required.', 'error'); return redirect(url_for('login'))
    if '@' not in email or '.' not in email.split('@')[-1]: flash('Invalid email address format.', 'error'); return redirect(url_for('login'))
    try:
        if users_collection.find_one({"username": username}): flash('Username already exists.', 'error'); return redirect(url_for('login'))
        if users_collection.find_one({"email": email.lower(), "role": "parent"}): flash('Email already registered.', 'error'); return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({"username": username, "password_hash": hashed_password, "role": "parent", "email": email.lower()})
        flash('Parent registration successful! Please log in.', 'success')
    except Exception as e: print(f"Parent registration error: {e}"); flash('An error occurred during registration.', 'error')
    return redirect(url_for('login'))
@app.route('/logout')
def logout(): # ... unchanged ...
    session.clear(); flash('You have been logged out.', 'info'); return redirect(url_for('login'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password(): # ... unchanged ...
    if request.method == 'POST':
        email = request.form.get('email')
        if not email: flash('Email address is required.', 'error'); return redirect(url_for('forgot_password'))
        try:
            parent_user = users_collection.find_one({"email": email.lower(), "role": "parent"})
            if parent_user:
                s = get_token_serializer(); token = s.dumps(email.lower(), salt=current_app.config['SECURITY_PASSWORD_SALT'])
                reset_url = url_for('reset_password_with_token', token=token, _external=True)
                html_body = render_template('email/reset_password_email.html', reset_url=reset_url)
                if send_email(email.lower(), "Reset Your Task Titan Password", html_body): flash('Password reset instructions sent.', 'success')
                else: flash('Failed to send password reset email.', 'error')
            else: flash('If account exists, reset instructions sent.', 'info')
        except Exception as e: print(f"Forgot password error: {e}"); flash('An error occurred.', 'error')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token): # ... unchanged ...
    s = get_token_serializer()
    try: email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired: flash('Reset link expired.', 'error'); return redirect(url_for('forgot_password'))
    except BadTimeSignature: flash('Invalid reset link.', 'error'); return redirect(url_for('forgot_password'))
    except Exception as e: print(f"Token verification error: {e}"); flash('Invalid reset link.', 'error'); return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form.get('new_password'); confirm_password = request.form.get('confirm_password')
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

# --- Parent Routes ---

@app.route('/parent_dashboard')
def parent_dashboard(): # ... unchanged from v5 ...
    if 'username' not in session or session.get('role') != 'parent': flash('Please log in as a parent.', 'warning'); return redirect(url_for('login'))
    parent_username = session['username']
    try:
        kids = list(users_collection.find({"role": "kid", "associated_parent_username": parent_username}))
        tasks = list(tasks_collection.find({"parent_username": parent_username}).sort("entry_datetime", -1))
        kids_summaries = {kid['username']: calculate_summaries(kid['username']) for kid in kids}
        kid_usernames = [k['username'] for k in kids]
        pending_requests = []
        if kid_usernames: pending_requests = list(spending_requests_collection.find({"kid_username": {"$in": kid_usernames}, "status": "pending"}).sort("request_datetime", 1))
        return render_template('parent_dashboard.html', parent_username=parent_username, tasks=tasks, kids=kids, kids_summaries=kids_summaries, pending_requests=pending_requests)
    except Exception as e: print(f"Error loading parent dashboard: {e}"); flash('Could not load dashboard data.', 'error'); return render_template('parent_dashboard.html', parent_username=parent_username, tasks=[], kids=[], kids_summaries={}, pending_requests=[])

@app.route('/parent/decide_request/<request_id>', methods=['POST'])
def decide_request(request_id): # ... unchanged from v5 ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']; decision = request.form.get('decision')
    if decision not in ['approve', 'deny']: flash('Invalid decision.', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        spending_request = spending_requests_collection.find_one({"_id": ObjectId(request_id)})
        if not spending_request: flash('Spending request not found.', 'error'); return redirect(url_for('parent_dashboard'))
        kid_username = spending_request.get('kid_username')
        kid_user = users_collection.find_one({"username": kid_username, "associated_parent_username": parent_username})
        if not kid_user or spending_request.get('status') != 'pending': flash('Cannot process this request.', 'error'); return redirect(url_for('parent_dashboard'))
        new_status = 'approved' if decision == 'approve' else 'denied'
        update_data = {"status": new_status, "decision_datetime": datetime.now(timezone.utc)}
        if decision == 'approve':
            summaries = calculate_summaries(kid_username); request_amount = Decimal(spending_request['amount'])
            if summaries['balance'] < request_amount:
                flash(f'Insufficient balance ({summaries["balance"] | currencyformat}) to approve request for {request_amount | currencyformat}. Denied.', 'error')
                update_data['status'] = 'denied'
                spending_requests_collection.update_one({"_id": ObjectId(request_id)}, {"$set": update_data})
            else:
                spending_requests_collection.update_one({"_id": ObjectId(request_id)}, {"$set": update_data})
                new_deduction = {"parent_username": parent_username, "kid_username": kid_username, "amount": spending_request['amount'], "category": "spending", "deduction_datetime": datetime.now(timezone.utc), "description": f"Approved spending request: {spending_request.get('reason', 'No reason given')[:50]}"}
                deductions_collection.insert_one(new_deduction); flash(f'Spending request for {kid_username} approved!', 'success')
        else: # Deny
            spending_requests_collection.update_one({"_id": ObjectId(request_id)}, {"$set": update_data})
            flash(f'Spending request for {kid_username} denied.', 'info')
    except Exception as e: print(f"Error deciding request {request_id}: {e}"); flash('An error occurred processing the request.', 'error')
    return redirect(url_for('parent_dashboard'))

# --- Other Parent Routes (Unchanged from v4) ---
@app.route('/add_kid', methods=['POST'])
def add_kid(): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']; kid_username = request.form.get('kid_username'); kid_password = request.form.get('kid_password')
    if not kid_username or not kid_password: flash('Kid username and password required.', 'error'); return redirect(url_for('parent_dashboard'))
    if len(kid_password) < 4: flash('Kid password too short (min 4 chars).', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        if users_collection.find_one({"username": kid_username}): flash(f'Username "{kid_username}" is already taken.', 'error'); return redirect(url_for('parent_dashboard'))
        hashed_password = generate_password_hash(kid_password)
        users_collection.insert_one({"username": kid_username, "password_hash": hashed_password, "role": "kid", "associated_parent_username": parent_username})
        flash(f'Kid account "{kid_username}" created!', 'success')
    except Exception as e: print(f"Error adding kid: {e}"); flash('Error adding kid account.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/parent/reset_kid_password/<kid_username>', methods=['POST'])
def reset_kid_password(kid_username): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']; new_password = request.form.get(f'new_password_{kid_username}'); confirm_password = request.form.get(f'confirm_password_{kid_username}')
    if not new_password or not confirm_password: flash('Both new password fields are required.', 'error'); return redirect(url_for('parent_dashboard'))
    if new_password != confirm_password: flash('Passwords do not match.', 'error'); return redirect(url_for('parent_dashboard'))
    if len(new_password) < 4: flash('Kid password must be at least 4 characters long.', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        kid_user = users_collection.find_one({"username": kid_username, "role": "kid", "associated_parent_username": parent_username})
        if not kid_user: flash('Kid user not found or not associated.', 'error'); return redirect(url_for('parent_dashboard'))
        hashed_password = generate_password_hash(new_password)
        result = users_collection.update_one({"_id": kid_user['_id']}, {"$set": {"password_hash": hashed_password}})
        if result.modified_count == 1: flash(f'Password for {kid_username} has been reset.', 'success')
        else: flash(f'Failed to reset password for {kid_username}.', 'error')
    except Exception as e: print(f"Error resetting kid password for {kid_username}: {e}"); flash('An error occurred.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/add_task', methods=['POST'])
def add_task(): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']; assigned_kid_username = request.form.get('assigned_kid_username'); description = request.form.get('description'); monetary_value_str = request.form.get('monetary_value'); deadline_str = request.form.get('deadline'); has_punishment = request.form.get('has_punishment') == 'true'; punishment_value_str = request.form.get('punishment_value')
    if not all([assigned_kid_username, description, monetary_value_str, deadline_str]): flash('Kid, description, reward value, and deadline required.', 'error'); return redirect(url_for('parent_dashboard'))
    kid_user = users_collection.find_one({"username": assigned_kid_username, "role": "kid", "associated_parent_username": parent_username})
    if not kid_user: flash(f'Invalid kid selection.', 'error'); return redirect(url_for('parent_dashboard'))
    if len(description) > 1000: flash('Description too long.', 'error'); return redirect(url_for('parent_dashboard'))
    try: monetary_value = Decimal(monetary_value_str); assert monetary_value >= Decimal('0.00')
    except: flash('Invalid reward value.', 'error'); return redirect(url_for('parent_dashboard'))
    try: deadline_dt = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
    except ValueError: flash('Invalid deadline format.', 'error'); return redirect(url_for('parent_dashboard'))
    punishment_value = None
    if has_punishment:
        if not punishment_value_str: flash('Punishment amount required if penalty checked.', 'error'); return redirect(url_for('parent_dashboard'))
        try: punishment_value_decimal = Decimal(punishment_value_str); assert punishment_value_decimal >= Decimal('0.00'); punishment_value = str(punishment_value_decimal.quantize(Decimal('0.01')))
        except: flash('Invalid punishment value.', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        new_task = {"parent_username": parent_username, "assigned_kid_username": assigned_kid_username, "description": description, "monetary_value": str(monetary_value.quantize(Decimal('0.01'))), "entry_datetime": datetime.now(timezone.utc), "deadline_datetime": deadline_dt, "status": "incomplete", "completion_level": 0, "completion_datetime": None, "calculated_payment": None, "has_punishment": has_punishment, "punishment_value": punishment_value}
        tasks_collection.insert_one(new_task); flash(f'Task added for {assigned_kid_username}!', 'success')
    except Exception as e: print(f"Error adding task: {e}"); flash('Error adding task.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/edit_task/<task_id>', methods=['GET', 'POST'])
def edit_task(task_id): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']
    try: task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    except: task = None
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))
    if task['status'] != 'incomplete': flash(f'Cannot edit a task that is already {task["status"]}.', 'error'); return redirect(url_for('parent_dashboard'))
    if request.method == 'POST':
        description = request.form.get('description'); monetary_value_str = request.form.get('monetary_value'); deadline_str = request.form.get('deadline'); has_punishment = request.form.get('has_punishment') == 'true'; punishment_value_str = request.form.get('punishment_value')
        if not all([description, monetary_value_str, deadline_str]): flash('Description, reward value, and deadline required.', 'error'); return render_template('edit_task.html', task=task)
        if len(description) > 1000: flash('Description too long.', 'error'); return render_template('edit_task.html', task=task)
        try: monetary_value = Decimal(monetary_value_str); assert monetary_value >= Decimal('0.00')
        except: flash('Invalid reward value.', 'error'); return render_template('edit_task.html', task=task)
        try: deadline_dt = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
        except ValueError: flash('Invalid deadline format.', 'error'); return render_template('edit_task.html', task=task)
        punishment_value = None
        if has_punishment:
            if not punishment_value_str: flash('Punishment amount required if penalty checked.', 'error'); return render_template('edit_task.html', task=task)
            try: punishment_value_decimal = Decimal(punishment_value_str); assert punishment_value_decimal >= Decimal('0.00'); punishment_value = str(punishment_value_decimal.quantize(Decimal('0.01')))
            except: flash('Invalid punishment value.', 'error'); return render_template('edit_task.html', task=task)
        try:
            update_data = {"description": description, "monetary_value": str(monetary_value.quantize(Decimal('0.01'))), "deadline_datetime": deadline_dt, "has_punishment": has_punishment, "punishment_value": punishment_value}
            tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": update_data}); flash('Task updated successfully!', 'success'); return redirect(url_for('parent_dashboard'))
        except Exception as e: print(f"Error updating task {task_id}: {e}"); flash('An error occurred while updating the task.', 'error'); return render_template('edit_task.html', task=task)
    if task.get('deadline_datetime'):
        deadline_dt = task['deadline_datetime']
        if deadline_dt.tzinfo is None: deadline_dt = deadline_dt.replace(tzinfo=timezone.utc)
        task['deadline_formatted'] = deadline_dt.strftime('%Y-%m-%dT%H:%M')
    return render_template('edit_task.html', task=task)
@app.route('/mark_complete/<task_id>', methods=['POST'])
def mark_complete(task_id): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']; task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))
    if task['status'] in ['complete', 'failed']: flash(f'Task is already marked as {task["status"]}.', 'info'); return redirect(url_for('parent_dashboard'))
    try:
        level_str = request.form.get('completion_level'); completion_level = int(level_str); assert completion_level in [25, 50, 100]
        monetary_value = Decimal(task['monetary_value']); calculated_payment = (monetary_value * Decimal(completion_level / 100.0))
        tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": "complete", "completion_level": completion_level, "completion_datetime": datetime.now(timezone.utc), "calculated_payment": str(calculated_payment.quantize(Decimal('0.01')))}})
        flash('Task marked as complete!', 'success')
    except Exception as e: print(f"Error marking complete: {e}"); flash('Error marking task complete.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/mark_failed/<task_id>', methods=['POST'])
def mark_failed(task_id): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    parent_username = session['username']; task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))
    if task['status'] in ['complete', 'failed']: flash(f'Task is already marked as {task["status"]}.', 'info'); return redirect(url_for('parent_dashboard'))
    try:
        tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": "failed", "completion_level": 0, "completion_datetime": datetime.now(timezone.utc), "calculated_payment": "0.00"}})
        penalty_applied = False
        if task.get('has_punishment') and task.get('punishment_value'):
            try:
                penalty_amount = Decimal(task['punishment_value'])
                if penalty_amount > Decimal('0.00'):
                    new_deduction = {"parent_username": parent_username, "kid_username": task['assigned_kid_username'], "amount": str(penalty_amount.quantize(Decimal('0.01'))), "category": "penalty", "deduction_datetime": datetime.now(timezone.utc), "description": f"Penalty for failed task: {task['description'][:50]}..."}
                    deductions_collection.insert_one(new_deduction); penalty_applied = True
            except Exception as deduct_e: print(f"Error creating penalty deduction for task {task_id}: {deduct_e}")
        if penalty_applied: flash('Task marked as failed and penalty applied!', 'warning')
        else: flash('Task marked as failed.', 'info')
    except Exception as e: print(f"Error marking task failed: {e}"); flash('Error marking task failed.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/delete_task/<task_id>', methods=['POST'])
def delete_task(task_id): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']; task = tasks_collection.find_one({"_id": ObjectId(task_id), "parent_username": parent_username})
    if not task: flash('Task not found or permission denied.', 'error'); return redirect(url_for('parent_dashboard'))
    if task['status'] != 'incomplete': flash(f'Cannot delete a task that is already {task["status"]}.', 'error'); return redirect(url_for('parent_dashboard'))
    try: tasks_collection.delete_one({"_id": ObjectId(task_id)}); flash('Task deleted.', 'success')
    except Exception as e: print(f"Error deleting task: {e}"); flash('Error deleting task.', 'error')
    return redirect(url_for('parent_dashboard'))
@app.route('/deduct_money', methods=['POST'])
def deduct_money(): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'parent': return redirect(url_for('login'))
    parent_username = session['username']; kid_username = request.form.get('deduct_kid_username')
    kid_user = users_collection.find_one({"username": kid_username, "role": "kid", "associated_parent_username": parent_username})
    if not kid_user: flash(f'Invalid kid selection.', 'error'); return redirect(url_for('parent_dashboard'))
    try:
        amount_str = request.form.get('deduct_amount'); category = request.form.get('deduct_category'); description = request.form.get('deduct_description', '')
        if not all([amount_str, category]): flash('Amount and category required.', 'error'); return redirect(url_for('parent_dashboard'))
        if category not in ['spending', 'investment']: flash('Invalid category for manual deduction.', 'error'); return redirect(url_for('parent_dashboard'))
        amount = Decimal(amount_str); assert amount > Decimal('0.00')
        new_deduction = {"parent_username": parent_username, "kid_username": kid_username, "amount": str(amount.quantize(Decimal('0.01'))), "category": category, "deduction_datetime": datetime.now(timezone.utc), "description": description}
        deductions_collection.insert_one(new_deduction); flash(f'Deduction recorded for {kid_username}.', 'success')
    except Exception as e: print(f"Error deducting money: {e}"); flash('Error recording deduction.', 'error')
    return redirect(url_for('parent_dashboard'))

# --- Kid Routes ---

@app.route('/kid_dashboard')
def kid_dashboard():
    """Displays the kid dashboard with tasks, requests, and goals (calculates goal progress)."""
    if 'username' not in session or session.get('role') != 'kid':
        flash('Please log in as a kid.', 'warning'); return redirect(url_for('login'))
    kid_username = session['username']
    kid_user = users_collection.find_one({"username": kid_username, "role": "kid"})
    if not kid_user or not kid_user.get('associated_parent_username'):
         flash('Account not configured.', 'error'); session.clear(); return redirect(url_for('login'))
    try:
        summaries = calculate_summaries(kid_username)
        tasks = list(tasks_collection.find({"assigned_kid_username": kid_username}).sort("entry_datetime", -1))
        spending_requests = list(spending_requests_collection.find({"kid_username": kid_username}).sort("request_datetime", -1))
        savings_goals = list(savings_goals_collection.find({"kid_username": kid_username, "status": "active"}).sort("creation_datetime", 1))

        # --- NEW: Calculate progress for each goal ---
        current_balance = summaries.get('balance', Decimal('0.00'))
        for goal in savings_goals:
            progress = 0
            try:
                target_amount_str = goal.get('target_amount', '0')
                target_decimal = Decimal(target_amount_str)
                if target_decimal > Decimal('0.00'):
                    # Ensure balance is Decimal (should be from calculate_summaries)
                    balance_decimal = current_balance if isinstance(current_balance, Decimal) else Decimal('0.00')
                    # Calculate progress
                    raw_progress = (balance_decimal / target_decimal) * 100
                    progress = int(raw_progress.to_integral_value(rounding=ROUND_HALF_UP)) # Round normally
                    progress = max(0, min(progress, 100)) # Clamp between 0 and 100
            except (InvalidOperation, ValueError, TypeError) as calc_e:
                print(f"Error calculating progress for goal {goal.get('_id')}: {calc_e}")
                progress = 0 # Default to 0 on error
            goal['progress'] = progress # Add progress to the goal dictionary
        # --- END CALCULATION ---

        return render_template('kid_dashboard.html',
                               kid_username=kid_username,
                               summaries=summaries,
                               tasks=tasks,
                               spending_requests=spending_requests,
                               savings_goals=savings_goals) # Pass goals with progress
    except Exception as e:
        print(f"Error loading kid dashboard: {e}"); flash('Could not load dashboard data.', 'error')
        return render_template('kid_dashboard.html', kid_username=kid_username, summaries=calculate_summaries(kid_username), tasks=[], spending_requests=[], savings_goals=[])

# --- Kid Spending Request Route (Unchanged from v5) ---
@app.route('/kid/request_spending', methods=['POST'])
def request_spending(): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'kid': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    kid_username = session['username']; amount_str = request.form.get('request_amount'); reason = request.form.get('request_reason', '')
    if not amount_str: flash('Amount is required.', 'error'); return redirect(url_for('kid_dashboard'))
    try: amount = Decimal(amount_str); assert amount > Decimal('0.00')
    except: flash('Invalid amount entered.', 'error'); return redirect(url_for('kid_dashboard'))
    try:
        kid_user = users_collection.find_one({"username": kid_username}); parent_username = kid_user.get('associated_parent_username')
        if not parent_username: flash('Parent account not linked.', 'error'); return redirect(url_for('kid_dashboard'))
        new_request = {"kid_username": kid_username, "parent_username": parent_username, "amount": str(amount.quantize(Decimal('0.01'))), "reason": reason, "status": "pending", "request_datetime": datetime.now(timezone.utc), "decision_datetime": None}
        spending_requests_collection.insert_one(new_request); flash('Spending request submitted!', 'success')
    except Exception as e: print(f"Error submitting spending request for {kid_username}: {e}"); flash('Error submitting request.', 'error')
    return redirect(url_for('kid_dashboard'))

# --- Kid Savings Goal Routes (Unchanged from v5) ---
@app.route('/kid/add_goal', methods=['POST'])
def add_goal(): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'kid': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    kid_username = session['username']; goal_name = request.form.get('goal_name'); target_amount_str = request.form.get('target_amount')
    if not goal_name or not target_amount_str: flash('Goal name and target amount required.', 'error'); return redirect(url_for('kid_dashboard'))
    try: target_amount = Decimal(target_amount_str); assert target_amount > Decimal('0.00')
    except: flash('Invalid target amount.', 'error'); return redirect(url_for('kid_dashboard'))
    try:
        new_goal = {"kid_username": kid_username, "goal_name": goal_name, "target_amount": str(target_amount.quantize(Decimal('0.01'))), "creation_datetime": datetime.now(timezone.utc), "status": "active"}
        savings_goals_collection.insert_one(new_goal); flash('New savings goal added!', 'success')
    except Exception as e: print(f"Error adding savings goal for {kid_username}: {e}"); flash('Error adding goal.', 'error')
    return redirect(url_for('kid_dashboard'))
@app.route('/kid/delete_goal/<goal_id>', methods=['POST'])
def delete_goal(goal_id): # ... unchanged ...
    if 'username' not in session or session.get('role') != 'kid': flash('Unauthorized access.', 'error'); return redirect(url_for('login'))
    kid_username = session['username']
    try:
        result = savings_goals_collection.delete_one({"_id": ObjectId(goal_id), "kid_username": kid_username})
        if result.deleted_count == 1: flash('Savings goal deleted.', 'success')
        else: flash('Could not find or delete savings goal.', 'error')
    except Exception as e: print(f"Error deleting goal {goal_id} for {kid_username}: {e}"); flash('Error deleting goal.', 'error')
    return redirect(url_for('kid_dashboard'))

# --- Utility Filters (Unchanged) ---
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M %Z'): # ... unchanged ...
    if value is None: return ""
    if isinstance(value, datetime):
        if value.tzinfo is None: value = value.replace(tzinfo=timezone.utc)
        return value.strftime(format)
    return value
@app.template_filter('currencyformat')
def currencyformat(value): # ... unchanged ...
    try: dec_value = Decimal(str(value)) if not isinstance(value, Decimal) else value; return "${:,.2f}".format(dec_value)
    except: return "$0.00"

# --- Run Application ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

