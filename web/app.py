from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Hardcoded credentials
USER_CREDENTIALS = {
    "username": "admin",
    "password": "password123"
}

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/submit_command', methods=['POST'])
def submit_command():
    command = request.form.get('command')
    if command:
        command_queue.append(command)
        flash(f'Command "{command}" added to queue!', 'info')
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

