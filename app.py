# ==============================================================================
# FILE: app.py - النسخة المحدثة - إصلاح المرتجعات، العهدة، التقارير، والطباعة
# ==============================================================================
import os
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_file, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import uuid
import hashlib
import platform
import subprocess
try:
    import requests as http_requests
except ImportError:
    http_requests = None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = 'tajer_pos.db'
app.config['BACKUP_DIR'] = 'backups'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['BACKUP_DIR'], exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==============================================================================
# دوال مساعدة
# ==============================================================================

def dict_from_row(row):
    if row is None:
        return None
    return dict(row)

def dicts_from_rows(rows):
    return [dict(row) for row in rows]

# ==============================================================================
# نظام الترخيص وحماية النسخ
# ==============================================================================

LICENSE_SERVER_URL = os.environ.get('LICENSE_SERVER_URL', 'http://127.0.0.1:8082')
LICENSE_SALT = 'TAJER_POS_2025_SECURE_XK9_SALT_BIND'


def get_device_id():
    """توليد معرف فريد للجهاز بناءً على خصائص الأجهزة"""
    components = []
    try:
        node = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((node >> elements) & 0xff)
                        for elements in range(0, 2 * 6, 2)][::-1])
        components.append(mac)
    except Exception:
        pass
    try:
        components.append(platform.node())
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Cryptography', '/v', 'MachineGuid'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'MachineGuid' in line:
                    parts = line.strip().split()
                    if parts:
                        components.append(parts[-1])
                    break
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['wmic', 'diskdrive', 'get', 'SerialNumber'],
            capture_output=True, text=True, timeout=5
        )
        serials = [l.strip() for l in result.stdout.splitlines()
                   if l.strip() and 'SerialNumber' not in l]
        if serials:
            components.append(serials[0])
    except Exception:
        pass
    raw = '|'.join(components) if components else platform.platform()
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _make_license_hash(code, device_id, server_token):
    raw = f"{code}|{device_id}|{server_token}|{LICENSE_SALT}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _call_license_server(code, device_id):
    """الاتصال بخادم الترخيص للتحقق من الرمز"""
    if http_requests is None:
        return {'success': False, 'message': 'مكتبة requests غير متوفرة.'}
    try:
        response = http_requests.post(
            f'{LICENSE_SERVER_URL}/api/verify',
            json={'code': code, 'device_id': device_id},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        return {'success': False, 'message': f'خطأ في الخادم: {response.status_code}'}
    except Exception as ex:
        name = type(ex).__name__
        if 'ConnectionError' in name:
            return {'success': False, 'message': 'تعذّر الاتصال بخادم التراخيص. تحقق من الإنترنت.'}
        if 'Timeout' in name:
            return {'success': False, 'message': 'انتهت مهلة الاتصال بخادم التراخيص.'}
        return {'success': False, 'message': f'خطأ غير متوقع: {str(ex)}'}


def store_license_data(code, device_id, server_token):
    """حفظ بيانات الترخيص في قاعدة البيانات"""
    h = _make_license_hash(code, device_id, server_token)
    db = get_db()
    db.execute('''
        INSERT OR REPLACE INTO license (id, code, device_id, server_token, hash, activated_at)
        VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (code, device_id, server_token, h))
    db.commit()


def verify_license():
    """التحقق من صحة الترخيص المحلي (بدون اتصال بالإنترنت)"""
    try:
        db = get_db()
        lic = db.execute("SELECT * FROM license WHERE id = 1").fetchone()
        if not lic:
            return False
        current_device_id = get_device_id()
        if lic['device_id'] != current_device_id:
            return False
        expected = _make_license_hash(lic['code'], current_device_id, lic['server_token'])
        return secrets.compare_digest(str(lic['hash']), expected)
    except Exception:
        return False


# ==============================================================================
# قاعدة البيانات
# ==============================================================================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT CHECK(role IN ('admin', 'cashier', 'supervisor')) DEFAULT 'cashier',
                is_active INTEGER DEFAULT 1,
                can_manage_products INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS suppliers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                barcode TEXT UNIQUE,
                name TEXT NOT NULL,
                category_id INTEGER,
                unit TEXT DEFAULT 'قطعة',
                cost_price REAL DEFAULT 0,
                sell_price REAL DEFAULT 0,
                expiry_date TEXT DEFAULT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS product_stock (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL UNIQUE,
                quantity REAL DEFAULT 0,
                min_quantity REAL DEFAULT 5,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_number TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                customer_name TEXT DEFAULT 'زبون عام',
                total_amount REAL NOT NULL,
                discount_amount REAL DEFAULT 0,
                net_amount REAL NOT NULL,
                paid_amount REAL NOT NULL,
                change_amount REAL DEFAULT 0,
                payment_method TEXT CHECK(payment_method IN ('cash', 'card', 'transfer')) DEFAULT 'cash',
                status TEXT CHECK(status IN ('completed', 'cancelled')) DEFAULT 'completed',
                has_return INTEGER DEFAULT 0,
                returned_amount REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS invoice_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity REAL NOT NULL,
                unit_price REAL NOT NULL,
                cost_price REAL NOT NULL,
                total_price REAL NOT NULL,
                FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id)
            );

            CREATE TABLE IF NOT EXISTS stock_movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                type TEXT CHECK(type IN ('sale', 'purchase', 'return', 'adjustment')) NOT NULL,
                quantity REAL NOT NULL,
                reference_id INTEGER,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                purchase_number TEXT UNIQUE NOT NULL,
                supplier_id INTEGER,
                user_id INTEGER,
                total_amount REAL NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS purchase_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                purchase_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity REAL NOT NULL,
                cost_price REAL NOT NULL,
                total_price REAL NOT NULL,
                FOREIGN KEY (purchase_id) REFERENCES purchases(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id)
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                store_name TEXT DEFAULT 'منظومة التاجر',
                currency TEXT DEFAULT 'د.ل',
                phone TEXT,
                address TEXT,
                invoice_footer TEXT DEFAULT 'شكراً لزيارتكم!',
                low_stock_alert INTEGER DEFAULT 1,
                require_session_close INTEGER DEFAULT 1,
                auto_close_session INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS cash_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                opening_balance REAL DEFAULT 0,
                closing_balance REAL DEFAULT 0,
                total_sales REAL DEFAULT 0,
                total_cash REAL DEFAULT 0,
                total_card REAL DEFAULT 0,
                total_transfer REAL DEFAULT 0,
                expected_cash REAL DEFAULT 0,
                actual_cash REAL DEFAULT 0,
                difference REAL DEFAULT 0,
                notes TEXT,
                status TEXT CHECK(status IN ('open', 'closed')) DEFAULT 'open',
                opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS cash_movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                type TEXT CHECK(type IN ('deposit', 'withdraw', 'sale', 'return')) NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES cash_sessions(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS returns (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                return_number TEXT UNIQUE NOT NULL,
                invoice_id    INTEGER NOT NULL,
                user_id       INTEGER NOT NULL,
                session_id    INTEGER,
                reason        TEXT,
                total_refund  REAL DEFAULT 0,
                is_partial    INTEGER DEFAULT 0,
                payment_method TEXT DEFAULT 'cash',
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (invoice_id)  REFERENCES invoices(id),
                FOREIGN KEY (user_id)     REFERENCES users(id),
                FOREIGN KEY (session_id)  REFERENCES cash_sessions(id)
            );

            CREATE TABLE IF NOT EXISTS return_items (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                return_id   INTEGER NOT NULL,
                product_id  INTEGER NOT NULL,
                quantity    REAL NOT NULL,
                unit_price  REAL NOT NULL,
                total_price REAL NOT NULL,
                FOREIGN KEY (return_id)  REFERENCES returns(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id)
            );

            CREATE TABLE IF NOT EXISTS license (
                id           INTEGER PRIMARY KEY DEFAULT 1,
                code         TEXT NOT NULL,
                device_id    TEXT NOT NULL,
                server_token TEXT NOT NULL,
                hash         TEXT NOT NULL,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')

        cursor.execute("INSERT OR IGNORE INTO settings (id, store_name) VALUES (1, 'منظومة التاجر')")

        hashed_password = generate_password_hash('admin123')
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, name, role)
            VALUES ('admin', ?, 'مدير النظام', 'admin')
        ''', (hashed_password,))

        db.commit()

        # Migrations inline
        migrations = [
            "ALTER TABLE users ADD COLUMN can_manage_products INTEGER DEFAULT 0",
            "ALTER TABLE products ADD COLUMN expiry_date TEXT DEFAULT NULL",
            "ALTER TABLE invoices ADD COLUMN has_return INTEGER DEFAULT 0",
            "ALTER TABLE invoices ADD COLUMN returned_amount REAL DEFAULT 0",
        ]
        for sql in migrations:
            try:
                cursor.execute(sql)
                db.commit()
            except Exception:
                pass

# ==============================================================================
# ترحيل قاعدة البيانات - يعمل تلقائياً عند كل تشغيل
# ==============================================================================

def run_migrations():
    """تطبيق ترحيل قاعدة البيانات بأمان على قواعد البيانات الموجودة"""
    try:
        with app.app_context():
            db = get_db()
            pending = [
                "ALTER TABLE users ADD COLUMN can_manage_products INTEGER DEFAULT 0",
                "ALTER TABLE products ADD COLUMN expiry_date TEXT DEFAULT NULL",
                "ALTER TABLE invoices ADD COLUMN has_return INTEGER DEFAULT 0",
                "ALTER TABLE invoices ADD COLUMN returned_amount REAL DEFAULT 0",
                """CREATE TABLE IF NOT EXISTS license (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    code TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    server_token TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""",
            ]
            for sql in pending:
                try:
                    db.execute(sql)
                    db.commit()
                except Exception:
                    pass
    except Exception:
        pass

init_db()
run_migrations()

# ==============================================================================
# Decorators
# ==============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'message': 'يجب تسجيل الدخول أولاً'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'message': 'لا تملك الصلاحية الكافية'}), 403
                return render_template('error.html', message='عذراً، لا تملك الصلاحية الكافية للوصول لهذه الصفحة.'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def verify_csrf_token(token):
    return session.get('csrf_token') and secrets.compare_digest(session['csrf_token'], str(token))

def get_setting(key, default=''):
    db = get_db()
    setting = db.execute("SELECT * FROM settings LIMIT 1").fetchone()
    if setting:
        return setting[key] if key in setting.keys() else default
    return default

app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['now'] = datetime.now

# ==============================================================================
# Middleware - التحقق من الجلسة قبل البيع
# ==============================================================================

@app.before_request
def check_activation():
    """التحقق من تفعيل الترخيص قبل كل طلب"""
    exempt_endpoints = {'static', 'activate', 'api_activate'}
    if request.endpoint is None or request.endpoint in exempt_endpoints:
        return
    if not verify_license():
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'message': 'النظام غير مفعّل. يرجى إدخال رمز التفعيل.',
                'require_activation': True
            }), 403
        return redirect(url_for('activate'))


@app.before_request
def check_cash_session():
    if request.endpoint == 'api_checkout' and session.get('user_id'):
        db = get_db()
        settings_row = db.execute("SELECT require_session_close FROM settings LIMIT 1").fetchone()
        if settings_row and settings_row['require_session_close']:
            session_data = db.execute(
                "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
                (session['user_id'],)
            ).fetchone()
            if not session_data:
                return jsonify({
                    'success': False,
                    'message': 'يجب فتح جلسة نقدية (عُهدة) قبل البدء بالبيع. <a href="/cash-session">افتح جلسة الآن</a>',
                    'require_session': True
                }), 400

# ==============================================================================
# المصادقة
# ==============================================================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('pos'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('pos'))

    error = ''
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token', '')
        if not verify_csrf_token(csrf_token):
            error = 'جلسة منتهية، يرجى إعادة تحميل الصفحة والمحاولة مجدداً.'
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            if username and password:
                db = get_db()
                user = db.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1 LIMIT 1",
                    (username,)
                ).fetchone()

                if user and check_password_hash(user['password'], password):
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['name'] = user['name']
                    session['role'] = user['role']
                    session['can_manage_products'] = True if user['role'] == 'admin' else bool(user['can_manage_products'])
                    session['csrf_token'] = secrets.token_hex(32)

                    db.execute(
                        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, 'LOGIN', 'تسجيل دخول')",
                        (user['id'],)
                    )
                    db.commit()
                    return redirect(url_for('pos'))
                else:
                    error = 'اسم المستخدم أو كلمة المرور غير صحيحة.'
            else:
                error = 'يرجى إدخال جميع البيانات المطلوبة.'

    store_name = get_setting('store_name', 'منظومة التاجر')
    return render_template('login.html', error=error, store_name=store_name)

@app.route('/logout')
def logout():
    if session.get('user_id'):
        db = get_db()
        settings_row = db.execute("SELECT auto_close_session FROM settings LIMIT 1").fetchone()
        if settings_row and settings_row['auto_close_session']:
            open_session = db.execute(
                "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
                (session['user_id'],)
            ).fetchone()
            if open_session:
                session.clear()
                return redirect(url_for('cash_session'))

    session.clear()
    return redirect(url_for('login'))

# ==============================================================================
# تفعيل الترخيص
# ==============================================================================

@app.route('/activate', methods=['GET', 'POST'])
def activate():
    """صفحة تفعيل النظام - أول صفحة تظهر قبل تسجيل الدخول"""
    if verify_license():
        return redirect(url_for('login'))

    error = ''
    device_id = get_device_id()
    device_id_short = device_id[:8].upper() + '-' + device_id[8:16].upper()

    if request.method == 'POST':
        code = request.form.get('activation_code', '').strip().upper()
        if not code:
            error = 'يرجى إدخال رمز التفعيل.'
        else:
            result = _call_license_server(code, device_id)
            if result.get('success'):
                store_license_data(code, device_id, result.get('token', secrets.token_hex(16)))
                return redirect(url_for('login'))
            else:
                error = result.get('message', 'رمز التفعيل غير صحيح أو منتهي الصلاحية.')

    return render_template('activate.html', error=error, device_id_short=device_id_short)


@app.route('/api/activate', methods=['POST'])
def api_activate():
    """API endpoint للتفعيل عبر JSON"""
    data = request.get_json() or {}
    code = data.get('code', '').strip().upper()
    if not code:
        return jsonify({'success': False, 'message': 'رمز التفعيل مطلوب'})
    device_id = get_device_id()
    result = _call_license_server(code, device_id)
    if result.get('success'):
        store_license_data(code, device_id, result.get('token', secrets.token_hex(16)))
        return jsonify({'success': True, 'message': 'تم التفعيل بنجاح'})
    return jsonify({'success': False, 'message': result.get('message', 'فشل التفعيل')})


# ==============================================================================
# لوحة التحكم
# ==============================================================================

@app.route('/dashboard')
@role_required(['admin', 'supervisor'])
def dashboard():
    db = get_db()

    today_sales = db.execute('''
        SELECT COALESCE(SUM(net_amount), 0) as total_sales, COUNT(id) as total_invoices
        FROM invoices
        WHERE DATE(created_at) = DATE('now') AND status = 'completed'
    ''').fetchone()

    week_data = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        sales = db.execute('''
            SELECT COALESCE(SUM(net_amount), 0) as total
            FROM invoices
            WHERE DATE(created_at) = ? AND status = 'completed'
        ''', (date,)).fetchone()
        week_data.append({'date': date, 'total': sales['total']})

    # الأكثر مبيعاً - يطرح المرتجعات من الكميات
    top_products = dicts_from_rows(db.execute('''
        SELECT
            p.name,
            (SUM(ii.quantity) - COALESCE(ret.ret_qty, 0))    AS total_qty,
            (SUM(ii.total_price) - COALESCE(ret.ret_amount, 0)) AS total_sales
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        JOIN invoices  i ON ii.invoice_id = i.id
        LEFT JOIN (
            SELECT ri.product_id,
                   SUM(ri.quantity)    AS ret_qty,
                   SUM(ri.total_price) AS ret_amount
            FROM return_items ri
            GROUP BY ri.product_id
        ) ret ON ret.product_id = ii.product_id
        WHERE i.status = 'completed'
        GROUP BY ii.product_id
        HAVING total_qty > 0
        ORDER BY total_qty DESC
        LIMIT 5
    ''').fetchall())

    low_stock = dicts_from_rows(db.execute('''
        SELECT p.*, s.quantity, s.min_quantity
        FROM products p
        JOIN product_stock s ON p.id = s.product_id
        WHERE s.quantity <= s.min_quantity AND p.is_active = 1
        ORDER BY s.quantity ASC
    ''').fetchall())

    recent_sales = dicts_from_rows(db.execute('''
        SELECT i.*, u.name as cashier_name
        FROM invoices i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.id DESC LIMIT 6
    ''').fetchall())

    total_products = db.execute(
        "SELECT COUNT(*) as count FROM products WHERE is_active = 1"
    ).fetchone()['count']

    today_returns = db.execute('''
        SELECT COUNT(id) as return_count,
               COALESCE(SUM(total_refund), 0) as total_refund
        FROM returns
        WHERE DATE(created_at) = DATE('now')
    ''').fetchone()

    return render_template('dashboard.html',
                           today_sales=today_sales,
                           today_returns=dict_from_row(today_returns),
                           week_data=week_data,
                           top_products=top_products,
                           low_stock=low_stock,
                           recent_sales=recent_sales,
                           total_products=total_products)

# ==============================================================================
# API - بيانات بطاقات لوحة التحكم (للنوافذ المنبثقة)
# ==============================================================================

@app.route('/api/dashboard/card-data')
@role_required(['admin', 'supervisor'])
def api_dashboard_card_data():
    card = request.args.get('card', '')
    db = get_db()

    if card == 'sales_today':
        rows = dicts_from_rows(db.execute('''
            SELECT i.id, i.invoice_number, i.customer_name, i.net_amount,
                   i.payment_method, i.created_at, i.status,
                   i.has_return, i.returned_amount,
                   u.name as cashier_name
            FROM invoices i
            JOIN users u ON i.user_id = u.id
            WHERE DATE(i.created_at) = DATE('now') AND i.status = 'completed'
            ORDER BY i.id DESC
        ''').fetchall())
        summary = db.execute('''
            SELECT
                COALESCE(SUM(net_amount), 0) as total,
                COALESCE(SUM(CASE WHEN payment_method='cash' THEN net_amount ELSE 0 END), 0) as cash_total,
                COALESCE(SUM(CASE WHEN payment_method='card' THEN net_amount ELSE 0 END), 0) as card_total,
                COALESCE(SUM(CASE WHEN payment_method='transfer' THEN net_amount ELSE 0 END), 0) as transfer_total,
                COUNT(id) as count
            FROM invoices
            WHERE DATE(created_at) = DATE('now') AND status = 'completed'
        ''').fetchone()
        return jsonify({'success': True, 'rows': rows, 'summary': dict_from_row(summary)})

    elif card == 'returns_today':
        rows = dicts_from_rows(db.execute('''
            SELECT r.return_number, r.total_refund, r.created_at, r.is_partial, r.reason,
                   u.name as cashier_name, i.invoice_number
            FROM returns r
            JOIN users u ON r.user_id = u.id
            JOIN invoices i ON r.invoice_id = i.id
            WHERE DATE(r.created_at) = DATE('now')
            ORDER BY r.id DESC
        ''').fetchall())
        summary = db.execute('''
            SELECT COUNT(id) as count, COALESCE(SUM(total_refund), 0) as total
            FROM returns WHERE DATE(created_at) = DATE('now')
        ''').fetchone()
        return jsonify({'success': True, 'rows': rows, 'summary': dict_from_row(summary)})

    elif card == 'invoices_today':
        rows = dicts_from_rows(db.execute('''
            SELECT i.id, i.invoice_number, i.customer_name, i.net_amount,
                   i.payment_method, i.status, i.has_return, i.returned_amount, i.created_at,
                   u.name as cashier_name
            FROM invoices i
            JOIN users u ON i.user_id = u.id
            WHERE DATE(i.created_at) = DATE('now')
            ORDER BY i.id DESC
        ''').fetchall())
        summary = db.execute('''
            SELECT COUNT(id) as count, COALESCE(SUM(net_amount), 0) as total
            FROM invoices
            WHERE DATE(created_at) = DATE('now') AND status = 'completed'
        ''').fetchone()
        return jsonify({'success': True, 'rows': rows, 'summary': dict_from_row(summary)})

    elif card == 'low_stock':
        rows = dicts_from_rows(db.execute('''
            SELECT p.name, p.barcode, s.quantity, s.min_quantity,
                   c.name as category_name
            FROM products p
            JOIN product_stock s ON p.id = s.product_id
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE s.quantity <= s.min_quantity AND p.is_active = 1
            ORDER BY s.quantity ASC
        ''').fetchall())
        total_products = db.execute(
            "SELECT COUNT(*) as c FROM products WHERE is_active = 1"
        ).fetchone()['c']
        return jsonify({'success': True, 'rows': rows, 'total_products': total_products})

    return jsonify({'success': False, 'message': 'نوع البطاقة غير معروف'})

@app.route('/pos')
@login_required
def pos():
    return render_template('pos.html')

# ==============================================================================
# API - نقطة البيع
# ==============================================================================

@app.route('/api/search_product')
@login_required
def api_search_product():
    barcode = request.args.get('barcode', '').strip()
    db = get_db()

    product = db.execute('''
        SELECT p.*, s.quantity
        FROM products p
        LEFT JOIN product_stock s ON p.id = s.product_id
        WHERE p.barcode = ? AND p.is_active = 1 LIMIT 1
    ''', (barcode,)).fetchone()

    if not product:
        product = db.execute('''
            SELECT p.*, s.quantity
            FROM products p
            LEFT JOIN product_stock s ON p.id = s.product_id
            WHERE p.name LIKE ? AND p.is_active = 1 LIMIT 1
        ''', (f'%{barcode}%',)).fetchone()

    if product:
        return jsonify({'success': True, 'product': dict_from_row(product)})

    return jsonify({'success': False, 'message': 'المنتج غير موجود'})

@app.route('/api/checkout', methods=['POST'])
@login_required
def api_checkout():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة، أعد تحميل الصفحة.'})

    items = data.get('items', [])
    discount = float(data.get('discount', 0))
    paid = float(data.get('paid', 0))
    customer_name = data.get('customer_name', '').strip() or 'زبون عام'
    payment_method = data.get('payment_method', 'cash')

    if not items:
        return jsonify({'success': False, 'message': 'السلة فارغة'})

    db = get_db()

    try:
        clean_items = []
        for item in items:
            product = db.execute(
                "SELECT * FROM products WHERE id = ? AND is_active = 1",
                (int(item.get('product_id', 0)),)
            ).fetchone()

            if not product:
                return jsonify({'success': False, 'message': 'أحد المنتجات غير صالح'})

            qty = float(item.get('quantity', 0))
            if qty <= 0:
                return jsonify({'success': False, 'message': 'الكمية غير صالحة'})

            clean_items.append({
                'product_id': product['id'],
                'price': float(product['sell_price']),
                'quantity': qty
            })

        db.execute("BEGIN TRANSACTION")

        total_amount = sum(item['price'] * item['quantity'] for item in clean_items)
        net_amount = max(0, total_amount - discount)
        change_amount = max(0, paid - net_amount)

        date_str = datetime.now().strftime('%Y%m%d')
        unique_id = secrets.token_hex(2).upper()
        invoice_number = f'INV-{date_str}-{unique_id}'

        cursor = db.execute('''
            INSERT INTO invoices (invoice_number, user_id, customer_name, total_amount,
                                discount_amount, net_amount, paid_amount, change_amount,
                                payment_method, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed')
        ''', (invoice_number, session['user_id'], customer_name, total_amount,
              discount, net_amount, paid, change_amount, payment_method))

        invoice_id = cursor.lastrowid

        for item in clean_items:
            product = db.execute(
                "SELECT cost_price FROM products WHERE id = ?",
                (item['product_id'],)
            ).fetchone()
            cost_price = float(product['cost_price']) if product else 0
            item_total = item['price'] * item['quantity']

            db.execute('''
                INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, cost_price, total_price)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (invoice_id, item['product_id'], item['quantity'], item['price'], cost_price, item_total))

            result = db.execute('''
                UPDATE product_stock
                SET quantity = quantity - ?
                WHERE product_id = ? AND quantity >= ?
            ''', (item['quantity'], item['product_id'], item['quantity']))

            if result.rowcount == 0:
                db.execute("ROLLBACK")
                return jsonify({'success': False, 'message': f"الكمية المتاحة غير كافية للمنتج رقم: {item['product_id']}"})

            db.execute('''
                INSERT INTO stock_movements (product_id, type, quantity, reference_id, notes)
                VALUES (?, 'sale', ?, ?, ?)
            ''', (item['product_id'], -item['quantity'], invoice_id, f"فاتورة مبيعات: {invoice_number}"))

        open_session = db.execute(
            "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
            (session['user_id'],)
        ).fetchone()

        if open_session and payment_method == 'cash':
            db.execute('''
                INSERT INTO cash_movements (session_id, user_id, type, amount, description)
                VALUES (?, ?, 'sale', ?, ?)
            ''', (open_session['id'], session['user_id'], net_amount, f"فاتورة مبيعات: {invoice_number}"))

        db.execute('''
            INSERT INTO activity_logs (user_id, action, details)
            VALUES (?, 'CREATE_INVOICE', ?)
        ''', (session['user_id'], f"إنشاء فاتورة رقم: {invoice_number}"))

        db.commit()

        return jsonify({
            'success': True,
            'invoice_id': invoice_id,
            'invoice_number': invoice_number
        })

    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({'success': False, 'message': str(e)})

# ==============================================================================
# المنتجات
# ==============================================================================

@app.route('/products')
@role_required(['admin', 'supervisor'])
def products():
    db = get_db()
    products_list = dicts_from_rows(db.execute('''
        SELECT p.*, c.name as category_name, s.quantity, s.min_quantity
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        LEFT JOIN product_stock s ON p.id = s.product_id
        WHERE p.is_active = 1
        ORDER BY p.id DESC
    ''').fetchall())

    categories = dicts_from_rows(db.execute("SELECT * FROM categories ORDER BY name ASC").fetchall())

    if session.get('role') == 'admin':
        can_manage = True
    elif session.get('role') == 'supervisor':
        _u = db.execute("SELECT can_manage_products FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        can_manage = bool(_u['can_manage_products']) if _u else False
        session['can_manage_products'] = can_manage
    else:
        can_manage = False

    return render_template('products.html', products=products_list, categories=categories, can_manage_products=can_manage)

@app.route('/api/products', methods=['POST'])
@role_required(['admin', 'supervisor'])
def api_products():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    action = data.get('action', '')
    db = get_db()

    if session.get('role') == 'supervisor':
        _u = db.execute("SELECT can_manage_products FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        _has_perm = bool(_u['can_manage_products']) if _u else False
        session['can_manage_products'] = _has_perm
        if not _has_perm and action in ['add', 'update', 'delete']:
            return jsonify({'success': False, 'message': 'ليس لديك صلاحية إدارة المنتجات. تواصل مع المدير لتفعيل الصلاحية.'})

    try:
        if action == 'add':
            name = data.get('name', '').strip()
            if not name:
                return jsonify({'success': False, 'message': 'اسم المنتج مطلوب'})

            cursor = db.execute('''
                INSERT INTO products (barcode, name, category_id, unit, cost_price, sell_price, expiry_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('barcode') or None,
                name,
                data.get('category_id') or None,
                data.get('unit', 'قطعة'),
                float(data.get('cost_price', 0)),
                float(data.get('sell_price', 0)),
                data.get('expiry_date') or None
            ))

            product_id = cursor.lastrowid

            db.execute('''
                INSERT INTO product_stock (product_id, quantity, min_quantity)
                VALUES (?, ?, ?)
            ''', (product_id, float(data.get('quantity', 0)), float(data.get('min_quantity', 5))))

            db.execute('''
                INSERT INTO activity_logs (user_id, action, details)
                VALUES (?, 'ADD_PRODUCT', ?)
            ''', (session['user_id'], f"أضاف منتج: {name}"))

            db.commit()
            return jsonify({'success': True, 'id': product_id})

        elif action == 'update':
            product_id = int(data.get('id', 0))
            if not product_id:
                return jsonify({'success': False, 'message': 'معرّف غير صالح'})

            name = data.get('name', '').strip()

            db.execute('''
                UPDATE products
                SET barcode=?, name=?, category_id=?, unit=?, cost_price=?, sell_price=?, expiry_date=?, is_active=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            ''', (
                data.get('barcode') or None,
                name,
                data.get('category_id') or None,
                data.get('unit', 'قطعة'),
                float(data.get('cost_price', 0)),
                float(data.get('sell_price', 0)),
                data.get('expiry_date') or None,
                int(data.get('is_active', 1)),
                product_id
            ))

            result = db.execute('''
                UPDATE product_stock
                SET quantity=?, min_quantity=?
                WHERE product_id=?
            ''', (float(data.get('quantity', 0)), float(data.get('min_quantity', 5)), product_id))

            if result.rowcount == 0:
                db.execute('''
                    INSERT INTO product_stock (product_id, quantity, min_quantity)
                    VALUES (?, ?, ?)
                ''', (product_id, float(data.get('quantity', 0)), float(data.get('min_quantity', 5))))

            db.execute('''
                INSERT INTO activity_logs (user_id, action, details)
                VALUES (?, 'UPDATE_PRODUCT', ?)
            ''', (session['user_id'], f"عدّل منتج: {name}"))

            db.commit()
            return jsonify({'success': True})

        elif action == 'delete':
            product_id = int(data.get('id', 0))
            if not product_id:
                return jsonify({'success': False, 'message': 'معرّف غير صالح'})

            in_invoices = db.execute(
                "SELECT COUNT(*) as c FROM invoice_items WHERE product_id = ?", (product_id,)
            ).fetchone()['c']
            in_purchases = db.execute(
                "SELECT COUNT(*) as c FROM purchase_items WHERE product_id = ?", (product_id,)
            ).fetchone()['c']

            if in_invoices > 0 or in_purchases > 0:
                db.execute(
                    "UPDATE products SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (product_id,)
                )
                db.execute('''
                    INSERT INTO activity_logs (user_id, action, details)
                    VALUES (?, 'DEACTIVATE_PRODUCT', ?)
                ''', (session['user_id'], f"تعطيل منتج رقم: {product_id}"))
                db.commit()
                return jsonify({
                    'success': True,
                    'message': 'لا يمكن حذف المنتج نهائياً لأنه مرتبط بفواتير أو مشتريات سابقة. تم تعطيله بدلاً من الحذف.'
                })
            else:
                db.execute("DELETE FROM products WHERE id = ?", (product_id,))
                db.execute('''
                    INSERT INTO activity_logs (user_id, action, details)
                    VALUES (?, 'DELETE_PRODUCT', ?)
                ''', (session['user_id'], f"حذف منتج رقم: {product_id}"))
                db.commit()
                return jsonify({'success': True, 'message': 'تم حذف المنتج بنجاح'})

        else:
            return jsonify({'success': False, 'message': 'إجراء غير معروف'})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)})

# ==============================================================================
# التصنيفات
# ==============================================================================

@app.route('/categories')
@role_required(['admin', 'supervisor'])
def categories():
    db = get_db()
    categories_list = dicts_from_rows(db.execute('''
        SELECT c.*, (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id AND p.is_active = 1) AS products_count
        FROM categories c ORDER BY c.name ASC
    ''').fetchall())
    return render_template('categories.html', categories=categories_list)

@app.route('/api/categories', methods=['POST'])
@role_required(['admin', 'supervisor'])
def api_categories():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    action = data.get('action', '')
    db = get_db()

    try:
        if action == 'add':
            name = data.get('name', '').strip()
            if not name:
                return jsonify({'success': False, 'message': 'الاسم مطلوب'})
            db.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            db.commit()
            return jsonify({'success': True})

        elif action == 'update':
            category_id = int(data.get('id', 0))
            name = data.get('name', '').strip()
            if not category_id or not name:
                return jsonify({'success': False, 'message': 'بيانات ناقصة'})
            db.execute("UPDATE categories SET name = ? WHERE id = ?", (name, category_id))
            db.commit()
            return jsonify({'success': True})

        elif action == 'delete':
            category_id = int(data.get('id', 0))
            db.execute("DELETE FROM categories WHERE id = ?", (category_id,))
            db.commit()
            return jsonify({'success': True})

        else:
            return jsonify({'success': False, 'message': 'إجراء غير معروف'})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': 'لا يمكن حذف تصنيف مرتبط بمنتجات'})

# ==============================================================================
# API - منتجات التصنيف
# ==============================================================================

@app.route('/api/category-products')
@login_required
def api_category_products():
    category_id = request.args.get('id', '')
    if not category_id:
        return jsonify({'success': False, 'message': 'معرّف التصنيف مطلوب'})

    db = get_db()
    products_list = dicts_from_rows(db.execute('''
        SELECT p.id, p.name, p.barcode, p.unit, p.sell_price, p.cost_price,
               s.quantity, s.min_quantity, c.name as category_name
        FROM products p
        LEFT JOIN product_stock s ON p.id = s.product_id
        LEFT JOIN categories c ON p.category_id = c.id
        WHERE p.category_id = ? AND p.is_active = 1
        ORDER BY p.name ASC
    ''', (category_id,)).fetchall())

    category = db.execute("SELECT name FROM categories WHERE id = ?", (category_id,)).fetchone()
    cat_name = category['name'] if category else ''

    return jsonify({'success': True, 'products': products_list, 'category_name': cat_name})

# ==============================================================================
# الموردون
# ==============================================================================

@app.route('/suppliers')
@role_required(['admin', 'supervisor'])
def suppliers():
    db = get_db()
    suppliers_list = dicts_from_rows(db.execute("SELECT * FROM suppliers ORDER BY name ASC").fetchall())
    return render_template('suppliers.html', suppliers=suppliers_list)

@app.route('/api/suppliers', methods=['POST'])
@role_required(['admin', 'supervisor'])
def api_suppliers():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    action = data.get('action', '')
    db = get_db()

    try:
        if action == 'add':
            name = data.get('name', '').strip()
            if not name:
                return jsonify({'success': False, 'message': 'الاسم مطلوب'})
            db.execute('''
                INSERT INTO suppliers (name, phone, email, address)
                VALUES (?, ?, ?, ?)
            ''', (name, data.get('phone', ''), data.get('email', ''), data.get('address', '')))
            db.commit()
            return jsonify({'success': True})

        elif action == 'update':
            supplier_id = int(data.get('id', 0))
            if not supplier_id:
                return jsonify({'success': False, 'message': 'معرّف غير صالح'})
            db.execute('''
                UPDATE suppliers SET name=?, phone=?, email=?, address=? WHERE id=?
            ''', (data.get('name', ''), data.get('phone', ''), data.get('email', ''), data.get('address', ''), supplier_id))
            db.commit()
            return jsonify({'success': True})

        elif action == 'delete':
            supplier_id = int(data.get('id', 0))
            db.execute("DELETE FROM suppliers WHERE id = ?", (supplier_id,))
            db.commit()
            return jsonify({'success': True})

        else:
            return jsonify({'success': False, 'message': 'إجراء غير معروف'})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': 'لا يمكن حذف مورد مرتبط بمشتريات'})

# ==============================================================================
# المشتريات
# ==============================================================================

@app.route('/purchases')
@role_required(['admin', 'supervisor'])
def purchases():
    db = get_db()
    purchases_list = dicts_from_rows(db.execute('''
        SELECT p.*, s.name as supplier_name, u.name as user_name
        FROM purchases p
        LEFT JOIN suppliers s ON p.supplier_id = s.id
        LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC
    ''').fetchall())

    suppliers_list = dicts_from_rows(db.execute("SELECT * FROM suppliers ORDER BY name ASC").fetchall())
    products_list = dicts_from_rows(db.execute(
        "SELECT id, name, cost_price FROM products WHERE is_active = 1 ORDER BY name ASC"
    ).fetchall())

    return render_template('purchases.html',
                           purchases=purchases_list,
                           suppliers=suppliers_list,
                           all_products=products_list)

@app.route('/api/purchases', methods=['POST'])
@role_required(['admin', 'supervisor'])
def api_purchases():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    items = data.get('items', [])
    if not items:
        return jsonify({'success': False, 'message': 'أضف صنفاً واحداً على الأقل'})

    db = get_db()

    try:
        db.execute("BEGIN TRANSACTION")

        total_amount = sum(float(item['quantity']) * float(item['cost_price']) for item in items)

        date_str = datetime.now().strftime('%Y%m%d')
        unique_id = secrets.token_hex(2).upper()
        purchase_number = f'PUR-{date_str}-{unique_id}'

        supplier_id = data.get('supplier_id') or None

        cursor = db.execute('''
            INSERT INTO purchases (purchase_number, supplier_id, user_id, total_amount)
            VALUES (?, ?, ?, ?)
        ''', (purchase_number, supplier_id, session['user_id'], total_amount))

        purchase_id = cursor.lastrowid

        for item in items:
            product_id = int(item['product_id'])
            quantity = float(item['quantity'])
            cost_price = float(item['cost_price'])
            item_total = quantity * cost_price

            db.execute('''
                INSERT INTO purchase_items (purchase_id, product_id, quantity, cost_price, total_price)
                VALUES (?, ?, ?, ?, ?)
            ''', (purchase_id, product_id, quantity, cost_price, item_total))

            db.execute('''
                INSERT INTO product_stock (product_id, quantity) VALUES (?, ?)
                ON CONFLICT(product_id) DO UPDATE SET quantity = quantity + ?
            ''', (product_id, quantity, quantity))

            db.execute("UPDATE products SET cost_price = ? WHERE id = ?", (cost_price, product_id))

            db.execute('''
                INSERT INTO stock_movements (product_id, type, quantity, reference_id, notes)
                VALUES (?, 'purchase', ?, ?, ?)
            ''', (product_id, quantity, purchase_id, f"فاتورة شراء: {purchase_number}"))

        db.execute('''
            INSERT INTO activity_logs (user_id, action, details)
            VALUES (?, 'CREATE_PURCHASE', ?)
        ''', (session['user_id'], f"إنشاء فاتورة شراء رقم: {purchase_number}"))

        db.commit()

        return jsonify({
            'success': True,
            'purchase_id': purchase_id,
            'purchase_number': purchase_number
        })

    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({'success': False, 'message': str(e)})

# ==============================================================================
# طباعة فاتورة الشراء
# ==============================================================================

@app.route('/print_purchase/<int:purchase_id>')
@role_required(['admin', 'supervisor'])
def print_purchase(purchase_id):
    db = get_db()

    purchase = db.execute('''
        SELECT p.*, s.name as supplier_name, u.name as user_name
        FROM purchases p
        LEFT JOIN suppliers s ON p.supplier_id = s.id
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (purchase_id,)).fetchone()

    if not purchase:
        return "فاتورة الشراء غير موجودة.", 404

    items = dicts_from_rows(db.execute('''
        SELECT pi.*, pr.name as product_name, pr.barcode
        FROM purchase_items pi
        JOIN products pr ON pi.product_id = pr.id
        WHERE pi.purchase_id = ?
    ''', (purchase_id,)).fetchall())

    settings = dict_from_row(db.execute("SELECT * FROM settings LIMIT 1").fetchone() or {})

    return render_template('print_purchase.html',
                           purchase=dict_from_row(purchase),
                           items=items,
                           settings=settings)

# ==============================================================================
# المستخدمون
# ==============================================================================

@app.route('/users')
@role_required(['admin'])
def users():
    db = get_db()
    users_list = dicts_from_rows(db.execute('''
        SELECT id, username, name, role, is_active, can_manage_products, created_at
        FROM users ORDER BY id DESC
    ''').fetchall())
    return render_template('users.html', users=users_list)

@app.route('/api/users', methods=['POST'])
@role_required(['admin'])
def api_users():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    action = data.get('action', '')
    db = get_db()

    try:
        if action == 'add':
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            name = data.get('name', '').strip()

            if not all([username, password, name]):
                return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة لإنشاء مستخدم جديد'})

            existing = db.execute("SELECT COUNT(*) as count FROM users WHERE username = ?", (username,)).fetchone()
            if existing['count'] > 0:
                return jsonify({'success': False, 'message': 'اسم المستخدم موجود مسبقاً'})

            hashed_password = generate_password_hash(password)
            new_role = data.get('role', 'cashier')
            can_manage_products = 1 if (data.get('can_manage_products') and new_role == 'supervisor') else 0
            db.execute('''
                INSERT INTO users (username, password, name, role, can_manage_products)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_password, name, new_role, can_manage_products))
            db.commit()
            return jsonify({'success': True})

        elif action == 'update':
            user_id = int(data.get('id', 0))
            if not user_id:
                return jsonify({'success': False, 'message': 'معرّف غير صالح'})

            if user_id == session['user_id'] and int(data.get('is_active', 1)) == 0:
                return jsonify({'success': False, 'message': 'لا يمكنك تعطيل حسابك الخاص'})

            password = data.get('password', '').strip()
            upd_role = data.get('role', 'cashier')
            can_manage_products = 1 if (data.get('can_manage_products') and upd_role == 'supervisor') else 0

            if password:
                hashed_password = generate_password_hash(password)
                db.execute('''
                    UPDATE users SET name=?, role=?, is_active=?, password=?, can_manage_products=?
                    WHERE id=?
                ''', (data.get('name', ''), upd_role,
                      int(data.get('is_active', 1)), hashed_password, can_manage_products, user_id))
            else:
                db.execute('''
                    UPDATE users SET name=?, role=?, is_active=?, can_manage_products=?
                    WHERE id=?
                ''', (data.get('name', ''), upd_role,
                      int(data.get('is_active', 1)), can_manage_products, user_id))

            db.commit()
            return jsonify({'success': True})

        elif action == 'delete':
            user_id = int(data.get('id', 0))
            if user_id == session['user_id']:
                return jsonify({'success': False, 'message': 'لا يمكنك حذف حسابك الخاص'})
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            return jsonify({'success': True})

        else:
            return jsonify({'success': False, 'message': 'إجراء غير معروف'})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': 'لا يمكن حذف مستخدم مرتبط بفواتير سابقة'})

# ==============================================================================
# التقارير - مع حساب صحيح للربح يأخذ المرتجعات في الحسبان
# ==============================================================================

@app.route('/reports')
@role_required(['admin', 'supervisor'])
def reports():
    from_date = request.args.get('from', (datetime.now() - timedelta(days=6)).strftime('%Y-%m-%d'))
    to_date = request.args.get('to', datetime.now().strftime('%Y-%m-%d'))

    db = get_db()

    # --- إجمالي المبيعات وعدد الفواتير ---
    summary_row = db.execute('''
        SELECT
            COALESCE(SUM(net_amount), 0)  AS total_sales,
            COUNT(id)                      AS total_invoices
        FROM invoices
        WHERE DATE(created_at) BETWEEN ? AND ? AND status = 'completed'
    ''', (from_date, to_date)).fetchone()

    # --- إجمالي تكلفة المبيعات ---
    total_cost = db.execute('''
        SELECT COALESCE(SUM(ii.cost_price * ii.quantity), 0) AS total_cost
        FROM invoice_items ii
        JOIN invoices i ON ii.invoice_id = i.id
        WHERE i.status = 'completed' AND DATE(i.created_at) BETWEEN ? AND ?
    ''', (from_date, to_date)).fetchone()['total_cost']

    # --- بيانات المرتجعات ---
    returns_data = db.execute('''
        SELECT COUNT(id) AS return_count,
               COALESCE(SUM(total_refund), 0) AS total_refund
        FROM returns
        WHERE DATE(created_at) BETWEEN ? AND ?
    ''', (from_date, to_date)).fetchone()

    total_refund = float(returns_data['total_refund'])

    # --- تكلفة الأصناف المُرجَعة (لطرحها من التكلفة الكلية) ---
    returns_cost = db.execute('''
        SELECT COALESCE(SUM(ri.quantity * ii.cost_price), 0) AS returned_cost
        FROM return_items ri
        JOIN returns r ON ri.return_id = r.id
        JOIN invoice_items ii
          ON ii.invoice_id = r.invoice_id AND ii.product_id = ri.product_id
        WHERE DATE(r.created_at) BETWEEN ? AND ?
    ''', (from_date, to_date)).fetchone()['returned_cost']

    # --- حساب الربح الصحيح ---
    net_cost   = total_cost - returns_cost
    net_sales  = float(summary_row['total_sales']) - total_refund
    profit     = net_sales - net_cost

    summary = {
        'total_sales'   : summary_row['total_sales'],
        'total_invoices': summary_row['total_invoices'],
        'profit'        : profit
    }

    returns_summary = {
        'return_count': returns_data['return_count'],
        'total_refund': total_refund
    }

    # --- الأكثر مبيعاً مع طرح المرتجعات ---
    top_products = dicts_from_rows(db.execute('''
        SELECT
            p.name,
            (SUM(ii.quantity)    - COALESCE(ret.ret_qty, 0))    AS total_qty,
            (SUM(ii.total_price) - COALESCE(ret.ret_amount, 0)) AS total_sales
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        JOIN invoices  i ON ii.invoice_id = i.id
        LEFT JOIN (
            SELECT ri.product_id,
                   SUM(ri.quantity)    AS ret_qty,
                   SUM(ri.total_price) AS ret_amount
            FROM return_items ri
            JOIN returns r ON ri.return_id = r.id
            WHERE DATE(r.created_at) BETWEEN ? AND ?
            GROUP BY ri.product_id
        ) ret ON ret.product_id = ii.product_id
        WHERE i.status = 'completed' AND DATE(i.created_at) BETWEEN ? AND ?
        GROUP BY ii.product_id
        HAVING total_qty > 0
        ORDER BY total_qty DESC
        LIMIT 10
    ''', (from_date, to_date, from_date, to_date)).fetchall())

    # --- أكثر المنتجات المُرجَعة ---
    top_returned = dicts_from_rows(db.execute('''
        SELECT p.name AS product_name,
               SUM(ri.quantity)    AS total_qty,
               SUM(ri.total_price) AS total_refund
        FROM return_items ri
        JOIN products p ON ri.product_id = p.id
        JOIN returns  r ON ri.return_id  = r.id
        WHERE DATE(r.created_at) BETWEEN ? AND ?
        GROUP BY ri.product_id
        ORDER BY total_qty DESC
        LIMIT 10
    ''', (from_date, to_date)).fetchall())

    # --- قائمة عمليات الإرجاع التفصيلية ---
    returns_list = dicts_from_rows(db.execute('''
        SELECT r.*, u.name AS cashier_name, i.invoice_number
        FROM returns r
        JOIN users    u ON r.user_id    = u.id
        JOIN invoices i ON r.invoice_id = i.id
        WHERE DATE(r.created_at) BETWEEN ? AND ?
        ORDER BY r.id DESC
    ''', (from_date, to_date)).fetchall())

    return render_template('reports.html',
                           summary=summary,
                           top_products=top_products,
                           returns_summary=returns_summary,
                           top_returned=top_returned,
                           returns_list=returns_list,
                           from_date=from_date,
                           to_date=to_date)

# ==============================================================================
# المرتجعات - مع حماية العهدة وعدم إلغاء الفاتورة الأصلية
# ==============================================================================

@app.route('/returns', methods=['GET', 'POST'])
@login_required
def returns():
    db = get_db()
    message = ''
    error = ''
    search_invoice = None
    search_number = request.args.get('search', '').strip()

    if search_number:
        invoice = db.execute('''
            SELECT i.*, u.name as cashier_name
            FROM invoices i
            LEFT JOIN users u ON i.user_id = u.id
            WHERE i.invoice_number = ?
        ''', (search_number,)).fetchone()

        if invoice:
            search_invoice = dict_from_row(invoice)
            items = dicts_from_rows(db.execute('''
                SELECT ii.*, p.name as product_name, p.barcode
                FROM invoice_items ii
                JOIN products p ON ii.product_id = p.id
                WHERE ii.invoice_id = ?
            ''', (search_invoice['id'],)).fetchall())

            # نجلب الكميات المُرجَعة مسبقاً لكل منتج
            already_returned = dicts_from_rows(db.execute('''
                SELECT ri.product_id, COALESCE(SUM(ri.quantity), 0) AS returned_qty
                FROM return_items ri
                JOIN returns r ON ri.return_id = r.id
                WHERE r.invoice_id = ?
                GROUP BY ri.product_id
            ''', (search_invoice['id'],)).fetchall())

            returned_map = {row['product_id']: row['returned_qty'] for row in already_returned}

            for item in items:
                item['already_returned'] = returned_map.get(item['product_id'], 0)
                item['remaining_qty'] = item['quantity'] - item['already_returned']

            search_invoice['items'] = items

            # تحقق هل الفاتورة مُرجَعة بالكامل
            if search_invoice.get('has_return'):
                total_remaining = sum(it['remaining_qty'] for it in items)
                search_invoice['fully_returned'] = total_remaining <= 0.001
            else:
                search_invoice['fully_returned'] = False

        else:
            error = "لم يتم العثور على فاتورة بهذا الرقم."

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            if not verify_csrf_token(data.get('csrf_token', '')):
                return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

            # ============================================================
            # التحقق من العهدة: الكاشير يحتاج عهدة مفتوحة، المشرف/المدير لا
            # ============================================================
            user_role = session.get('role')
            if user_role == 'cashier':
                cashier_session_check = db.execute(
                    "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
                    (session['user_id'],)
                ).fetchone()
                if not cashier_session_check:
                    return jsonify({
                        'success': False,
                        'message': 'يجب فتح عهدة أولاً قبل معالجة المرتجعات.',
                        'require_session': True
                    })

            invoice_id = int(data.get('invoice_id', 0))
            reason     = data.get('reason', 'مرتجع زبون')
            ret_items  = data.get('items', [])

            if not ret_items:
                return jsonify({'success': False, 'message': 'لم تختر أي منتج للإرجاع'})

            try:
                db.execute("BEGIN TRANSACTION")

                invoice = db.execute(
                    "SELECT * FROM invoices WHERE id = ? AND status = 'completed'",
                    (invoice_id,)
                ).fetchone()

                if not invoice:
                    raise Exception("الفاتورة غير موجودة أو ملغاة مسبقاً.")

                all_items = db.execute(
                    "SELECT * FROM invoice_items WHERE invoice_id = ?",
                    (invoice_id,)
                ).fetchall()

                orig_map = {row['product_id']: row for row in all_items}
                total_refund = 0.0

                date_str      = datetime.now().strftime('%Y%m%d')
                unique_id     = secrets.token_hex(2).upper()
                return_number = f'RET-{date_str}-{unique_id}'

                open_session = db.execute(
                    "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
                    (session['user_id'],)
                ).fetchone()
                session_id = open_session['id'] if open_session else None

                # إنشاء سجل المرتجع
                ret_cursor = db.execute('''
                    INSERT INTO returns (return_number, invoice_id, user_id, session_id,
                                        reason, total_refund, is_partial, payment_method)
                    VALUES (?, ?, ?, ?, ?, 0, 0, ?)
                ''', (return_number, invoice_id, session['user_id'], session_id,
                      reason, invoice['payment_method']))
                return_id = ret_cursor.lastrowid

                returned_count = 0

                for ri in ret_items:
                    pid     = int(ri['product_id'])
                    ret_qty = float(ri['quantity'])

                    if pid not in orig_map:
                        raise Exception(f"المنتج رقم {pid} ليس ضمن الفاتورة")

                    orig_qty   = float(orig_map[pid]['quantity'])
                    unit_price = float(orig_map[pid]['unit_price'])

                    # نحسب الكمية المُرجَعة مسبقاً (من مرتجعات أخرى لنفس الفاتورة)
                    already_ret = db.execute('''
                        SELECT COALESCE(SUM(ri2.quantity), 0) AS qty
                        FROM return_items ri2
                        JOIN returns r2 ON ri2.return_id = r2.id
                        WHERE r2.invoice_id = ? AND ri2.product_id = ? AND r2.id != ?
                    ''', (invoice_id, pid, return_id)).fetchone()['qty']

                    remaining = orig_qty - float(already_ret)

                    if ret_qty <= 0 or ret_qty > remaining + 0.001:
                        raise Exception(f"الكمية المرتجعة ({ret_qty}) تتجاوز الكمية المتبقية ({remaining:.2f}) للمنتج رقم {pid}")

                    item_refund   = ret_qty * unit_price
                    total_refund += item_refund

                    db.execute('''
                        INSERT INTO return_items (return_id, product_id, quantity, unit_price, total_price)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (return_id, pid, ret_qty, unit_price, item_refund))

                    # إعادة المخزون
                    db.execute('''
                        UPDATE product_stock SET quantity = quantity + ?
                        WHERE product_id = ?
                    ''', (ret_qty, pid))

                    db.execute('''
                        INSERT INTO stock_movements (product_id, type, quantity, reference_id, notes)
                        VALUES (?, 'return', ?, ?, ?)
                    ''', (pid, ret_qty, invoice_id,
                          f"مرتجع فاتورة: {invoice['invoice_number']} | رقم المرتجع: {return_number}"))

                    returned_count += 1

                # =============================================================
                # تحديث الفاتورة الأصلية - لا نلغيها، نضع علامة has_return فقط
                # =============================================================
                all_returned_now = db.execute('''
                    SELECT ri.product_id, COALESCE(SUM(ri.quantity), 0) AS total_returned
                    FROM return_items ri
                    JOIN returns r ON ri.return_id = r.id
                    WHERE r.invoice_id = ?
                    GROUP BY ri.product_id
                ''', (invoice_id,)).fetchall()

                returned_map_now = {row['product_id']: float(row['total_returned']) for row in all_returned_now}

                full_return = all(
                    abs(returned_map_now.get(row['product_id'], 0) - float(row['quantity'])) < 0.001
                    for row in all_items
                )

                db.execute('''
                    UPDATE returns SET total_refund = ?, is_partial = ? WHERE id = ?
                ''', (total_refund, 0 if full_return else 1, return_id))

                # تحديث الفاتورة الأصلية - تبقى completed ونضع has_return فقط
                db.execute('''
                    UPDATE invoices
                    SET has_return = 1,
                        returned_amount = returned_amount + ?
                    WHERE id = ?
                ''', (total_refund, invoice_id))

                # ربط بالجلسة النقدية للمبالغ النقدية فقط
                if session_id and invoice['payment_method'] == 'cash':
                    db.execute('''
                        INSERT INTO cash_movements (session_id, user_id, type, amount, description)
                        VALUES (?, ?, 'return', ?, ?)
                    ''', (session_id, session['user_id'], total_refund,
                          f"مرتجع {return_number} - فاتورة: {invoice['invoice_number']}"))

                db.execute('''
                    INSERT INTO activity_logs (user_id, action, details)
                    VALUES (?, 'RETURN', ?)
                ''', (session['user_id'],
                      f"مرتجع {'كلي' if full_return else 'جزئي'} | {return_number} | فاتورة: {invoice['invoice_number']} | قيمة: {total_refund:.3f}"))

                db.commit()
                return jsonify({
                    'success'      : True,
                    'full_return'  : full_return,
                    'return_id'    : return_id,
                    'return_number': return_number,
                    'total_refund' : total_refund,
                    'message'      : 'تم إرجاع جميع الأصناف وتحديث المخزون.' if full_return
                                     else f'تم إرجاع {returned_count} صنف بنجاح وتحديث المخزون.'
                })

            except Exception as e:
                db.execute("ROLLBACK")
                return jsonify({'success': False, 'message': str(e)})

    return render_template('returns.html',
                           message=message,
                           error=error,
                           search_invoice=search_invoice,
                           search_number=search_number)

# ==============================================================================
# طباعة الفاتورة
# ==============================================================================

@app.route('/print_invoice/<int:invoice_id>')
@login_required
def print_invoice(invoice_id):
    db = get_db()

    invoice = db.execute('''
        SELECT i.*, u.name as cashier_name
        FROM invoices i
        JOIN users u ON i.user_id = u.id
        WHERE i.id = ?
    ''', (invoice_id,)).fetchone()

    if not invoice:
        return "الفاتورة غير موجودة.", 404

    invoice = dict_from_row(invoice)

    items = dicts_from_rows(db.execute('''
        SELECT ii.*, p.name
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        WHERE ii.invoice_id = ?
    ''', (invoice_id,)).fetchall())

    settings = db.execute("SELECT * FROM settings LIMIT 1").fetchone()
    settings = dict_from_row(settings) if settings else {}

    return render_template('print_invoice.html',
                           invoice=invoice,
                           items=items,
                           settings=settings)

# ==============================================================================
# طباعة إيصال المرتجع
# ==============================================================================

@app.route('/print_return/<int:return_id>')
@login_required
def print_return(return_id):
    db = get_db()

    ret = db.execute('''
        SELECT r.*, u.name as cashier_name, i.invoice_number, i.payment_method as inv_payment
        FROM returns r
        JOIN users    u ON r.user_id    = u.id
        JOIN invoices i ON r.invoice_id = i.id
        WHERE r.id = ?
    ''', (return_id,)).fetchone()

    if not ret:
        return "إيصال المرتجع غير موجود.", 404

    ret = dict_from_row(ret)

    items = dicts_from_rows(db.execute('''
        SELECT ri.*, p.name as product_name, p.barcode
        FROM return_items ri
        JOIN products p ON ri.product_id = p.id
        WHERE ri.return_id = ?
    ''', (return_id,)).fetchall())

    settings = dict_from_row(db.execute("SELECT * FROM settings LIMIT 1").fetchone() or {})

    return render_template('print_return.html', ret=ret, items=items, settings=settings)

# ==============================================================================
# الإعدادات
# ==============================================================================

@app.route('/settings', methods=['GET', 'POST'])
@role_required(['admin'])
def settings():
    db = get_db()
    message = None

    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token', '')
        if not verify_csrf_token(csrf_token):
            message = {'type': 'danger', 'text': 'جلسة غير صالحة، أعد المحاولة.'}
        else:
            db.execute('''
                UPDATE settings
                SET store_name=?, currency=?, phone=?, address=?,
                    invoice_footer=?, low_stock_alert=?,
                    require_session_close=?, auto_close_session=?
                WHERE id = 1
            ''', (
                request.form.get('store_name', ''),
                request.form.get('currency', 'د.ل'),
                request.form.get('phone', ''),
                request.form.get('address', ''),
                request.form.get('invoice_footer', ''),
                int(request.form.get('low_stock_alert', 0)),
                int(request.form.get('require_session_close', 1)),
                int(request.form.get('auto_close_session', 0))
            ))
            db.commit()
            message = {'type': 'success', 'text': 'تم حفظ الإعدادات بنجاح'}

    settings_data = db.execute("SELECT * FROM settings LIMIT 1").fetchone()
    settings_data = dict_from_row(settings_data) if settings_data else {}

    return render_template('settings.html', settings=settings_data, message=message)

# ==============================================================================
# النسخ الاحتياطي
# ==============================================================================

@app.route('/backup', methods=['GET', 'POST'])
@role_required(['admin'])
def backup():
    message = ''
    error = ''

    if request.method == 'POST' and request.form.get('action') == 'create_backup':
        csrf_token = request.form.get('csrf_token', '')
        if not verify_csrf_token(csrf_token):
            error = 'جلسة غير صالحة، أعد المحاولة.'
        else:
            try:
                filename = f'backup_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.sql'
                filepath = os.path.join(app.config['BACKUP_DIR'], filename)

                db = get_db()
                with open(filepath, 'w', encoding='utf-8') as f:
                    for line in db.iterdump():
                        f.write(f'{line}\n')

                message = f"تم إنشاء النسخة الاحتياطية بنجاح: {filename}"

            except Exception as e:
                error = f"حدث خطأ: {str(e)}"

    existing_backups = []
    if os.path.exists(app.config['BACKUP_DIR']):
        existing_backups = sorted(
            [f for f in os.listdir(app.config['BACKUP_DIR']) if f.endswith('.sql')],
            reverse=True
        )

    return render_template('backup.html',
                           message=message,
                           error=error,
                           existing_backups=existing_backups)

@app.route('/backup/download/<filename>')
@role_required(['admin'])
def download_backup(filename):
    filepath = os.path.join(app.config['BACKUP_DIR'], filename)
    if os.path.exists(filepath) and filename.startswith('backup_') and filename.endswith('.sql'):
        return send_file(filepath, as_attachment=True, download_name=filename)
    return "الملف غير موجود", 404

# ==============================================================================
# نظام العُهد والجلسات النقدية
# ==============================================================================

@app.route('/cash-session')
@login_required
def cash_session():
    db = get_db()
    user_id = session['user_id']

    current_session = db.execute('''
        SELECT cs.*, u.name as user_name
        FROM cash_sessions cs
        JOIN users u ON cs.user_id = u.id
        WHERE cs.user_id = ? AND cs.status = 'open'
        ORDER BY cs.id DESC LIMIT 1
    ''', (user_id,)).fetchone()

    last_session = None
    if not current_session:
        last_session = db.execute('''
            SELECT * FROM cash_sessions
            WHERE user_id = ? AND status = 'closed'
            ORDER BY id DESC LIMIT 1
        ''', (user_id,)).fetchone()

    session_stats = None
    movements = []
    if current_session:
        session_stats = db.execute('''
            SELECT
                COUNT(DISTINCT i.id) as invoice_count,
                COALESCE(SUM(CASE WHEN i.payment_method = 'cash' THEN i.net_amount ELSE 0 END), 0) as cash_sales,
                COALESCE(SUM(CASE WHEN i.payment_method = 'card' THEN i.net_amount ELSE 0 END), 0) as card_sales,
                COALESCE(SUM(CASE WHEN i.payment_method = 'transfer' THEN i.net_amount ELSE 0 END), 0) as transfer_sales,
                COALESCE(SUM(i.net_amount), 0) as total_sales
            FROM invoices i
            WHERE i.user_id = ?
            AND i.status = 'completed'
            AND i.created_at >= (SELECT opened_at FROM cash_sessions WHERE id = ?)
        ''', (user_id, current_session['id'])).fetchone()

        movements = dicts_from_rows(db.execute('''
            SELECT * FROM cash_movements
            WHERE session_id = ?
            ORDER BY created_at DESC
        ''', (current_session['id'],)).fetchall())

    closed_sessions = dicts_from_rows(db.execute('''
        SELECT cs.*, u.name as user_name
        FROM cash_sessions cs
        JOIN users u ON cs.user_id = u.id
        WHERE cs.user_id = ? AND cs.status = 'closed'
        ORDER BY cs.id DESC LIMIT 5
    ''', (user_id,)).fetchall())

    current_session = dict_from_row(current_session) if current_session else None
    last_session    = dict_from_row(last_session)    if last_session    else None
    session_stats   = dict_from_row(session_stats)   if session_stats   else None

    return render_template('cash_session.html',
                           current_session=current_session,
                           last_session=last_session,
                           session_stats=session_stats,
                           movements=movements,
                           closed_sessions=closed_sessions)

@app.route('/api/cash-session/open', methods=['POST'])
@login_required
def api_open_session():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    db = get_db()
    user_id = session['user_id']

    existing = db.execute(
        "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
        (user_id,)
    ).fetchone()

    if existing:
        return jsonify({'success': False, 'message': 'لديك جلسة مفتوحة بالفعل، أغلقها أولاً'})

    opening_balance = float(data.get('opening_balance', 0))

    try:
        cursor = db.execute('''
            INSERT INTO cash_sessions (user_id, opening_balance)
            VALUES (?, ?)
        ''', (user_id, opening_balance))

        session_id = cursor.lastrowid

        if opening_balance > 0:
            db.execute('''
                INSERT INTO cash_movements (session_id, user_id, type, amount, description)
                VALUES (?, ?, 'deposit', ?, 'رصيد افتتاحي')
            ''', (session_id, user_id, opening_balance))

        db.execute('''
            INSERT INTO activity_logs (user_id, action, details)
            VALUES (?, 'OPEN_SESSION', ?)
        ''', (user_id, f'فتح جلسة نقدية برصيد {opening_balance}'))

        db.commit()
        return jsonify({'success': True, 'session_id': session_id})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/cash-session/close', methods=['POST'])
@login_required
def api_close_session():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    db = get_db()
    user_id = session['user_id']

    session_data = db.execute(
        "SELECT * FROM cash_sessions WHERE user_id = ? AND status = 'open'",
        (user_id,)
    ).fetchone()

    if not session_data:
        return jsonify({'success': False, 'message': 'لا توجد جلسة مفتوحة'})

    actual_cash = float(data.get('actual_cash', 0))
    notes = data.get('notes', '')

    try:
        db.execute("BEGIN TRANSACTION")

        stats = db.execute('''
            SELECT
                COALESCE(SUM(CASE WHEN payment_method = 'cash' THEN net_amount ELSE 0 END), 0)     as cash_sales,
                COALESCE(SUM(CASE WHEN payment_method = 'card' THEN net_amount ELSE 0 END), 0)     as card_sales,
                COALESCE(SUM(CASE WHEN payment_method = 'transfer' THEN net_amount ELSE 0 END), 0) as transfer_sales,
                COALESCE(SUM(net_amount), 0)                                                        as total_sales
            FROM invoices
            WHERE user_id = ? AND status = 'completed'
            AND created_at >= ?
        ''', (user_id, session_data['opened_at'])).fetchone()

        # حركات النقدية: الإيداعات والسحوبات والمرتجعات
        move_stats = db.execute('''
            SELECT
                COALESCE(SUM(CASE WHEN type = 'deposit'  THEN amount ELSE 0 END), 0) as total_deposits,
                COALESCE(SUM(CASE WHEN type = 'withdraw' THEN amount ELSE 0 END), 0) as total_withdraws,
                COALESCE(SUM(CASE WHEN type = 'return'   THEN amount ELSE 0 END), 0) as total_returns
            FROM cash_movements
            WHERE session_id = ?
        ''', (session_data['id'],)).fetchone()

        # المتوقع = الإيداعات (تشمل الافتتاحي) + المبيعات النقدية - السحوبات - المرتجعات النقدية
        expected_cash = (
            stats['cash_sales'] +
            move_stats['total_deposits'] -
            move_stats['total_withdraws'] -
            move_stats['total_returns']
        )

        difference = actual_cash - expected_cash

        db.execute('''
            UPDATE cash_sessions
            SET status          = 'closed',
                closing_balance = ?,
                total_sales     = ?,
                total_cash      = ?,
                total_card      = ?,
                total_transfer  = ?,
                expected_cash   = ?,
                actual_cash     = ?,
                difference      = ?,
                notes           = ?,
                closed_at       = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            actual_cash,
            stats['total_sales'],
            stats['cash_sales'],
            stats['card_sales'],
            stats['transfer_sales'],
            expected_cash,
            actual_cash,
            difference,
            notes,
            session_data['id']
        ))

        db.execute('''
            INSERT INTO activity_logs (user_id, action, details)
            VALUES (?, 'CLOSE_SESSION', ?)
        ''', (user_id, f'إغلاق جلسة - المتوقع: {expected_cash:.3f} - الفعلي: {actual_cash:.3f} - الفرق: {difference:+.3f}'))

        db.commit()

        return jsonify({
            'success'      : True,
            'expected_cash': expected_cash,
            'actual_cash'  : actual_cash,
            'difference'   : difference,
            'total_sales'  : stats['total_sales'],
            'total_returns': move_stats['total_returns']
        })

    except Exception as e:
        db.execute("ROLLBACK")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/cash-movement', methods=['POST'])
@login_required
def api_cash_movement():
    data = request.get_json()

    if not verify_csrf_token(data.get('csrf_token', '')):
        return jsonify({'success': False, 'message': 'جلسة غير صالحة'})

    db = get_db()
    user_id = session['user_id']

    session_data = db.execute(
        "SELECT id FROM cash_sessions WHERE user_id = ? AND status = 'open'",
        (user_id,)
    ).fetchone()

    if not session_data:
        return jsonify({'success': False, 'message': 'لا توجد جلسة مفتوحة، افتح جلسة أولاً'})

    movement_type = data.get('type')
    amount = float(data.get('amount', 0))
    description = data.get('description', '')

    if movement_type in ['deposit', 'withdraw']:
        return jsonify({'success': False, 'message': 'عمليات الإيداع والسحب اليدوي غير مسموح بها. قيمة العُهدة تُحدَّد عند فتح الجلسة فقط.'})

    if movement_type not in ['sale', 'return']:
        return jsonify({'success': False, 'message': 'نوع الحركة غير صالح'})

    if amount <= 0:
        return jsonify({'success': False, 'message': 'المبلغ يجب أن يكون أكبر من صفر'})

    try:
        db.execute('''
            INSERT INTO cash_movements (session_id, user_id, type, amount, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_data['id'], user_id, movement_type, amount, description))

        db.commit()
        return jsonify({'success': True, 'message': 'تم تسجيل الحركة بنجاح'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ==============================================================================
# لوحة مراقبة المشرفين (للمدير فقط)
# ==============================================================================

@app.route('/admin/supervisors')
@role_required(['admin'])
def admin_supervisors():
    db = get_db()

    supervisors = dicts_from_rows(db.execute('''
        SELECT id, name, username, is_active, created_at
        FROM users WHERE role = 'supervisor'
        ORDER BY name ASC
    ''').fetchall())

    recent_logs = dicts_from_rows(db.execute('''
        SELECT al.*, u.name as user_name, u.username
        FROM activity_logs al
        JOIN users u ON al.user_id = u.id
        WHERE u.role = 'supervisor'
        ORDER BY al.created_at DESC
        LIMIT 100
    ''').fetchall())

    sales_stats = dicts_from_rows(db.execute('''
        SELECT u.id, u.name, u.username,
            COUNT(i.id) as total_invoices,
            COALESCE(SUM(i.net_amount), 0) as total_sales,
            COALESCE(SUM(CASE WHEN i.payment_method='cash' THEN i.net_amount ELSE 0 END), 0) as cash_sales,
            MAX(i.created_at) as last_sale
        FROM users u
        LEFT JOIN invoices i ON i.user_id = u.id AND i.status = 'completed'
        WHERE u.role = 'supervisor'
        GROUP BY u.id
        ORDER BY total_sales DESC
    ''').fetchall())

    return render_template('admin_supervisors.html',
                           supervisors=supervisors,
                           recent_logs=recent_logs,
                           sales_stats=sales_stats)


@app.route('/admin/supervisors/<int:user_id>')
@role_required(['admin'])
def admin_supervisor_detail(user_id):
    db = get_db()

    supervisor = db.execute(
        "SELECT id, name, username, is_active, created_at FROM users WHERE id = ? AND role = 'supervisor'",
        (user_id,)
    ).fetchone()

    if not supervisor:
        return render_template('error.html', message='المشرف غير موجود.'), 404

    supervisor = dict_from_row(supervisor)

    logs = dicts_from_rows(db.execute('''
        SELECT * FROM activity_logs
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 200
    ''', (user_id,)).fetchall())

    sessions = dicts_from_rows(db.execute('''
        SELECT cs.*,
            (SELECT COUNT(*) FROM invoices i
             WHERE i.user_id = cs.user_id AND i.status = 'completed'
             AND i.created_at >= cs.opened_at
             AND (cs.closed_at IS NULL OR i.created_at <= cs.closed_at)) as invoice_count,
            (SELECT COALESCE(SUM(i.net_amount),0) FROM invoices i
             WHERE i.user_id = cs.user_id AND i.status = 'completed'
             AND i.created_at >= cs.opened_at
             AND (cs.closed_at IS NULL OR i.created_at <= cs.closed_at)) as total_sales
        FROM cash_sessions cs
        WHERE cs.user_id = ?
        ORDER BY cs.id DESC
    ''', (user_id,)).fetchall())

    products_sold = dicts_from_rows(db.execute('''
        SELECT p.name as product_name, p.barcode,
               SUM(ii.quantity) as total_qty,
               SUM(ii.total_price) as total_revenue
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        JOIN invoices i ON ii.invoice_id = i.id
        WHERE i.user_id = ? AND i.status = 'completed'
        GROUP BY ii.product_id
        ORDER BY total_qty DESC
        LIMIT 20
    ''', (user_id,)).fetchall())

    total_stats = db.execute('''
        SELECT COUNT(id) as invoice_count,
               COALESCE(SUM(net_amount), 0) as total_sales,
               COALESCE(SUM(CASE WHEN payment_method='cash' THEN net_amount ELSE 0 END), 0) as cash_sales,
               COALESCE(SUM(CASE WHEN payment_method='card' THEN net_amount ELSE 0 END), 0) as card_sales,
               COALESCE(SUM(CASE WHEN payment_method='transfer' THEN net_amount ELSE 0 END), 0) as transfer_sales
        FROM invoices
        WHERE user_id = ? AND status = 'completed'
    ''', (user_id,)).fetchone()

    return render_template('admin_supervisors.html',
                           supervisors=None,
                           detail_supervisor=supervisor,
                           logs=logs,
                           sessions=sessions,
                           products_sold=products_sold,
                           total_stats=dict_from_row(total_stats) if total_stats else {})

# ==============================================================================
# لوحة إدارة جلسات المستخدمين
# ==============================================================================

@app.route('/admin/sessions')
@role_required(['admin', 'supervisor'])
def admin_sessions():
    db = get_db()

    all_sessions = dicts_from_rows(db.execute('''
        SELECT cs.*, u.name as user_name, u.username,
               (SELECT COUNT(*) FROM invoices i
                WHERE i.user_id = cs.user_id AND i.status = 'completed'
                AND i.created_at >= cs.opened_at
                AND (cs.closed_at IS NULL OR i.created_at <= cs.closed_at)) as invoice_count,
               (SELECT COALESCE(SUM(i.net_amount),0) FROM invoices i
                WHERE i.user_id = cs.user_id AND i.status = 'completed'
                AND i.created_at >= cs.opened_at
                AND (cs.closed_at IS NULL OR i.created_at <= cs.closed_at)) as total_sales
        FROM cash_sessions cs
        JOIN users u ON cs.user_id = u.id
        ORDER BY cs.id DESC
    ''').fetchall())

    return render_template('admin_sessions.html', all_sessions=all_sessions)


@app.route('/admin/sessions/<int:session_id>/details')
@role_required(['admin', 'supervisor'])
def admin_session_details(session_id):
    db = get_db()

    session_row = db.execute('''
        SELECT cs.*, u.name as user_name, u.username
        FROM cash_sessions cs
        JOIN users u ON cs.user_id = u.id
        WHERE cs.id = ?
    ''', (session_id,)).fetchone()

    if not session_row:
        return render_template('error.html', message='الجلسة غير موجودة.'), 404

    session_row = dict_from_row(session_row)

    stats = db.execute('''
        SELECT
            COUNT(i.id) as invoice_count,
            COALESCE(SUM(i.net_amount), 0) as total_sales,
            COALESCE(SUM(CASE WHEN i.payment_method='cash' THEN i.net_amount ELSE 0 END), 0) as cash_sales,
            COALESCE(SUM(CASE WHEN i.payment_method='card' THEN i.net_amount ELSE 0 END), 0) as card_sales,
            COALESCE(SUM(CASE WHEN i.payment_method='transfer' THEN i.net_amount ELSE 0 END), 0) as transfer_sales
        FROM invoices i
        WHERE i.user_id = ? AND i.status = 'completed'
        AND i.created_at >= ?
        AND (? IS NULL OR i.created_at <= ?)
    ''', (session_row['user_id'], session_row['opened_at'],
          session_row['closed_at'], session_row['closed_at'])).fetchone()

    products_sold = dicts_from_rows(db.execute('''
        SELECT p.name as product_name, p.barcode,
               SUM(ii.quantity) as total_qty,
               SUM(ii.total_price) as total_revenue,
               AVG(ii.unit_price) as avg_price
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        JOIN invoices i ON ii.invoice_id = i.id
        WHERE i.user_id = ? AND i.status = 'completed'
        AND i.created_at >= ?
        AND (? IS NULL OR i.created_at <= ?)
        GROUP BY ii.product_id
        ORDER BY total_qty DESC
    ''', (session_row['user_id'], session_row['opened_at'],
          session_row['closed_at'], session_row['closed_at'])).fetchall())

    invoices = dicts_from_rows(db.execute('''
        SELECT i.invoice_number, i.customer_name, i.net_amount,
               i.payment_method, i.created_at, i.status
        FROM invoices i
        WHERE i.user_id = ? AND i.created_at >= ?
        AND (? IS NULL OR i.created_at <= ?)
        ORDER BY i.created_at DESC
    ''', (session_row['user_id'], session_row['opened_at'],
          session_row['closed_at'], session_row['closed_at'])).fetchall())

    return render_template('admin_sessions.html',
                           all_sessions=None,
                           detail_session=session_row,
                           stats=dict_from_row(stats) if stats else {},
                           products_sold=products_sold,
                           invoices=invoices)

# ==============================================================================
# حركة المنتج - سجل كامل للمخزون
# ==============================================================================

@app.route('/product-movements/<int:product_id>')
@role_required(['admin', 'supervisor'])
def product_movements(product_id):
    db = get_db()

    from_date = request.args.get('from', (datetime.now() - timedelta(days=29)).strftime('%Y-%m-%d'))
    to_date   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))

    product = db.execute('''
        SELECT p.*, c.name as category_name, s.quantity as current_stock, s.min_quantity
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        LEFT JOIN product_stock s ON p.id = s.product_id
        WHERE p.id = ?
    ''', (product_id,)).fetchone()

    if not product:
        return render_template('error.html', message='المنتج غير موجود.'), 404

    product = dict_from_row(product)

    # جلب حركات المخزون مع ربطها بمصادرها
    raw_movements = dicts_from_rows(db.execute('''
        SELECT
            sm.id,
            sm.type,
            sm.quantity,
            sm.notes,
            sm.created_at,
            sm.reference_id,
            -- بيانات الفاتورة (بيع)
            inv.invoice_number,
            inv.id as invoice_db_id,
            -- بيانات المشتريات (شراء)
            pur.purchase_number,
            pur.id as purchase_db_id,
            sup.name as supplier_name,
            -- بيانات المرتجع
            ret.return_number,
            ret.id as return_db_id
        FROM stock_movements sm
        LEFT JOIN invoices  inv ON sm.type IN ('sale')     AND sm.reference_id = inv.id
        LEFT JOIN invoices  inv2 ON sm.type = 'return'     AND sm.reference_id = inv2.id
        LEFT JOIN purchases pur ON sm.type = 'purchase'   AND sm.reference_id = pur.id
        LEFT JOIN suppliers sup ON pur.supplier_id = sup.id
        LEFT JOIN returns   ret ON sm.type = 'return'     AND sm.reference_id = ret.invoice_id
        WHERE sm.product_id = ?
          AND DATE(sm.created_at) BETWEEN ? AND ?
        ORDER BY sm.created_at ASC
    ''', (product_id, from_date, to_date)).fetchall())

    # حساب الرصيد التراكمي
    # نحتاج أولاً رصيد ما قبل الفترة
    before_qty = db.execute('''
        SELECT COALESCE(SUM(quantity), 0) as total
        FROM stock_movements
        WHERE product_id = ? AND DATE(created_at) < ?
    ''', (product_id, from_date)).fetchone()['total']

    running_balance = float(before_qty)
    movements = []
    total_in  = 0.0
    total_out = 0.0

    for m in raw_movements:
        qty = float(m['quantity'])
        running_balance += qty

        # تحديد نوع الحركة وتسميتها
        if m['type'] == 'sale':
            type_label = 'بيع'
            type_class = 'danger'
            source = f"فاتورة #{m['invoice_number']}" if m['invoice_number'] else (m['notes'] or '—')
            link   = f"/print_invoice/{m['invoice_db_id']}" if m['invoice_db_id'] else None
        elif m['type'] == 'purchase':
            type_label = 'شراء'
            type_class = 'success'
            src_parts = []
            if m['purchase_number']: src_parts.append(f"أمر شراء #{m['purchase_number']}")
            if m['supplier_name']:   src_parts.append(f"المورد: {m['supplier_name']}")
            source = ' — '.join(src_parts) if src_parts else (m['notes'] or '—')
            link   = f"/print_purchase/{m['purchase_db_id']}" if m['purchase_db_id'] else None
        elif m['type'] == 'return':
            type_label = 'مرتجع'
            type_class = 'warning'
            source = f"مرتجع #{m['return_number']}" if m['return_number'] else (m['notes'] or '—')
            link   = f"/print_return/{m['return_db_id']}" if m['return_db_id'] else None
        else:
            type_label = 'تعديل'
            type_class = 'info'
            source = m['notes'] or 'تعديل يدوي'
            link   = None

        if qty > 0:
            total_in  += qty
        else:
            total_out += abs(qty)

        movements.append({
            'id'             : m['id'],
            'type'           : m['type'],
            'type_label'     : type_label,
            'type_class'     : type_class,
            'quantity'       : qty,
            'source'         : source,
            'link'           : link,
            'balance'        : running_balance,
            'created_at'     : m['created_at'],
            'reference_id'   : m['reference_id'],
        })

    # إحصائيات الفترة
    stats = {
        'total_in'    : total_in,
        'total_out'   : total_out,
        'net_movement': total_in - total_out,
        'count'       : len(movements),
        'balance_before': float(before_qty),
    }

    return render_template('product_movements.html',
                           product=product,
                           movements=movements,
                           stats=stats,
                           from_date=from_date,
                           to_date=to_date)

# ==============================================================================
# تشغيل التطبيق
# ==============================================================================

if __name__ == '__main__':
    init_db()
    run_migrations()
    app.run(debug=True, host='0.0.0.0', port=5000)