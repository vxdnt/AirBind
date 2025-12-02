from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import secrets
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300}
app.config['UPLOAD_FOLDER'] = 'static/event_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# ==================== MODELS ====================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    contact = db.Column(db.String(15))
    city = db.Column(db.String(50))
    upi = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    orders = db.relationship('Order', backref='user', lazy=True, cascade='all, delete-orphan')
    commissions = db.relationship('Commission', backref='user', lazy=True, cascade='all, delete-orphan')

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    ref_url = db.Column(db.String(255))
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    city = db.Column(db.String(100), nullable=False)
    commission_percent = db.Column(db.Float, default=0.0)
    image = db.Column(db.String(255))
    promo_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    orders = db.relationship('Order', backref='event', lazy=True, cascade='all, delete-orphan')
    tickets = db.relationship('Ticket', backref='event', lazy=True, cascade='all, delete-orphan')

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    
    category = db.Column(db.String(100), nullable=False)  # e.g., "VIP", "General", "Early Bird"
    price = db.Column(db.Float, nullable=False)
    available_quantity = db.Column(db.Integer, nullable=False)
    total_quantity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)  # Optional: benefits of this ticket category
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=True)
    
    client_name = db.Column(db.String(100), nullable=False)
    client_email = db.Column(db.String(100))
    client_mobile = db.Column(db.String(15))
    client_city = db.Column(db.String(50))
    
    ticket_category = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    
    transaction_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    commission = db.relationship('Commission', backref='order', uselist=False, lazy=True, cascade='all, delete-orphan')
    ticket = db.relationship('Ticket', foreign_keys=[ticket_id])

class Commission(db.Model):
    __tablename__ = 'commissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)

# ==================== HELPER FUNCTIONS ====================
def init_db():
    """Initialize database and create admin user"""
    with app.app_context():
        db.create_all()
        
        # Check if admin exists
        admin = User.query.filter_by(username='admin').first()
        password = os.getenv("ADMIN_PASSWORD")
        if not admin:
            admin = User(
                name='Administrator',
                username='admin',
                password_hash = generate_password_hash(password),
                email='admin@eventsales.com',
                is_admin=True,
                contact='1234567890',
                city='Mumbai',
                upi='admin@upi'
            )
            db.session.add(admin)
            db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== STATIC FILES ====================
@app.route('/static/event_images/<path:filename>')
def serve_event_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== AUTH ROUTES ====================
@app.route('/')
def index():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        contact = request.form.get('contact')
        city = request.form.get('city')
        upi = request.form.get('upi')
        
        # Check if user exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            name=name,
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            contact=contact,
            city=city,
            upi=upi
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== API ROUTES FOR TICKETS ====================
@app.route('/api/event/<int:event_id>/tickets')
def get_event_tickets(event_id):
    """API endpoint to get available tickets for an event"""
    tickets = Ticket.query.filter_by(event_id=event_id, is_active=True).all()
    return jsonify([{
        'id': t.id,
        'category': t.category,
        'price': t.price,
        'available_quantity': t.available_quantity,
        'description': t.description
    } for t in tickets])

# ==================== USER ROUTES ====================
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    user = db.session.get(User, session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    events = Event.query.order_by(Event.date.desc()).all()
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    commissions = Commission.query.filter_by(user_id=user.id).order_by(Commission.requested_at.desc()).all()
    
    # Calculate statistics
    total_sales = sum(order.total_amount for order in orders if order.status == 'completed')
    pending_commission = sum(c.amount for c in commissions if c.status == 'pending')
    earned_commission = sum(c.amount for c in commissions if c.status == 'completed')
    
    return render_template('user_dashboard.html',
                         user=user,
                         events=events,
                         orders=orders,
                         commissions=commissions,
                         total_sales=total_sales,
                         pending_commission=pending_commission,
                         earned_commission=earned_commission)

@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    user = db.session.get(User, session['user_id'])
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.contact = request.form.get('contact')
        user.city = request.form.get('city')
        user.upi = request.form.get('upi')
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))
    
    return render_template('user_profile.html', user=user)

@app.route('/user/order/create', methods=['POST'])
@login_required
def create_order():
    user = db.session.get(User, session['user_id'])

    try:
        ticket_id = request.form.get('ticket_id')
        quantity = int(request.form.get('quantity'))
        
        # Get ticket details
        ticket = db.session.get(Ticket, ticket_id)
        if not ticket or not ticket.is_active:
            flash('Invalid ticket selected', 'error')
            return redirect(url_for('user_dashboard'))
        
        # Check availability
        if ticket.available_quantity < quantity:
            flash(f'Only {ticket.available_quantity} tickets available', 'error')
            return redirect(url_for('user_dashboard'))
        
        # Calculate total amount
        total_amount = ticket.price * quantity
        
        # Auto-populate client city from event city (user can override if needed)
        client_city = request.form.get('client_city') if request.form.get('client_city') else ticket.event.city
        
        order = Order(
            user_id=user.id,
            event_id=ticket.event_id,
            ticket_id=ticket_id,
            client_name=request.form.get('client_name'),
            client_email=request.form.get('client_email'),
            client_mobile=request.form.get('client_mobile'),
            client_city=client_city,
            ticket_category=ticket.category,
            quantity=quantity,
            total_amount=total_amount,
            transaction_id=request.form.get('transaction_id'),
            status='pending'
        )
        
        # Update ticket availability
        ticket.available_quantity -= quantity
        
        db.session.add(order)
        db.session.commit()
        
        flash('Booking created successfully! Wait for admin approval.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating booking: {str(e)}', 'error')
    
    return redirect(url_for('user_dashboard'))

@app.route('/user/commission/request', methods=['POST'])
@login_required
def request_commission():
    user = User.query.get(session['user_id'])
    order_id = request.form.get('order_id')
    
    order = Order.query.filter_by(id=order_id, user_id=user.id, status='completed').first()
    
    if not order:
        flash('Order not found or not completed', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Check if commission already requested
    existing = Commission.query.filter_by(order_id=order_id).first()
    if existing:
        flash('Commission already requested for this order', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Calculate commission
    commission_amount = (order.total_amount * order.event.commission_percent) / 100
    
    commission = Commission(
        user_id=user.id,
        order_id=order_id,
        amount=commission_amount,
        status='pending'
    )
    
    db.session.add(commission)
    db.session.commit()
    
    flash('Commission request submitted successfully!', 'success')
    return redirect(url_for('user_dashboard'))

# ==================== ADMIN ROUTES ====================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user = db.session.get(User, session['user_id'])
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    events = Event.query.order_by(Event.date.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).all()
    commissions = Commission.query.order_by(Commission.requested_at.desc()).all()
    
    pending_orders = Order.query.filter_by(status='pending').order_by(Order.created_at.desc()).all()
    pending_commissions = Commission.query.filter_by(status='pending').order_by(Commission.requested_at.desc()).all()
    completed_commissions = Commission.query.filter_by(status='completed').order_by(Commission.requested_at.desc()).all()
    
    total_users = len(users)
    total_events = len(events)
    total_orders = len(orders)
    total_revenue = sum(o.total_amount for o in orders if o.status == 'completed')
    
    return render_template('admin_dashboard.html',
                         user=user,
                         users=users,
                         events=events,
                         orders=orders,
                         commissions=commissions,
                         pending_orders=pending_orders,
                         pending_commissions=pending_commissions,
                         completed_commissions=completed_commissions,
                         total_users=total_users,
                         total_events=total_events,
                         total_orders=total_orders,
                         total_revenue=total_revenue)

@app.route('/admin/event/add', methods=['GET', 'POST'])
@admin_required
def add_event():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        try:
            # Handle file upload
            image_path = None
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename = f"{secrets.token_hex(8)}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = f"{filename}"
            
            event = Event(
                name=request.form.get('name'),
                description=request.form.get('description'),
                date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
                time=datetime.strptime(request.form.get('time'), '%H:%M').time(),
                city=request.form.get('city'),
                commission_percent=float(request.form.get('commission_percent')),
                promo_text=request.form.get('promo_text'),
                ref_url=request.form.get('ref_url'),
                image=image_path
            )
            
            db.session.add(event)
            db.session.commit()
            
            flash('Event added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding event: {str(e)}', 'error')
    
    return render_template('add_event.html', user=user)

@app.route('/admin/event/edit/<int:event_id>', methods=['GET', 'POST'])
@admin_required
def edit_event(event_id):
    user = User.query.get(session['user_id'])
    event = Event.query.get_or_404(event_id)
    
    if request.method == 'POST':
        try:
            event.name = request.form.get('name')
            event.description = request.form.get('description')
            event.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
            event.time = datetime.strptime(request.form.get('time'), '%H:%M').time()
            event.city = request.form.get('city')
            event.commission_percent = float(request.form.get('commission_percent'))
            event.promo_text = request.form.get('promo_text')
            event.ref_url = request.form.get('ref_url')
            
            # Handle file upload
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename = f"{secrets.token_hex(8)}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    event.image = f"event_images/{filename}"
            
            db.session.commit()
            
            flash('Event updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating event: {str(e)}', 'error')
    
    return render_template('edit_event.html', user=user, event=event)

@app.route('/admin/event/delete/<int:event_id>')
@admin_required
def delete_event(event_id):
    try:
        event = Event.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

# ==================== ADMIN TICKET MANAGEMENT ====================
@app.route('/admin/event/<int:event_id>/tickets')
@admin_required
def manage_tickets(event_id):
    user = User.query.get(session['user_id'])
    event = Event.query.get_or_404(event_id)
    tickets = Ticket.query.filter_by(event_id=event_id).all()
    
    return render_template('manage_tickets.html', user=user, event=event, tickets=tickets)

@app.route('/admin/ticket/add', methods=['POST'])
@admin_required
def add_ticket():
    try:
        ticket = Ticket(
            event_id=request.form.get('event_id'),
            category=request.form.get('category'),
            price=float(request.form.get('price')),
            total_quantity=int(request.form.get('total_quantity')),
            available_quantity=int(request.form.get('total_quantity')),
            description=request.form.get('description'),
            is_active=True
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        flash('Ticket category added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding ticket: {str(e)}', 'error')
    
    return redirect(url_for('manage_tickets', event_id=request.form.get('event_id')))

@app.route('/admin/ticket/edit/<int:ticket_id>', methods=['POST'])
@admin_required
def edit_ticket(ticket_id):
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        ticket.category = request.form.get('category')
        ticket.price = float(request.form.get('price'))
        ticket.total_quantity = int(request.form.get('total_quantity'))
        ticket.available_quantity = int(request.form.get('available_quantity'))
        ticket.description = request.form.get('description')
        ticket.is_active = request.form.get('is_active') == 'true'
        ticket.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash('Ticket updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating ticket: {str(e)}', 'error')
    
    return redirect(url_for('manage_tickets', event_id=ticket.event_id))

@app.route('/admin/ticket/delete/<int:ticket_id>')
@admin_required
def delete_ticket(ticket_id):
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        event_id = ticket.event_id
        db.session.delete(ticket)
        db.session.commit()
        
        flash('Ticket deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting ticket: {str(e)}', 'error')
    
    return redirect(url_for('manage_tickets', event_id=event_id))

@app.route('/admin/order/update/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        old_status = order.status
        new_status = request.form.get('status')
        
        order.status = new_status
        order.updated_at = datetime.utcnow()
        
        # If order is cancelled, return tickets to available pool
        if new_status == 'cancelled' and old_status != 'cancelled':
            if order.ticket_id:
                ticket = Ticket.query.get(order.ticket_id)
                if ticket:
                    ticket.available_quantity += order.quantity
        
        db.session.commit()
        
        flash('Order status updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating order: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/commission/update/<int:commission_id>', methods=['POST'])
@admin_required
def update_commission_status(commission_id):
    try:
        commission = Commission.query.get_or_404(commission_id)
        commission.status = request.form.get('status')
        if request.form.get('status') == 'completed':
            commission.paid_at = datetime.utcnow()
        db.session.commit()
        
        flash('Commission payment updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating commission: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/guidelines')
def guidelines():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('guidelines.html', user=user)

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    init_db()
    # Use environment variable for debug mode (default to False in production)
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
