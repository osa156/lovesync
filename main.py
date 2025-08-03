import os
import sys
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests
from datetime import datetime, timedelta
import secrets
from src.models.user import db, User, Swipe, Message, Match

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = 'asdf#FGSgvasgf$5$WGT'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'app.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Paystack configuration
PAYSTACK_SECRET_KEY = 'sk_live_86fcee14d403288d8fd5c991850896d1b68e225a'
PAYSTACK_PUBLIC_KEY = 'pk_live_669ad09183f1ded9229c99297d5d67f539e3c828'

with app.app_context():
    db.create_all()

# Authentication middleware
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Auth routes
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    gender = data.get('gender')
    
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    hashed_password = generate_password_hash(password)
    verification_token = secrets.token_urlsafe(32)
    
    user = User(
        email=email,
        password=hashed_password,
        gender=gender,
        verification_token=verification_token
    )
    
    db.session.add(user)
    db.session.commit()
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'gender': user.gender,
            'verified': user.verified,
            'subscription': user.subscription
        }
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'gender': user.gender,
            'verified': user.verified,
            'subscription': user.subscription,
            'profile': {
                'name': user.name,
                'age': user.age,
                'bio': user.bio,
                'interests': user.interests,
                'occupation': user.occupation,
                'income': user.income,
                'location': user.location
            }
        }
    })

# Profile routes
@app.route('/api/profile', methods=['POST'])
@token_required
def update_profile(current_user):
    data = request.get_json()
    
    current_user.name = data.get('name', current_user.name)
    current_user.age = data.get('age', current_user.age)
    current_user.bio = data.get('bio', current_user.bio)
    current_user.interests = data.get('interests', current_user.interests)
    current_user.occupation = data.get('occupation', current_user.occupation)
    current_user.income = data.get('income', current_user.income)
    current_user.location = data.get('location', current_user.location)
    
    db.session.commit()
    
    return jsonify({'message': 'Profile updated successfully'})

@app.route('/api/profiles', methods=['GET'])
@token_required
def get_profiles(current_user):
    # Income thresholds based on subscription
    income_thresholds = {
        'basic': 0,
        'silver': 30000,
        'gold': 50000,
        'platinum': 75000,
        'diamond': 100000
    }
    
    # Get swiped profile IDs to exclude
    swiped_ids = [swipe.target_user_id for swipe in Swipe.query.filter_by(user_id=current_user.id).all()]
    
    # Find potential matches
    opposite_gender = 'female' if current_user.gender == 'male' else 'male'
    min_income = income_thresholds.get(current_user.subscription, 0)
    
    profiles = User.query.filter(
        User.gender == opposite_gender,
        User.id != current_user.id,
        User.id.notin_(swiped_ids),
        User.income >= min_income
    ).limit(10).all()
    
    profile_list = []
    for profile in profiles:
        profile_list.append({
            'id': profile.id,
            'name': profile.name,
            'age': profile.age,
            'bio': profile.bio,
            'interests': profile.interests,
            'occupation': profile.occupation,
            'income': profile.income,
            'location': profile.location
        })
    
    return jsonify({
        'profiles': profile_list,
        'swipe_count': current_user.swipe_count,
        'subscription': current_user.subscription
    })

# Swipe routes
@app.route('/api/swipe', methods=['POST'])
@token_required
def swipe(current_user):
    data = request.get_json()
    target_user_id = data.get('target_user_id')
    direction = data.get('direction')
    
    # Check if already swiped
    existing_swipe = Swipe.query.filter_by(
        user_id=current_user.id,
        target_user_id=target_user_id
    ).first()
    
    if existing_swipe:
        return jsonify({'message': 'Already swiped on this profile'}), 400
    
    # Create swipe record
    swipe = Swipe(
        user_id=current_user.id,
        target_user_id=target_user_id,
        direction=direction
    )
    db.session.add(swipe)
    
    # Update swipe count for males
    if current_user.gender == 'male' and direction == 'right':
        current_user.swipe_count += 1
        
        # Check if payment is needed (free users get 25 swipes)
        if current_user.subscription == 'basic' and current_user.swipe_count >= 25:
            db.session.commit()
            return jsonify({
                'message': 'Swipe limit reached',
                'needs_payment': True,
                'swipe_count': current_user.swipe_count
            })
    
    # Check for mutual match
    mutual_swipe = Swipe.query.filter_by(
        user_id=target_user_id,
        target_user_id=current_user.id,
        direction='right'
    ).first()
    
    is_match = False
    if direction == 'right' and mutual_swipe:
        # Create match
        match = Match(user1_id=current_user.id, user2_id=target_user_id)
        db.session.add(match)
        is_match = True
    
    db.session.commit()
    
    return jsonify({
        'message': 'Swipe recorded',
        'is_match': is_match,
        'swipe_count': current_user.swipe_count
    })

# Subscription routes
@app.route('/api/subscription/plans', methods=['GET'])
def get_subscription_plans():
    plans = {
        'male': [
            {'id': 'male_unlimited', 'name': 'Unlimited Swipes', 'price': 999, 'description': 'Unlimited right swipes for 30 days'}
        ],
        'female': [
            {'id': 'silver', 'name': 'Silver', 'price': 1999, 'description': 'Access to men earning $30k+/year'},
            {'id': 'gold', 'name': 'Gold', 'price': 3999, 'description': 'Access to men earning $50k+/year + Priority matching'},
            {'id': 'platinum', 'name': 'Platinum', 'price': 7999, 'description': 'Access to men earning $75k+/year + Advanced filters'},
            {'id': 'diamond', 'name': 'Diamond', 'price': 15999, 'description': 'Access to men earning $100k+/year + VIP features'}
        ]
    }
    return jsonify(plans)

@app.route('/api/subscription/verify', methods=['POST'])
@token_required
def verify_subscription(current_user):
    data = request.get_json()
    reference = data.get('reference')
    plan_id = data.get('plan_id')
    
    # Verify payment with Paystack
    headers = {
        'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(
        f'https://api.paystack.co/transaction/verify/{reference}',
        headers=headers
    )
    
    if response.status_code == 200:
        payment_data = response.json()
        if payment_data['data']['status'] == 'success':
            # Update user subscription
            if current_user.gender == 'male' and plan_id == 'male_unlimited':
                current_user.swipe_count = 0  # Reset swipe count
                current_user.subscription_expires = datetime.utcnow() + timedelta(days=30)
            elif current_user.gender == 'female':
                current_user.subscription = plan_id
                current_user.subscription_expires = datetime.utcnow() + timedelta(days=30)
            
            db.session.commit()
            
            return jsonify({
                'message': 'Subscription updated successfully',
                'subscription': current_user.subscription,
                'swipe_count': current_user.swipe_count
            })
    
    return jsonify({'message': 'Payment verification failed'}), 400

# Messaging routes
@app.route('/api/matches', methods=['GET'])
@token_required
def get_matches(current_user):
    matches = Match.query.filter(
        (Match.user1_id == current_user.id) | (Match.user2_id == current_user.id)
    ).all()
    
    match_list = []
    for match in matches:
        other_user_id = match.user2_id if match.user1_id == current_user.id else match.user1_id
        other_user = User.query.get(other_user_id)
        
        # Get last message
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
            ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        
        match_list.append({
            'id': match.id,
            'user': {
                'id': other_user.id,
                'name': other_user.name,
                'age': other_user.age
            },
            'last_message': {
                'content': last_message.content if last_message else None,
                'timestamp': last_message.timestamp.isoformat() if last_message else None
            }
        })
    
    return jsonify({'matches': match_list})

@app.route('/api/messages/<int:match_id>', methods=['GET'])
@token_required
def get_messages(current_user, match_id):
    match = Match.query.get(match_id)
    if not match or (match.user1_id != current_user.id and match.user2_id != current_user.id):
        return jsonify({'message': 'Match not found'}), 404
    
    other_user_id = match.user2_id if match.user1_id == current_user.id else match.user1_id
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    message_list = []
    for message in messages:
        message_list.append({
            'id': message.id,
            'content': message.content,
            'sender_id': message.sender_id,
            'timestamp': message.timestamp.isoformat()
        })
    
    return jsonify({'messages': message_list})

# Socket.IO events for real-time messaging
@socketio.on('join_room')
def on_join(data):
    room = data['room']
    emit('status', {'msg': f'User joined room {room}'}, room=room)

@socketio.on('send_message')
def handle_message(data):
    # Save message to database
    message = Message(
        sender_id=data['sender_id'],
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    db.session.add(message)
    db.session.commit()
    
    # Emit to room
    room = f"{min(data['sender_id'], data['receiver_id'])}_{max(data['sender_id'], data['receiver_id'])}"
    emit('receive_message', {
        'id': message.id,
        'content': message.content,
        'sender_id': message.sender_id,
        'timestamp': message.timestamp.isoformat()
    }, room=room)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404

    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "index.html not found", 404

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

