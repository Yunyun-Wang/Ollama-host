from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session, flash
import requests
import json
import time
import os
import uuid
import hashlib
import sqlite3
from functools import wraps
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
OLLAMA_LIST_MODELS = "http://localhost:11434/api/tags"
CONVERSATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conversations")

# Create conversations directory if it doesn't exist
if not os.path.exists(CONVERSATIONS_DIR):
    os.makedirs(CONVERSATIONS_DIR)

# Database setup
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Update conversations directory to be user-specific
def get_user_conversations_dir():
    user_id = session.get('user_id')
    if not user_id:
        return None
    
    user_dir = os.path.join(CONVERSATIONS_DIR, str(user_id))
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return user_dir

@app.route('/')
@login_required
def home():
    # Add a cache-busting parameter to prevent partial refreshes
    return render_template('index.html', 
                          cache_bust=str(time.time()), 
                          username=session.get('username'))

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    messages = data.get('messages', [])
    model = data.get('model', 'deepseek-r1:7b')
    conversation_id = data.get('conversation_id')
    stream = data.get('stream', True)  # Default to streaming, but allow non-streaming
    
    # Log the conversation context for debugging
    print(f"Processing chat request for conversation: {conversation_id}")
    print(f"Message history length: {len(messages)}")
    
    # Prepare the request for Ollama
    ollama_request = {
        "model": model,
        "messages": messages,
        "stream": stream
    }
    
    # Handle non-streaming requests (for summarization)
    if not stream:
        try:
            response = requests.post(OLLAMA_ENDPOINT, json=ollama_request, timeout=60)
            response_data = response.json()
            return jsonify({
                "full_response": response_data.get('message', {}).get('content', ''),
                "done": True
            })
        except Exception as e:
            print(f"Non-streaming error: {str(e)}")
            return jsonify({"error": str(e)}), 500
    
    # For streaming requests, use a more robust approach
    def generate():
        try:
            # Use a session for better connection handling
            with requests.Session() as session:
                # Add timeout and increase buffer size
                response = session.post(OLLAMA_ENDPOINT, json=ollama_request, stream=True, timeout=120)
                
                # Initialize an empty response
                full_response = ""
                
                # Stream the response with better error handling
                try:
                    for line in response.iter_lines():
                        if line:
                            try:
                                chunk = json.loads(line.decode('utf-8'))
                                if 'message' in chunk and 'content' in chunk['message']:
                                    content = chunk['message']['content']
                                    full_response += content
                                    
                                    # Send each character immediately for a smoother streaming experience
                                    yield f"data: {json.dumps({'content': content, 'full_response': full_response})}\n\n"
                                
                                elif 'done' in chunk and chunk['done']:
                                    # Save the conversation to disk when done, but only if conversation_id is provided and not null
                                    if conversation_id and conversation_id != "null":
                                        save_conversation(conversation_id, messages + [{"role": "assistant", "content": full_response}], model)
                                    
                                    # Send done signal
                                    yield f"data: {json.dumps({'done': True, 'full_response': full_response})}\n\n"
                                    break
                            except json.JSONDecodeError as e:
                                print(f"JSON decode error: {str(e)}, line: {line}")
                                continue
                except Exception as e:
                    print(f"Error during streaming: {str(e)}")
                    # Send a partial response with what we have so far
                    if full_response:
                        yield f"data: {json.dumps({'error': str(e), 'full_response': full_response, 'done': True})}\n\n"
                    else:
                        yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"
        
        except requests.exceptions.Timeout:
            print("Request to Ollama timed out")
            yield f"data: {json.dumps({'error': 'Request to language model timed out', 'done': True})}\n\n"
        except requests.exceptions.ConnectionError:
            print("Connection error to Ollama")
            yield f"data: {json.dumps({'error': 'Connection to language model failed', 'done': True})}\n\n"
        except Exception as e:
            print(f"Streaming error: {str(e)}")
            yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"
    
    # Set response headers to prevent buffering
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/models', methods=['GET'])
def get_models():
    try:
        response = requests.get(OLLAMA_LIST_MODELS)
        models = response.json()
        return jsonify(models)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations', methods=['GET'])
@login_required
def get_conversations():
    try:
        user_id = session.get('user_id')
        user_dir = get_user_conversations_dir()
        
        # Get the user's password hash for decryption
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        password_hash = user[0]
        
        conversations = []
        
        for filename in os.listdir(user_dir):
            if filename.endswith('.enc'):
                try:
                    with open(os.path.join(user_dir, filename), 'r') as f:
                        encrypted_data = f.read()
                        conversation = decrypt_data(encrypted_data, password_hash)
                        # Only include necessary metadata for the list view
                        conversations.append({
                            "id": conversation["id"],
                            "title": conversation["title"],
                            "model": conversation["model"],
                            "updated_at": conversation["updated_at"]
                        })
                except Exception as e:
                    print(f"Error decrypting conversation {filename}: {e}")
        
        # Sort by last modified time (newest first)
        conversations.sort(key=lambda x: x.get('updated_at', 0), reverse=True)
        return jsonify({"conversations": conversations})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['GET'])
@login_required
def get_conversation(conversation_id):
    try:
        user_id = session.get('user_id')
        user_dir = get_user_conversations_dir()
        
        # Get the user's password hash for decryption
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        password_hash = user[0]
        
        file_path = os.path.join(user_dir, f"{conversation_id}.enc")
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
                conversation = decrypt_data(encrypted_data, password_hash)
            return jsonify(conversation)
        else:
            return jsonify({"error": "Conversation not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations', methods=['POST'])
def create_conversation():
    try:
        print("\n=== CREATE/UPDATE CONVERSATION DEBUG ===")
        data = request.json
        conversation_id = data.get('id') or str(uuid.uuid4())
        title = data.get('title')
        messages = data.get('messages', [])
        model = data.get('model', 'deepseek-r1:7b')
        
        print(f"Received conversation update: ID={conversation_id}, Title={title}")
        
        saved_title = save_conversation(conversation_id, messages, model, title)
        
        print(f"Conversation saved with title: {saved_title}")
        print("=== END CREATE/UPDATE CONVERSATION DEBUG ===\n")
        
        return jsonify({
            "id": conversation_id, 
            "success": True,
            "title": saved_title
        })
    except Exception as e:
        print(f"Error in create_conversation: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['DELETE'])
@login_required
def delete_conversation(conversation_id):
    try:
        user_dir = get_user_conversations_dir()
        if not user_dir:
            return jsonify({"error": "User not logged in"}), 401
            
        file_path = os.path.join(user_dir, f"{conversation_id}.enc")
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Conversation not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/clear', methods=['POST'])
@login_required
def clear_conversations():
    try:
        user_dir = get_user_conversations_dir()
        if not user_dir:
            return jsonify({"error": "User not logged in"}), 401
            
        for filename in os.listdir(user_dir):
            if filename.endswith('.enc'):
                os.remove(os.path.join(user_dir, filename))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def get_encryption_key(password_hash):
    # Use the first 32 bytes of the password hash as a salt
    salt = password_hash[:32].encode()
    
    # Use PBKDF2 to derive a key from the password hash
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    # Use the rest of the password hash as the key material
    key = base64.urlsafe_b64encode(kdf.derive(password_hash[32:].encode()))
    return key

def encrypt_data(data, password_hash):
    key = get_encryption_key(password_hash)
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(encrypted_data, password_hash):
    key = get_encryption_key(password_hash)
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data.encode()).decode())

def save_conversation(conversation_id, messages, model, title=None):
    """Save an encrypted conversation to disk"""
    print("\n=== SAVE CONVERSATION DEBUG ===")
    print(f"Saving conversation: {conversation_id}")
    print(f"Title provided: {title}")
    
    user_id = session.get('user_id')
    if not user_id:
        print("No user logged in")
        return None
    
    # Get the user's password hash for encryption
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        print("User not found in database")
        return None
    
    password_hash = user[0]
    
    user_dir = get_user_conversations_dir()
    if not user_dir:
        print("No user directory available")
        return None
    
    file_path = os.path.join(user_dir, f"{conversation_id}.enc")
    print(f"File path: {file_path}")
    
    # If the file exists, read and decrypt the existing data
    existing_title = None
    existing_data = None
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
                existing_data = decrypt_data(encrypted_data, password_hash)
                existing_title = existing_data.get('title')
                print(f"Existing title found: {existing_title}")
        except Exception as e:
            print(f"Error reading/decrypting existing file: {e}")
    else:
        print("No existing file found")
    
    # Use existing title if no new title provided
    if title is None:
        title = existing_title or "New Chat"
        print(f"No title provided, using: {title}")
    else:
        print(f"Using provided title: {title}")
    
    # If we're explicitly providing a title, use it
    # Otherwise, if title is still "New Chat" and there are messages, use first message as title
    if title != "New Chat" or (existing_title and existing_title != "New Chat"):
        # Keep the provided title or existing non-default title
        print(f"Using non-default title: {title}")
    elif messages and len(messages) > 0:
        first_message = next((m for m in messages if m['role'] == 'user'), None)
        if first_message:
            # Only use this as a fallback if we don't have a better title
            old_title = title
            title = first_message['content'][:30] + ('...' if len(first_message['content']) > 30 else '')
            print(f"Generated fallback title from message: {old_title} -> {title}")
    
    # Prepare the conversation data
    conversation_data = {
        "id": conversation_id,
        "title": title,
        "messages": messages,
        "model": model,
        "updated_at": int(time.time())
    }
    
    # Encrypt the conversation data
    encrypted_data = encrypt_data(conversation_data, password_hash)
    
    # Save the encrypted data
    with open(file_path, 'w') as f:
        f.write(encrypted_data)
    
    print("Conversation saved and encrypted successfully")
    print("=== END SAVE CONVERSATION DEBUG ===\n")
    
    return title

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required')
            return render_template('register.html')
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                          (username, hashed_password))
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', 
                      (username, hashed_password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 