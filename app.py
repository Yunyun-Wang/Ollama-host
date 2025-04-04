from flask import Flask, render_template, request, jsonify, Response
import requests
import json
import time
import os
import uuid

app = Flask(__name__)

OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
OLLAMA_LIST_MODELS = "http://localhost:11434/api/tags"
CONVERSATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conversations")

# Create conversations directory if it doesn't exist
if not os.path.exists(CONVERSATIONS_DIR):
    os.makedirs(CONVERSATIONS_DIR)

@app.route('/')
def home():
    # Add a cache-busting parameter to prevent partial refreshes
    return render_template('index.html', cache_bust=str(time.time()))

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
            response = requests.post(OLLAMA_ENDPOINT, json=ollama_request)
            response_data = response.json()
            return jsonify({
                "full_response": response_data.get('message', {}).get('content', ''),
                "done": True
            })
        except Exception as e:
            print(f"Non-streaming error: {str(e)}")
            return jsonify({"error": str(e)}), 500
    
    # For streaming requests, continue with existing code
    def generate():
        try:
            # Use a session for better connection handling
            with requests.Session() as session:
                response = session.post(OLLAMA_ENDPOINT, json=ollama_request, stream=True, timeout=60)
                
                # Initialize an empty response
                full_response = ""
                
                # Stream the response
                for line in response.iter_lines():
                    if line:
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
            
        except Exception as e:
            print(f"Streaming error: {str(e)}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/models', methods=['GET'])
def get_models():
    try:
        response = requests.get(OLLAMA_LIST_MODELS)
        models = response.json()
        return jsonify(models)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations', methods=['GET'])
def get_conversations():
    try:
        conversations = []
        for filename in os.listdir(CONVERSATIONS_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(CONVERSATIONS_DIR, filename), 'r') as f:
                    conversation = json.load(f)
                    conversations.append(conversation)
        
        # Sort by last modified time (newest first)
        conversations.sort(key=lambda x: x.get('updated_at', 0), reverse=True)
        return jsonify({"conversations": conversations})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['GET'])
def get_conversation(conversation_id):
    try:
        file_path = os.path.join(CONVERSATIONS_DIR, f"{conversation_id}.json")
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                conversation = json.load(f)
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
def delete_conversation(conversation_id):
    try:
        file_path = os.path.join(CONVERSATIONS_DIR, f"{conversation_id}.json")
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Conversation not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/clear', methods=['POST'])
def clear_conversations():
    try:
        for filename in os.listdir(CONVERSATIONS_DIR):
            if filename.endswith('.json'):
                os.remove(os.path.join(CONVERSATIONS_DIR, filename))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def save_conversation(conversation_id, messages, model, title=None):
    """Save a conversation to disk"""
    print("\n=== SAVE CONVERSATION DEBUG ===")
    print(f"Saving conversation: {conversation_id}")
    print(f"Title provided: {title}")
    
    file_path = os.path.join(CONVERSATIONS_DIR, f"{conversation_id}.json")
    print(f"File path: {file_path}")
    
    # If the file exists, read the existing title
    existing_title = None
    existing_data = None
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                existing_data = json.load(f)
                existing_title = existing_data.get('title')
                print(f"Existing title found: {existing_title}")
        except Exception as e:
            print(f"Error reading existing file: {e}")
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
    
    # Preserve other existing data if available
    conversation_data = {
        "id": conversation_id,
        "title": title,
        "messages": messages,
        "model": model,
        "updated_at": int(time.time())
    }
    
    # Log what's happening
    print(f"Final title being saved: {title}")
    
    with open(file_path, 'w') as f:
        json.dump(conversation_data, f, indent=2)
    
    print("Conversation saved successfully")
    print("=== END SAVE CONVERSATION DEBUG ===\n")
    
    return title

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 