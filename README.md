

# Ollama Chat Interface

A secure, multi-user web interface for interacting with Ollama language models. This application provides a clean, responsive UI for chatting with AI models, with user authentication and encrypted conversation storage.

## Features

- **User Authentication**: Secure registration and login system
- **Encrypted Storage**: All conversations are encrypted using user-specific keys
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Streaming**: See AI responses as they're generated
- **Conversation Management**: Save, load, and delete conversations
- **Multiple Models**: Support for all models available in Ollama
- **Markdown Support**: Rich text formatting in AI responses
- **Code Highlighting**: Syntax highlighting for code blocks
- **Stop Generation**: Ability to stop AI responses mid-generation

## Prerequisites

- Python 3.7+
- Ollama running locally (default: http://localhost:11434)
- Required Python packages (see Installation)

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/Yunyun-Wang/Ollama-host.git
cd Ollama-host
```

2. **Create a conda environment**

3. **Install dependencies**

```bash
pip install flask requests cryptography
```

4. **Start Ollama**

Make sure Ollama is running on your system. If you haven't installed it yet, follow the instructions at [ollama.ai](https://ollama.ai).

5. **Run the application**

```bash
python app.py
```

6. **Access the web interface**

Open your browser and go to:
- Local access: http://localhost:5001
- Network access: http://your-ip-address:5001

## Usage

1. **Register a new account** or log in with existing credentials
2. **Select a model** from the dropdown menu
3. **Type your message** in the input field and press Enter or click Send
4. **View your conversation history** in the sidebar
5. **Create a new chat** by clicking the "New Chat" button
6. **Delete conversations** by hovering over them in the sidebar and clicking the trash icon
7. **Clear all conversations** using the button at the bottom of the sidebar

## Security Features

- **Password Hashing**: User passwords are hashed using SHA-256
- **Conversation Encryption**: All conversations are encrypted using Fernet symmetric encryption
- **User-specific Keys**: Encryption keys are derived from the user's password hash
- **Session Management**: Secure session handling for authentication

## Mobile Support

The interface is fully responsive and works well on mobile devices:
- Collapsible sidebar for more chat space
- Touch-friendly buttons and inputs
- Optimized layout for small screens

## Project Structure

```
ollama-chat-interface/
├── app.py                 # Main Flask application
├── .gitignore             # Git ignore file
├── README.md              # This documentation
├── conversations/         # Directory for encrypted conversations
├── users.db               # SQLite database for user accounts
└── templates/
    ├── index.html         # Main chat interface
    ├── login.html         # Login page
    └── register.html      # Registration page
```


## Troubleshooting

- **Can't connect to Ollama**: Make sure Ollama is running and accessible at http://localhost:11434
- **Login issues**: Try registering a new account if you forgot your password
- **Slow responses**: Some models are larger and may take longer to generate responses

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Ollama](https://ollama.ai) for providing the local LLM server
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Marked.js](https://marked.js.org/) for Markdown rendering
- [highlight.js](https://highlightjs.org/) for code syntax highlighting

---
