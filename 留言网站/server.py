from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import hashlib
import datetime
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)

# 添加限流器
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2 per second"]
)

# 在实际应用中，这些配置应该存储在环境变量中
SECRET_KEY = "your-secret-key"
ADMIN_PASSWORD_HASH = hashlib.sha256("123456".encode()).hexdigest()  # 默认密码的哈希值

# 存储留言的文件
MESSAGES_FILE = "messages.json"

def load_messages():
    try:
        # 首先尝试读取 MESSAGES_FILE
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('messages', [])
    except FileNotFoundError:
        try:
            # 如果 MESSAGES_FILE 不存在，尝试读取默认的 messages.json
            with open('messages.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                messages = data.get('messages', [])
                # 保存到 MESSAGES_FILE
                save_messages(messages)
                return messages
        except FileNotFoundError:
            # 如果两个文件都不存在，返回空列表
            return []
    except Exception as e:
        print(f"Error loading messages: {e}")
        return []

def save_messages(messages):
    with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump({'messages': messages}, f, ensure_ascii=False, indent=2)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password')
    
    # 验证密码
    if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        # 生成 JWT token
        token = jwt.encode({
            'admin': True,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        
        return jsonify({'token': token})
    
    return jsonify({'error': '密码错误'}), 401

def verify_token(token):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return True
    except:
        return False

@app.route('/api/messages', methods=['GET', 'POST', 'DELETE'])
@limiter.limit("2 per second")  # 限制每个IP每秒最多2个请求
def handle_messages():
    if request.method == 'GET':
        return jsonify(load_messages())
    
    elif request.method == 'POST':
        data = request.get_json()
        messages = load_messages()
        messages.insert(0, {
            'name': data['name'],
            'message': data['message'],
            'time': data['time']
        })
        save_messages(messages)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        token = request.headers.get('Authorization')
        if not token or not verify_token(token):
            return jsonify({'error': '未授权'}), 401
        
        data = request.get_json()
        messages = load_messages()
        messages = [m for m in messages if m['time'] != data['time']]
        save_messages(messages)
        return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True) 