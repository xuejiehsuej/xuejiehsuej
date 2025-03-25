from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import config
import os
import requests
import hmac
import hashlib
import base64
import time

app = Flask(__name__)
app.config.from_object(config[os.environ.get('FLASK_ENV') or 'default'])

# 示例用户数据 - 在实际应用中应使用数据库
users = {
    'admin': {
        'password': generate_password_hash('admin123'),
        'name': '管理员'
    },
    'user': {
        'password': generate_password_hash('user123'),
        'name': '普通用户'
    }
}

# 智能体API配置
DAS_APP_KEY = "hengnaoSxWXpETuk1tFoR4UhLK9"
DAS_APP_SECRET = "o8tm2z5lrlx1txawleemde5ls5d4413q"
DAS_AGENT_API_URL = "https://www.das-ai.com/open/api/v2/agent/execute"

def get_sign(key, secret):
    timestamp = int(time.time() * 1000)
    data = f"{timestamp}\n{secret}\n{key}"
    hmac_sha256 = hmac.new(secret.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
    sign = hmac_sha256.digest()
    return f"{timestamp}{base64.b64encode(sign).decode('utf-8')}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['name'] = users[username]['name']
            session.permanent = True
            flash(f'欢迎回来, {users[username]["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('name', None)
    flash('您已成功退出', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=session.get('name', '用户'))

# 1. 线下参会用户的地图指引
@app.route('/map-guide')
@login_required
def map_guide():
    return render_template('features/map_guide.html')

# 2. 问答系统
@app.route('/qa-system')
@login_required
def qa_system():
    return render_template('features/qa_system.html')

# 问答系统API端点
@app.route('/api/ask', methods=['POST'])
@login_required
def ask_agent():
    try:
        # 获取前端发送的数据
        data = request.json
        user_input = data.get('input')
        session_id = data.get('sid', "3a790a6a-1dca-4243-a356-0005fe956cec")
        
        # 生成签名
        sign = get_sign(DAS_APP_KEY, DAS_APP_SECRET)
        
        # 调用智能体API
        response = requests.post(
            DAS_AGENT_API_URL,
            headers={
                "appKey": DAS_APP_KEY,
                "sign": sign,
                "Content-Type": "application/json"
            },
            json={
                "id": "ad8c7a3e-18c5-472a-94ad-ea0e5972c00e",
                "inputs": {"input": user_input},
                "sid": session_id
            }
        )
        
        # 将智能体API的响应返回给前端
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": f"调用智能体API失败: {response.status_code}"}), 500
            
    except Exception as e:
        return jsonify({"error": f"发生错误: {str(e)}"}), 500

# 3. 参会指南
@app.route('/conference-guide')
@login_required
def conference_guide():
    return render_template('features/conference_guide.html')

# 4. 线上用户的会议亮点推荐
@app.route('/highlights')
@login_required
def highlights():
    return render_template('features/highlights.html')

# 5. 论坛关注度排行
@app.route('/forum-ranking')
@login_required
def forum_ranking():
    return render_template('features/forum_ranking.html')

# 6. 感兴趣的内容推荐
@app.route('/recommendations')
@login_required
def recommendations():
    return render_template('features/recommendations.html')

# 7. 相关资料下载入口指引
@app.route('/downloads')
@login_required
def downloads():
    return render_template('features/downloads.html')

# 8. 实时语音转文字、多语言翻译
@app.route('/translation')
@login_required
def translation():
    return render_template('features/translation.html')

# 9. 智能区分发言人会议要点自动总结
@app.route('/speaker-summary')
@login_required
def speaker_summary():
    return render_template('features/speaker_summary.html')

# 10. AI智能分析和总结
@app.route('/ai-summary')
@login_required
def ai_summary():
    return render_template('features/ai_summary.html')

# 11. 用户数据安全与隐私保护
@app.route('/privacy')
@login_required
def privacy():
    return render_template('features/privacy.html')

if __name__ == '__main__':
    app.run(debug=True)
