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
import re

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

# 高德地图API配置
GAODE_KEY = "c32ab8b3137a1b492ae102b406dd94a1"

# 交通模式映射
TRANSPORT_MODES = {
    "transit": "公共交通",
    "driving": "自驾",
    "walking": "步行"
}

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

def get_geocode(address):
    """增强版地址解析"""
    url = "https://restapi.amap.com/v3/geocode/geo"
    params = {"address": address, "key": GAODE_KEY, "citylimit": "true"}
    try:
        response = requests.get(url, params=params, timeout=5)
        data = response.json()
        if data["status"] == "1" and data["count"] != "0":
            geo = data["geocodes"][0]
            if re.match(r"^\d+\.\d+,\d+\.\d+$", geo["location"]):
                return {
                    "formatted": geo["formatted_address"],
                    "location": geo["location"],
                    "adcode": geo["adcode"][:4]
                }
        return None
    except Exception as e:
        print(f"地址解析失败: {str(e)}")
        return None

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
@app.route('/map-guide', methods=['GET', 'POST'])
@login_required
def map_guide():
    navigation_result = None
    error_message = None
    
    if request.method == 'POST':
        start_address = request.form.get('start')
        end_address = request.form.get('end')
        mode = request.form.get('mode', 'transit')

        # 处理默认终点
        if not end_address:
            end_address = "浙江省杭州市西湖区国际会展中心"  # 默认终点设为会议地点

        start_info = get_geocode(start_address)
        end_info = get_geocode(end_address)
        
        if not all([start_info, end_info]):
            error_message = "地址解析失败，请尝试添加城市前缀（如：杭州西湖）"
            return render_template('map_guide.html', error_message=error_message)

        api_config = {
            "transit": {
                "url": "https://restapi.amap.com/v3/direction/transit/integrated",
                "params": {
                    "origin": start_info["location"],
                    "destination": end_info["location"],
                    "city": start_info["adcode"],
                    "cityd": end_info["adcode"],
                    "extensions": "all",
                    "key": GAODE_KEY
                }
            },
            "driving": {
                "url": "https://restapi.amap.com/v3/direction/driving",
                "params": {
                    "origin": start_info["location"],
                    "destination": end_info["location"],
                    "strategy": "0",
                    "extensions": "all",
                    "key": GAODE_KEY
                }
            },
            "walking": {
                "url": "https://restapi.amap.com/v3/direction/walking",
                "params": {
                    "origin": start_info["location"],
                    "destination": end_info["location"],
                    "key": GAODE_KEY
                }
            }
        }

        try:
            config = api_config[mode]
            response = requests.get(config["url"], params=config["params"], timeout=10)
            data = response.json()

            # 统一错误处理
            if (mode == "bicycle" and data.get("errcode") != 0) or \
               (mode != "bicycle" and data.get("status") != "1"):
                error_msg = data.get("errmsg") or data.get("info") or "未知错误"
                error_message = f"请求失败: {error_msg}"
                return render_template('map_guide.html', error_message=error_message)

            navigation_result = {
                "start": start_info["formatted"],
                "end": end_info["formatted"],
                "mode": TRANSPORT_MODES[mode],
                "distance": "",
                "duration": "",
                "steps": [],
                "origin_loc": start_info["location"],
                "destination_loc": end_info["location"]
            }

            if mode == "transit":
                transit = data["route"]["transits"][0]
                # 修复类型转换
                navigation_result["distance"] = f"{int(transit['distance'])/1000:.1f}公里"
                navigation_result["duration"] = f"{int(transit['duration'])/60:.1f}分钟"
                for segment in transit["segments"]:
                    if "walking" in segment:
                        walk_info = segment['walking']
                        instruction = walk_info.get('instruction', '步行路段')  # 添加默认值
                        navigation_result["steps"].append(f"🚶 {instruction}")
                    if "bus" in segment:
                        bus_lines = segment['bus']['buslines']
                        if bus_lines:
                            line_name = bus_lines[0].get('name', '未知线路')
                            departure = bus_lines[0].get('departure_stop', {}).get('name', '未知站点')
                            arrival = bus_lines[0].get('arrival_stop', {}).get('name', '未知站点')
                            navigation_result["steps"].append(f"🚌 乘坐{line_name} ({departure} → {arrival})")
                    if "railway" in segment:
                        railway = segment['railway']
                        if railway:
                            line_name = railway.get('name', '未知线路')
                            departure = railway.get('departure_stop', {}).get('name', '未知站点')
                            arrival = railway.get('arrival_stop', {}).get('name', '未知站点')
                            navigation_result["steps"].append(f"🚆 乘坐{line_name} ({departure} → {arrival})")
            else:
                path = data["route"]["paths"][0]
                navigation_result["distance"] = f"{int(path['distance'])/1000:.1f}公里"
                navigation_result["duration"] = f"{int(path['duration'])/60:.1f}分钟"
                navigation_result["steps"] = [f"➤ {step['instruction']}" for step in path["steps"]]

        except Exception as e:
            error_message = f"系统错误: {str(e)}"
            return render_template('map_guide.html', error_message=error_message)
    
    # 添加默认会议地点
    conference_location = {
        "name": "西湖数字安全峰会主会场",
        "address": "浙江省杭州市西湖区国际会展中心",
        "location": "120.123456,30.123456"  # 会议地点的实际坐标
    }
    
    return render_template('map_guide.html', navigation_result=navigation_result, 
                          conference_location=conference_location, error_message=error_message)

# 2. 问答系统 - 修复路由问题，确保endpoint与URL匹配
@app.route('/qa_system')  # 修改URL路径，去掉连字符
@login_required
def qa_system():  # 保持函数名不变
    return render_template('qa_system.html')

# 识别内容中的结构化字段
def extract_structured_fields(text):
    # 常见的结构化字段模式
    field_patterns = [
        (r'- 时间：([^\n]+)', '时间'),
        (r'主题：([^\n]+)', '主题'),
        (r'地点：([^\n]+)', '地点'),
        (r'推荐理由：([^\n]+)', '推荐理由'),
        (r'- 姓名：([^\n]+)', '姓名'),
        (r'- 背景：([^\n]+)', '背景'),
        (r'- 演讲主题：([^\n]+)', '演讲主题')
    ]
    
    extracted = {}
    for pattern, field_name in field_patterns:
        match = re.search(pattern, text)
        if match:
            # 提取字段值并清理
            value = match.group(1).strip()
            # 截断在第一个明显的乱码分隔符处
            for sep in ['-----', '____', '====', '····', '....', '----']:
                if sep in value:
                    value = value.split(sep)[0].strip()
            
            # 找到第一个连续4个以上非中文字符的位置（可能是乱码开始处）
            codes_start = re.search(r'[^\u4e00-\u9fa5\s,.;:，。、；：""''（）【】《》？！]{4,}', value)
            if codes_start:
                value = value[:codes_start.start()].strip()
            
            # 清理特殊字符
            value = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9，。、；：""''（）【】《》？！,.;:\'\"()\[\]{}<>?!@#$%^&*\-+=\s]', '', value)
            
            # 限制字段长度，避免过长
            max_lengths = {
                '时间': 30,
                '主题': 50,
                '地点': 30,
                '推荐理由': 200,  # 推荐理由可以稍长一些
                '姓名': 20,
                '背景': 200,
                '演讲主题': 100
            }
            
            if field_name in max_lengths:
                value = value[:max_lengths[field_name]]
            
            extracted[field_name] = value
    
    return extracted

# 超强乱码清理函数
def clean_text_completely(text):
    if not text:
        return ""
    
    # 检查是否包含结构化标题（如【日程推荐】）
    title_match = re.search(r'【[^】]+】', text)
    title = ""
    if title_match:
        title = title_match.group(0)
        # 提取标题后的内容
        text = text[title_match.end():].strip()
    
    # 处理不同类型的结构化内容
    if "【日程推荐】" in title:
        # 处理日程信息
        result_parts = [title]
        
        # 尝试识别日程项（通常以"- 时间："开头）
        schedule_blocks = re.split(r'(?=- 时间：)', text)
        
        for block in schedule_blocks:
            if not block.strip():
                continue
            
            # 提取结构化字段
            fields = extract_structured_fields(block)
            if fields:
                clean_block_parts = []
                
                # 按固定顺序构建干净的日程项
                if '时间' in fields:
                    clean_block_parts.append(f"- 时间：{fields['时间']}")
                if '主题' in fields:
                    clean_block_parts.append(f"主题：{fields['主题']}")
                if '地点' in fields:
                    clean_block_parts.append(f"地点：{fields['地点']}")
                if '推荐理由' in fields:
                    # 进一步处理推荐理由，可能包含多个句子
                    reason = fields['推荐理由']
                    sentences = re.split(r'([。！？])', reason)
                    clean_sentences = []
                    
                    # 重新组合句子和标点
                    i = 0
                    while i < len(sentences):
                        if i + 1 < len(sentences) and sentences[i+1] in ['。', '！', '？']:
                            clean_sentences.append(sentences[i] + sentences[i+1])
                            i += 2
                        else:
                            clean_sentences.append(sentences[i])
                            i += 1
                    
                    # 只保留有意义的中文句子
                    valid_sentences = []
                    for s in clean_sentences:
                        # 检查中文字符比例
                        chinese_chars = len(re.findall(r'[\u4e00-\u9fa5]', s))
                        if chinese_chars > 3 and chinese_chars / max(1, len(s)) > 0.3:
                            valid_sentences.append(s)
                    
                    # 最多保留前3个句子
                    if valid_sentences:
                        reason = ''.join(valid_sentences[:3])
                        clean_block_parts.append(f"推荐理由：{reason}")
                
                if clean_block_parts:  # 如果提取到了有效内容
                    result_parts.append("\n".join(clean_block_parts))
        
        return "\n\n".join(result_parts)
    
    elif "【嘉宾信息】" in title:
        # 处理嘉宾信息
        result_parts = [title]
        
        # 尝试识别嘉宾块（通常以"- 姓名："开头）
        guest_blocks = re.split(r'(?=- 姓名：)', text)
        
        for block in guest_blocks:
            if not block.strip():
                continue
            
            # 提取结构化字段
            fields = extract_structured_fields(block)
            if fields:
                clean_block_parts = []
                
                # 按固定顺序构建干净的嘉宾信息
                if '姓名' in fields:
                    clean_block_parts.append(f"- 姓名：{fields['姓名']}")
                if '背景' in fields:
                    # 进一步处理背景信息，保留有意义的部分
                    background = fields['背景']
                    # 提取首段有意义的描述
                    first_sentence_match = re.search(r'^([^，。]+[，。])?([^，。]+[，。])?([^，。]+[，。])?', background)
                    if first_sentence_match and first_sentence_match.group(0):
                        background = first_sentence_match.group(0).strip()
                    clean_block_parts.append(f"- 背景：{background}")
                if '演讲主题' in fields:
                    clean_block_parts.append(f"- 演讲主题：{fields['演讲主题']}")
                
                if clean_block_parts:  # 如果提取到了有效内容
                    result_parts.append("\n".join(clean_block_parts))
        
        return "\n\n".join(result_parts)
    else:
        # 处理普通文本内容
        # 首先按段落分割
        paragraphs = re.split(r'\n+', text)
        clean_paragraphs = []
        
        for para in paragraphs:
            # 找到连续特殊符号或明显乱码开始的位置
            code_start = re.search(r'[-_=\.]{3,}|[^\u4e00-\u9fa5a-zA-Z0-9，。、；：""''（）【】《》？！,.;:\'\"()\[\]{}<>?!@#$%^&*\-+=\s]{4,}', para)
            if code_start:
                para = para[:code_start.start()].strip()
            
            # 清理剩余文本中的特殊字符
            clean_para = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9，。、；：""''（）【】《》？！,.;:\'\"()\[\]{}<>?!@#$%^&*\-+=\s]', '', para)
            clean_para = re.sub(r'\s+', ' ', clean_para).strip()
            
            # 只保留包含足够中文的段落
            chinese_chars = len(re.findall(r'[\u4e00-\u9fa5]', clean_para))
            if chinese_chars > 3:  # 至少有3个中文字符
                clean_paragraphs.append(clean_para)
        
        # 如果有标题，加上标题
        result = "\n\n".join(clean_paragraphs)
        if title:
            result = title + "\n\n" + result
        
        return result

# 问答系统API端点 - 同样修改URL路径
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
        
        # 处理API响应
        if response.status_code == 200:
            api_response = response.json()
            
            # 处理会话消息，清理所有助手回复中的乱码
            if ("data" in api_response and 
                api_response["data"] is not None and 
                "session" in api_response["data"] and 
                "messages" in api_response["data"]["session"]):
                
                for i, message in enumerate(api_response["data"]["session"]["messages"]):
                    if "content" in message and message["role"] == "assistant":
                        # 对所有助手回复都使用最强的清理函数
                        api_response["data"]["session"]["messages"][i]["content"] = clean_text_completely(message["content"])
            
            return jsonify(api_response)
        else:
            return jsonify({"error": f"调用智能体API失败: {response.status_code}"}), 500
            
    except Exception as e:
        return jsonify({"error": f"发生错误: {str(e)}"}), 500

# 3. 参会指南
@app.route('/conference-guide')
@login_required
def conference_guide():
    return render_template('conference_guide.html')

# 4. 线上用户的会议亮点推荐
@app.route('/highlights')
@login_required
def highlights():
    return render_template('highlights.html')

# 5. 论坛关注度排行
@app.route('/forum-ranking')
@login_required
def forum_ranking():
    return render_template('forum_ranking.html')

# 6. 感兴趣的内容推荐
@app.route('/recommendations')
@login_required
def recommendations():
    return render_template('recommendations.html')

# 7. 相关资料下载入口指引
@app.route('/downloads')
@login_required
def downloads():
    return render_template('downloads.html')

# 8. 实时语音转文字、多语言翻译
@app.route('/translation')
@login_required
def translation():
    return render_template('translation.html')

# 9. 智能区分发言人会议要点自动总结
@app.route('/speaker-summary')
@login_required
def speaker_summary():
    return render_template('speaker_summary.html')

# 10. AI智能分析和总结
@app.route('/ai-summary')
@login_required
def ai_summary():
    return render_template('ai_summary.html')

# 11. 用户数据安全与隐私保护
@app.route('/privacy')
@login_required
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    app.run(debug=True)