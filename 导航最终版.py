from flask import Flask, request, render_template_string
import requests
import re

app = Flask(__name__)
GAODE_KEY = "c32ab8b3137a1b492ae102b406dd94a1"  # 确认密钥有效性

TRANSPORT_MODES = {
    "transit": "公共交通",
    "driving": "自驾",
    "walking": "步行"
}

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

@app.route('/', methods=['GET', 'POST'])
def navigation():
    if request.method == 'POST':
        start_address = request.form.get('start')
        end_address = request.form.get('end')
        mode = request.form.get('mode', 'transit')

        start_info = get_geocode(start_address)
        end_info = get_geocode(end_address)
        
        if not all([start_info, end_info]):
            return "地址解析失败，请尝试添加城市前缀（如：北京天安门）"

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
                return f"请求失败: {error_msg}"

            result = {
                "start": start_info["formatted"],
                "end": end_info["formatted"],
                "mode": TRANSPORT_MODES[mode],
                "distance": "",
                "duration": "",
                "steps": []
            }

            if mode == "transit":
                transit = data["route"]["transits"][0]
                # 修复类型转换
                result["distance"] = f"{int(transit['distance'])/1000:.1f}公里"
                result["duration"] = f"{int(transit['duration'])/60:.1f}分钟"
                for segment in transit["segments"]:
                    if "walking" in segment:
                        walk_info = segment['walking']
                        instruction = walk_info.get('instruction', '步行路段')  # 添加默认值
                        result["steps"].append(f"🚶 {instruction}")
                    if "bus" in segment:
                        bus_lines = segment['bus']['buslines']
                        if bus_lines:
                            line_name = bus_lines[0].get('name', '未知线路')
                            departure = bus_lines[0].get('departure_stop', '未知站点')
                            arrival = bus_lines[0].get('arrival_stop', '未知站点')
                            result["steps"].append(f"🚌 乘坐{line_name} ({departure} → {arrival})")
            elif mode == "bicycle":
                bicycle = data["data"]["paths"][0]
                result["distance"] = f"{int(bicycle['distance'])/1000:.1f}公里"
                result["duration"] = f"{int(bicycle['duration'])/60:.1f}分钟"
                result["steps"] = [f"🚴 {step['instruction']}" for step in bicycle["steps"]]
            else:
                path = data["route"]["paths"][0]
                result["distance"] = f"{int(path['distance'])/1000:.1f}公里"
                result["duration"] = f"{int(path['duration'])/60:.1f}分钟"
                result["steps"] = [f"➤ {step['instruction']}" for step in path["steps"]]

            return render_template_string(RESULT_TEMPLATE, **result)

        except Exception as e:
            return f"系统错误: {str(e)}"
    
    return render_template_string(FORM_TEMPLATE)

# 前端模板
FORM_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>智能会议导航</title>
    <style>
        body { max-width: 600px; margin: 20px auto; padding: 20px; }
        .nav-box { background: #f8f9fa; padding: 25px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        input, select { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #007bff; color: white; border: none; padding: 12px 25px; border-radius: 5px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="nav-box">
        <h2>会议场地导航系统</h2>
        <form method="POST">
            <input type="text" name="start" placeholder="请输入起点（如：北京西站）" required>
            <input type="text" name="end" placeholder="请输入终点（如：国家会议中心）" required>
            <select name="mode">
                <option value="transit">公共交通</option>
                <option value="driving">自驾</option>
                <option value="walking">步行</option>
            </select>
            <button type="submit">开始导航</button>
        </form>
    </div>
</body>
</html>
"""

RESULT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>导航结果</title>
    <style>
        body { max-width: 600px; margin: 20px auto; padding: 20px; }
        .result-box { background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .info-item { margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .steps { margin-top: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="result-box">
        <h2>导航结果</h2>
        <div class="info-item">
            <p>🚩 起点：{{ start }}</p>
            <p>🏁 终点：{{ end }}</p>
            <p>🚗 交通方式：{{ mode }}</p>
        </div>
        <div class="info-item">
            <p>📏 距离：{{ distance }}</p>
            <p>⏱ 预计耗时：{{ duration }}</p>
        </div>
        <div class="steps">
            <h3>详细路线指引：</h3>
            {% for step in steps %}
                <p>{{ step }}</p>
            {% endfor %}
        </div>
        <a href="/" style="display: inline-block; margin-top: 20px;">返回重新查询</a>
    </div>
</body>
</html>
"""
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
