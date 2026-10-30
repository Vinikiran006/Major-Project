import socket
import json
import ctypes
import os
import sys
import threading
import csv
import io
import time
from datetime import datetime
from collections import Counter, deque
from flask import Flask, jsonify, Response, render_template_string

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ascon

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
HOST = "0.0.0.0"
PORT = 5000                 # ESP32 TCP receiver
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8000       # Open http://127.0.0.1:8000 on the laptop

AES_KEY = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
ASCON_KEY = AES_KEY
GIFT_KEY = AES_KEY
AAD = b"ESP32-DHT22-v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GIFT_DLL_PATH = os.path.join(BASE_DIR, "giftcofb.dll")
if not os.path.isfile(GIFT_DLL_PATH):
    raise FileNotFoundError(f"GIFT DLL not found: {GIFT_DLL_PATH}")

gift = ctypes.CDLL(GIFT_DLL_PATH)
U8P = ctypes.POINTER(ctypes.c_ubyte)
ULLP = ctypes.POINTER(ctypes.c_ulonglong)
gift.giftcofb_crypto_aead_decrypt.argtypes = [
    U8P, ULLP, U8P, U8P, ctypes.c_ulonglong,
    U8P, ctypes.c_ulonglong, U8P, U8P
]
gift.giftcofb_crypto_aead_decrypt.restype = ctypes.c_int

app = Flask(__name__)
events_lock = threading.Lock()
events = deque(maxlen=2000)
stats = {
    "received": 0,
    "success": 0,
    "rejected": 0,
    "start_time": time.time(),
    "last_seen": None,
}
algo_counts = Counter()
# In-memory data is for the current app session. Use Export CSV to save it.


def as_c_buffer(data):
    if not data:
        return None
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def decrypt_gift(ciphertext, nonce, aad, key):
    if len(nonce) != 16:
        raise ValueError("Invalid GIFT nonce length")
    if len(key) != 16:
        raise ValueError("Invalid GIFT key length")
    if len(ciphertext) < 16:
        raise ValueError("GIFT ciphertext is missing its tag")

    output = (ctypes.c_ubyte * len(ciphertext))()
    output_len = ctypes.c_ulonglong(0)
    result = gift.giftcofb_crypto_aead_decrypt(
        output,
        ctypes.byref(output_len),
        None,
        as_c_buffer(ciphertext),
        len(ciphertext),
        as_c_buffer(aad),
        len(aad),
        as_c_buffer(nonce),
        as_c_buffer(key),
    )
    if result != 0:
        raise ValueError("GIFT authentication failed")
    if output_len.value > len(output):
        raise ValueError("Invalid GIFT plaintext length")
    return bytes(output[:output_len.value])


def decrypt_message(message):
    algorithm = message.get("algorithm")

    if algorithm == "AES-128-GCM":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        tag = bytes.fromhex(message["tag"])
        aad = message.get("aad", AAD.decode()).encode()
        if len(nonce) != 12:
            raise ValueError("Invalid AES nonce length")
        if len(tag) != 16:
            raise ValueError("Invalid AES authentication tag length")
        plaintext = AESGCM(AES_KEY).decrypt(nonce, ciphertext + tag, aad)

    elif algorithm == "ASCON-AEAD128":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        aad = message.get("aad", AAD.decode()).encode()
        if len(nonce) != 16:
            raise ValueError("Invalid ASCON nonce length")
        if len(ciphertext) < 16:
            raise ValueError("ASCON ciphertext is missing its tag")
        plaintext = ascon.ascon_decrypt(
            ASCON_KEY, nonce, aad, ciphertext,
            variant="Ascon-AEAD128"
        )
        if plaintext is None:
            raise ValueError("ASCON authentication failed")

    elif algorithm == "GIFT-COFB-128":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        aad = message.get("aad", AAD.decode()).encode()
        plaintext = decrypt_gift(ciphertext, nonce, aad, GIFT_KEY)

    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

    return json.loads(plaintext.decode("utf-8"))


def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def process_message(message, peer):
    start = time.perf_counter()
    algorithm = message.get("algorithm", "Unknown")
    device = message.get("device_id", "Unknown")
    sensor = {}
    status = "PASS"
    error_text = ""
    try:
        sensor = decrypt_message(message)
    except Exception as exc:
        status = "REJECTED"
        error_text = str(exc)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    now = datetime.now().astimezone().isoformat(timespec="seconds")

    event = {
        "timestamp": now,
        "device": device,
        "algorithm": algorithm,
        "status": status,
        "authentication": "PASS" if status == "PASS" else "FAIL",
        "decryption": "PASS" if status == "PASS" else "FAIL",
        "temperature": safe_float(sensor.get("temperature")) if status == "PASS" else None,
        "humidity": safe_float(sensor.get("humidity")) if status == "PASS" else None,
        # This is receiver-side processing time, not ESP32 encryption latency.
        "receiver_processing_ms": round(elapsed_ms, 4),
        "error": error_text,
        "peer": peer,
    }

    with events_lock:
        stats["received"] += 1
        stats["last_seen"] = now
        if status == "PASS":
            stats["success"] += 1
            algo_counts[algorithm] += 1
        else:
            stats["rejected"] += 1
        events.appendleft(event)

    print(f"\n[{now}] Message from {peer}")
    print("Device:", device)
    print("Algorithm:", algorithm)
    print("Authentication:", event["authentication"])
    print("Decryption:", event["decryption"])
    if status == "PASS":
        print("Recovered sensor data:", json.dumps(sensor))
    else:
        print("Authentication/decryption: REJECTED")
        print("Reason:", error_text)


def receiver_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
        server.listen(10)
        print(f"Secure IoT receiver listening on port {PORT}")
        print("Supported algorithms: AES-128-GCM, ASCON-AEAD128, GIFT-COFB-128")
        print(f"Dashboard: http://127.0.0.1:{DASHBOARD_PORT}")
        while True:
            conn, addr = server.accept()
            with conn:
                buffer = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buffer += data
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            message = json.loads(line.decode("utf-8"))
                            process_message(message, f"{addr[0]}:{addr[1]}")
                        except Exception as exc:
                            print("Invalid incoming message:", str(exc))
                if buffer.strip():
                    try:
                        message = json.loads(buffer.decode("utf-8"))
                        process_message(message, f"{addr[0]}:{addr[1]}")
                    except Exception as exc:
                        print("Invalid final message:", str(exc))
    except OSError as exc:
        print(f"Receiver socket error: {exc}")
    finally:
        server.close()


HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Adaptive IoT Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--panel2:#18233b;--text:#eef3ff;--muted:#9aa8c7;--line:#283653;--teal:#35d0b0;--blue:#68a7ff;--amber:#f3bd58;--red:#ff6e7d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#17294b 0,#0b1020 44%);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}
.wrap{max-width:1400px;margin:auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:22px}
.eyebrow{color:var(--teal);font-size:12px;font-weight:800;letter-spacing:2px;text-transform:uppercase}.title{font-size:clamp(26px,4vw,38px);font-weight:800;margin:7px 0}.sub{color:var(--muted);font-size:14px}
.live{display:flex;align-items:center;gap:9px;border:1px solid #23675f;background:#10352f;color:#9af1df;border-radius:999px;padding:10px 14px;font-size:13px;font-weight:700}.dot{width:8px;height:8px;background:var(--teal);border-radius:50%;box-shadow:0 0 12px var(--teal)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,rgba(24,35,59,.96),rgba(17,25,44,.96));border:1px solid var(--line);border-radius:18px;padding:19px;min-width:0;box-shadow:0 12px 30px #0002}.label{color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.7px;text-transform:uppercase}.metric{font-size:32px;font-weight:800;margin:12px 0 5px;letter-spacing:-1px}.hint{font-size:12px;color:var(--muted)}.good{color:var(--teal)}.blue{color:var(--blue)}.amber{color:var(--amber)}.red{color:var(--red)}
.main{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;margin-top:14px}.card h2{font-size:16px;margin:0 0 17px}.chartbox{height:250px;position:relative}.algo-list{display:grid;gap:14px}.algo-head{display:flex;justify-content:space-between;gap:12px;font-size:13px;margin-bottom:7px}.bar{height:9px;background:#26334e;border-radius:20px;overflow:hidden}.fill{height:100%;border-radius:20px;transition:width .4s}.fill.aes{background:var(--blue)}.fill.ascon{background:var(--teal)}.fill.gift{background:var(--amber)}
.lower{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.tablewrap{overflow:auto;max-height:360px}table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}th{text-align:left;color:var(--muted);font-weight:700;padding:11px 9px;border-bottom:1px solid var(--line)}td{padding:12px 9px;border-bottom:1px solid #26334e}tr:last-child td{border-bottom:0}.pill{display:inline-block;padding:5px 8px;border-radius:99px;font-size:11px;font-weight:800;background:#123c34;color:#8cf0d7}.pill.fail{background:#4a202b;color:#ff9da7}.btn{background:var(--teal);color:#06221e;border:0;padding:11px 15px;border-radius:10px;font-weight:800;cursor:pointer;text-decoration:none;font-size:13px}.btn.secondary{background:#253450;color:var(--text);border:1px solid #354767}.actions{display:flex;gap:9px;flex-wrap:wrap}.footer{color:var(--muted);font-size:11px;margin:17px 3px 0;line-height:1.6}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.main,.lower{grid-template-columns:1fr}}@media(max-width:480px){.wrap{padding:15px}.grid{gap:9px}.card{padding:14px}.metric{font-size:26px}}
</style>
</head>
<body><div class="wrap">
<header class="top">
 <div><div class="eyebrow">IoT · Adaptive Cryptography</div><div class="title">Security Operations Dashboard</div><div class="sub">ESP32 + DHT22 · AES-GCM · ASCON · GIFT-COFB</div></div>
 <div class="actions"><div class="live"><span class="dot"></span><span id="connection">Waiting for device data</span></div><a class="btn" href="/export.csv">Export CSV</a></div>
</header>
<section class="grid">
 <div class="card"><div class="label">Temperature</div><div class="metric" id="temp">— °C</div><div class="hint">Latest authenticated reading</div></div>
 <div class="card"><div class="label">Humidity</div><div class="metric" id="humidity">—%</div><div class="hint">Latest authenticated reading</div></div>
 <div class="card"><div class="label">Messages received</div><div class="metric" id="received">0</div><div class="hint"><span class="good" id="success">0 successful</span> · <span class="red" id="rejected">0 rejected</span></div></div>
 <div class="card"><div class="label">Authentication success</div><div class="metric good" id="rate">—%</div><div class="hint">Successful / received messages</div></div>
</section>
<section class="main">
 <div class="card"><h2>Receiver processing time</h2><div class="chartbox"><canvas id="latencyChart"></canvas></div><div class="hint">Measured on the laptop: authentication + decryption + JSON parsing. Not ESP32 encryption latency.</div></div>
 <div class="card"><h2>Algorithm selection distribution</h2><div class="algo-list" id="algoList">
  <div class="hint">Waiting for successful messages…</div>
 </div><div style="height:16px"></div><h2>Latest message</h2><div class="hint" id="latest">No messages received yet.</div></div>
</section>
<section class="lower">
 <div class="card"><h2>Recent sensor readings</h2><div class="chartbox"><canvas id="sensorChart"></canvas></div></div>
 <div class="card"><h2>Recent security events <span class="hint" id="eventCount"></span></h2><div class="tablewrap"><table><thead><tr><th>Time</th><th>Algorithm</th><th>Auth</th><th>Decrypt</th><th>Rx ms</th></tr></thead><tbody id="events"><tr><td colspan="5" class="hint">Waiting for messages…</td></tr></tbody></table></div></div>
</section>
<div class="footer">Demonstration mode: context values generated by the ESP32 are simulated. Dashboard statistics reset when this Python process restarts. Keep the demo key private and do not use this hardcoded key in production.</div>
</div>
<script>
Chart.defaults.color = '#9aa8c7';
Chart.defaults.borderColor = '#283653';
const latencyChart = new Chart(document.getElementById('latencyChart'), {
 type:'line', data:{labels:[],datasets:[{label:'Receiver processing (ms)',data:[],borderColor:'#35d0b0',backgroundColor:'#35d0b022',fill:true,tension:.28,pointRadius:2}]},
 options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}},scales:{x:{ticks:{maxTicksLimit:6}},y:{beginAtZero:true,title:{display:true,text:'Milliseconds'}}}}
});
const sensorChart = new Chart(document.getElementById('sensorChart'), {
 type:'line', data:{labels:[],datasets:[
 {label:'Temperature °C',data:[],borderColor:'#68a7ff',tension:.25,pointRadius:1,yAxisID:'y'},
 {label:'Humidity %',data:[],borderColor:'#f3bd58',tension:.25,pointRadius:1,yAxisID:'y1'}]},
 options:{responsive:true,maintainAspectRatio:false,animation:false,interaction:{mode:'index',intersect:false},
 scales:{x:{ticks:{maxTicksLimit:6}},y:{position:'left',title:{display:true,text:'°C'}},y1:{position:'right',title:{display:true,text:'%'},grid:{drawOnChartArea:false}}}}
});
function pct(n,d){return d?((n/d)*100).toFixed(1):'0.0'}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function refresh(){
 try{
  const r=await fetch('/api/data',{cache:'no-store'}); const d=await r.json();
  const s=d.stats, list=d.events, success=list.filter(e=>e.status==='PASS');
  document.getElementById('received').textContent=s.received;
  document.getElementById('success').textContent=s.success+' successful';
  document.getElementById('rejected').textContent=s.rejected+' rejected';
  document.getElementById('rate').textContent=pct(s.success,s.received)+'%';
  document.getElementById('connection').textContent=s.last_seen?'Receiving live data':'Waiting for device data';
  document.getElementById('connection').parentElement.style.borderColor=s.last_seen?'#23675f':'#66522d';
  const latest=success[0];
  document.getElementById('temp').textContent=latest?.temperature!=null?latest.temperature.toFixed(1)+' °C':'— °C';
  document.getElementById('humidity').textContent=latest?.humidity!=null?latest.humidity.toFixed(1)+'%':'—%';
  document.getElementById('latest').innerHTML=latest
    ? `<b>${esc(latest.algorithm)}</b> · ${esc(latest.timestamp)}<br>Auth: <span class="good">PASS</span> · Decryption: <span class="good">PASS</span><br>Receiver processing: ${latest.receiver_processing_ms.toFixed(4)} ms`
    : 'No successfully decrypted messages yet.';
  const counts={}; success.forEach(e=>counts[e.algorithm]=(counts[e.algorithm]||0)+1);
  const total=Object.values(counts).reduce((a,b)=>a+b,0);
  const items=[['AES-128-GCM','aes'],['ASCON-AEAD128','ascon'],['GIFT-COFB-128','gift']];
  document.getElementById('algoList').innerHTML=items.map(([name,cls])=>{
    const n=counts[name]||0, p=total?n/total*100:0;
    return `<div><div class="algo-head"><span>${name}</span><b>${n} · ${p.toFixed(1)}%</b></div><div class="bar"><div class="fill ${cls}" style="width:${p}%"></div></div></div>`;
  }).join('');
  const recent=list.slice(0,50).reverse();
  latencyChart.data.labels=recent.map(e=>e.timestamp.split('T').pop());
  latencyChart.data.datasets[0].data=recent.map(e=>e.receiver_processing_ms);
  latencyChart.update('none');
  const sens=success.filter(e=>e.temperature!=null&&e.humidity!=null).slice(0,50).reverse();
  sensorChart.data.labels=sens.map(e=>e.timestamp.split('T').pop());
  sensorChart.data.datasets[0].data=sens.map(e=>e.temperature);
  sensorChart.data.datasets[1].data=sens.map(e=>e.humidity);
  sensorChart.update('none');
  document.getElementById('events').innerHTML=list.slice(0,30).map(e=>`<tr>
   <td>${esc(e.timestamp.split('T').pop())}</td><td>${esc(e.algorithm)}</td>
   <td><span class="pill ${e.authentication==='PASS'?'':'fail'}">${esc(e.authentication)}</span></td>
   <td><span class="pill ${e.decryption==='PASS'?'':'fail'}">${esc(e.decryption)}</span></td>
   <td>${Number(e.receiver_processing_ms).toFixed(4)}</td></tr>`).join('')||'<tr><td colspan="5">Waiting for messages…</td></tr>';
  document.getElementById('eventCount').textContent='('+list.length+' shown)';
 }catch(e){document.getElementById('connection').textContent='Dashboard API reconnecting';}
}
refresh();setInterval(refresh,1500);
</script>
</body></html>
"""


@app.route("/")
def dashboard():
    return render_template_string(HTML)


@app.route("/api/data")
def api_data():
    with events_lock:
        snapshot = list(events)
        stat_copy = dict(stats)
    return jsonify({"stats": stat_copy, "events": snapshot})


@app.route("/export.csv")
def export_csv():
    with events_lock:
        rows = list(events)
    output = io.StringIO()
    fields = [
        "timestamp", "device", "algorithm", "status", "authentication",
        "decryption", "temperature", "humidity", "receiver_processing_ms",
        "peer", "error"
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    # Export oldest-to-newest for easier analysis.
    for row in reversed(rows):
        writer.writerow(row)
    filename = f"iot_performance_{datetime.now():%Y%m%d_%H%M%S}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


if __name__ == "__main__":
    t = threading.Thread(target=receiver_server, daemon=True)
    t.start()
    print(f"Open dashboard at http://127.0.0.1:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, threaded=True)
