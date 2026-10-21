"""A tiny built-in web dashboard, standard library only.

Serves one self-contained HTML page that polls ``/api/state`` every few seconds
and redraws the device list and the live event feed. No external libraries, no
build step - it works the moment the monitor starts.
"""

import json
import socketserver
from http.server import BaseHTTPRequestHandler


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # keep the console clean for the monitor's own output

        def do_GET(self):
            if self.path.startswith("/api/state"):
                body = json.dumps(state.snapshot()).encode("utf-8")
                self._send(body, "application/json")
            elif self.path in ("/", "/index.html"):
                self._send(PAGE.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._send(b"Not found", "text/plain", status=404)

        def _send(self, body, content_type, status=200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


class Dashboard(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(state, host="127.0.0.1", port=8787):
    server = Dashboard((host, port), make_handler(state))
    return server


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetWatch</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#273040;--text:#e6edf3;--muted:#8b98a9;
        --high:#f85149;--medium:#e3892f;--low:#539bf5;--info:#6b7684;--ok:#3fb950;--accent:#58a6ff;}
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);
       font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
  header{display:flex;align-items:center;gap:12px;padding:16px 22px;border-bottom:1px solid var(--line);}
  .logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#1f6feb,#3fb950);
        display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;}
  h1{font-size:18px;margin:0;letter-spacing:.3px;}
  header .sub{color:var(--muted);font-size:12px;}
  .live{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px;}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 rgba(63,185,80,.6);
       animation:pulse 2s infinite;}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5);}70%{box-shadow:0 0 0 7px rgba(63,185,80,0);}100%{box-shadow:0 0 0 0 rgba(63,185,80,0);}}
  main{max-width:1100px;margin:0 auto;padding:20px 22px 48px;}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px;}
  .tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;}
  .tile .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px;}
  .tile .v{font-size:28px;font-weight:700;margin-top:3px;}
  .tile .v small{font-size:13px;color:var(--muted);font-weight:500;}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin:24px 0 10px;}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;}
  table{width:100%;border-collapse:collapse;}
  th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle;}
  th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;}
  tr:last-child td{border-bottom:0;}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
  .pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:600;}
  .on{background:rgba(63,185,80,.15);color:var(--ok);}
  .off{background:rgba(139,152,169,.15);color:var(--muted);}
  .tag{display:inline-block;margin:0 4px 3px 0;padding:0 7px;border-radius:5px;border:1px solid var(--line);
       font-size:11px;font-family:ui-monospace,monospace;color:var(--muted);}
  .gw{color:var(--accent);font-size:11px;border:1px solid var(--accent);border-radius:5px;padding:0 6px;margin-left:6px;}
  .feed .row{display:flex;gap:12px;padding:11px 14px;border-bottom:1px solid var(--line);}
  .feed .row:last-child{border-bottom:0;}
  .sev{width:8px;border-radius:4px;flex:none;}
  .sev.high{background:var(--high);} .sev.medium{background:var(--medium);}
  .sev.low{background:var(--low);} .sev.info{background:var(--info);}
  .badge{font-size:10px;font-weight:700;text-transform:uppercase;padding:1px 6px;border-radius:5px;}
  .badge.high{background:rgba(248,81,73,.15);color:var(--high);} .badge.medium{background:rgba(227,137,47,.15);color:var(--medium);}
  .badge.low{background:rgba(83,155,245,.15);color:var(--low);} .badge.info{background:rgba(107,118,132,.18);color:var(--info);}
  .feed .title{font-weight:600;}
  .feed .detail{color:var(--muted);font-size:12.5px;margin-top:2px;}
  .feed .when{color:var(--muted);font-size:11px;white-space:nowrap;margin-left:auto;}
  .empty{padding:26px;text-align:center;color:var(--muted);}
  .cols{display:grid;grid-template-columns:1fr;gap:22px;}
  @media(min-width:860px){.cols{grid-template-columns:1.1fr .9fr;}}
  footer{color:var(--muted);font-size:11px;margin-top:26px;text-align:center;}
</style></head>
<body>
<header>
  <div class="logo">N</div>
  <div><h1>NetWatch</h1><div class="sub" id="sub">watching your network</div></div>
  <div class="live"><span class="dot"></span><span id="live">live</span></div>
</header>
<main>
  <div class="tiles">
    <div class="tile"><div class="k">Devices online</div><div class="v"><span id="t-online">-</span><small> / <span id="t-total">-</span> known</small></div></div>
    <div class="tile"><div class="k">High alerts</div><div class="v" style="color:var(--high)" id="t-high">-</div></div>
    <div class="tile"><div class="k">Medium</div><div class="v" style="color:var(--medium)" id="t-med">-</div></div>
    <div class="tile"><div class="k">Scans run</div><div class="v" id="t-scans">-</div></div>
    <div class="tile"><div class="k">Watching</div><div class="v" style="font-size:18px" id="t-target">-</div></div>
  </div>

  <div class="cols">
    <section>
      <h2>Devices</h2>
      <div class="panel"><table>
        <thead><tr><th>Address</th><th>Name / vendor</th><th>Open ports</th><th>Status</th></tr></thead>
        <tbody id="devices"></tbody>
      </table><div class="empty" id="dev-empty" style="display:none">No devices seen yet - first scan running...</div></div>
    </section>
    <section>
      <h2>Live event feed</h2>
      <div class="panel feed" id="feed"></div>
    </section>
  </div>
  <footer>NetWatch - passive network security monitor. Only watch networks you own or manage.</footer>
</main>
<script>
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function ago(ts){if(!ts)return "-";const s=Math.max(0,Math.round(Date.now()/1000-ts));
  if(s<60)return s+"s ago";if(s<3600)return Math.round(s/60)+"m ago";if(s<86400)return Math.round(s/3600)+"h ago";return Math.round(s/86400)+"d ago";}
function dur(s){if(s<60)return s+"s";if(s<3600)return Math.round(s/60)+"m";return Math.round(s/3600)+"h";}
async function tick(){
  let d; try{d=await (await fetch('/api/state',{cache:'no-store'})).json();}catch(e){document.getElementById('live').textContent='reconnecting...';return;}
  document.getElementById('live').textContent='live';
  document.getElementById('t-online').textContent=d.online;
  document.getElementById('t-total').textContent=d.devices.length;
  document.getElementById('t-high').textContent=d.event_counts.high||0;
  document.getElementById('t-med').textContent=d.event_counts.medium||0;
  document.getElementById('t-scans').textContent=d.scans;
  document.getElementById('t-target').textContent=(d.meta&&d.meta.target)||'-';
  document.getElementById('sub').textContent='uptime '+dur(d.uptime_s)+' · last scan '+ago(d.last_scan);
  const tb=document.getElementById('devices');
  document.getElementById('dev-empty').style.display=d.devices.length?'none':'block';
  tb.innerHTML=d.devices.map(x=>{
    const ports=(x.open_ports||[]).map(p=>'<span class="tag">'+p+'</span>').join('')||'<span style="color:var(--muted)">none</span>';
    const name=esc(x.hostname||x.vendor||'')||'<span style="color:var(--muted)">unknown</span>';
    const gw=x.is_gateway?'<span class="gw">gateway</span>':'';
    const me=x.is_this_computer?'<span class="gw" style="border-color:var(--muted);color:var(--muted)">this PC</span>':'';
    const st=x.online?'<span class="pill on">online</span>':'<span class="pill off">offline</span>';
    return '<tr><td class="mono">'+esc(x.ip)+gw+me+'<div style="color:var(--muted);font-size:11px" class="mono">'+esc(x.mac||'')+'</div></td>'+
           '<td>'+name+'</td><td>'+ports+'</td><td>'+st+'</td></tr>';
  }).join('');
  const feed=document.getElementById('feed');
  if(!d.events.length){feed.innerHTML='<div class="empty">No events yet. NetWatch will post here when something changes on the network.</div>';}
  else{feed.innerHTML=d.events.map(e=>
    '<div class="row"><div class="sev '+e.severity+'"></div><div style="flex:1">'+
    '<div><span class="badge '+e.severity+'">'+e.severity+'</span> <span class="title">'+esc(e.title)+'</span></div>'+
    '<div class="detail">'+esc(e.detail)+'</div></div>'+
    '<div class="when">'+ago(e.ts)+'</div></div>').join('');}
}
tick();setInterval(tick,4000);
</script>
</body></html>
"""
