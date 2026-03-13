import multiprocessing
import threading
import uvicorn
import asyncio
import json
import socket
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import our core modules
from core.ingestion_server import run_ingestion
from core.feature_engineer import run_feature_engineering
from core.inference_engine import run_inference

# --- CONFIGURATION ---
HOST_IP = "0.0.0.0"
PORT = 8000
DEBUG_MODE = True 

# --- TERMINAL COLORS ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

# ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# --- GLOBAL QUEUES ---
packet_queue = multiprocessing.Queue()
feature_queue = multiprocessing.Queue()
result_queue = multiprocessing.Queue()

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        if DEBUG_MODE:
            print(f"{Colors.GREEN}[WS] Client connected. Total: {len(self.active_connections)}{Colors.ENDC}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if DEBUG_MODE:
            print(f"{Colors.YELLOW}[WS] Client disconnected{Colors.ENDC}")

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                self.disconnect(connection)

manager = ConnectionManager()

# --- BACKGROUND WORKER ---
def result_monitor(loop, result_q, ws_manager):
    print(f"{Colors.CYAN}[Main] Result Monitor started.{Colors.ENDC}")
    
    while True:
        try:
            data = result_q.get()
            

            if DEBUG_MODE:
                sev = data['severity']
                prob = data['probability']
                key = data['flow_key']

                if sev == "HIGH":
                    msg = f"{Colors.RED}{Colors.BOLD}[ALERT] {key} | PROB: {prob:.2f} | SEVERITY: {sev}{Colors.ENDC}"
                elif sev == "MEDIUM":
                    msg = f"{Colors.YELLOW}[WARN]  {key} | PROB: {prob:.2f} | SEVERITY: {sev}{Colors.ENDC}"
                else:
                    msg = f"{Colors.GREEN}[INFO]  {key} | PROB: {prob:.2f} | SEVERITY: {sev}{Colors.ENDC}"
                
                print(msg)
            
            # push to WebSocket
            future = asyncio.run_coroutine_threadsafe(ws_manager.broadcast(data), loop)
            future.result(timeout=1)
            
        except Exception as e:
            print(f"{Colors.RED}[Main] Monitor Error: {e}{Colors.ENDC}")

# -Startup/Shutdown ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # START PROCESSES
    print(f"{Colors.HEADER}--- ETA-DOH CORE STARTING ---{Colors.ENDC}")
    
    p1 = multiprocessing.Process(target=run_ingestion, args=(packet_queue,), daemon=True)
    p2 = multiprocessing.Process(target=run_feature_engineering, args=(packet_queue, feature_queue), daemon=True)
    p3 = multiprocessing.Process(target=run_inference, args=(feature_queue, result_queue), daemon=True)
    
    for p in [p1, p2, p3]:
        p.start()
    
    # START MONITOR THREAD
    loop = asyncio.get_event_loop()
    threading.Thread(target=result_monitor, args=(loop, result_queue, manager), daemon=True).start()
    
    local_ip = get_local_ip()
    print(f"\n{Colors.BOLD}{Colors.GREEN}>> SYSTEM READY <<{Colors.ENDC}")
    print(f"Dashboard accessible at: {Colors.CYAN}{Colors.UNDERLINE}http://{local_ip}:{PORT}{Colors.ENDC}\n")
    
    yield
    
    print(f"\n{Colors.RED}--- SHUTTING DOWN ---{Colors.ENDC}")
    for p in [p1, p2, p3]:
        p.terminate()

# --- FASTAPI webiste ---
app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="ui"), name="static")
templates = Jinja2Templates(directory="ui")

@app.get("/")
async def get_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host=HOST_IP, port=PORT, log_level="error") 
# suppressed uvicorn noise to keep clean
