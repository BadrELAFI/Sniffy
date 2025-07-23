from flask import Flask 
from flask_socketio import SocketIO
from threading import Thread 
from sniff import capture_packets


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route("/")

def hello():
    return "Backend is running"

def emit_packet(packet):
    socketio.emit("packet", packet)

def run_sniffer():
    capture_packets(emit_packet)

if __name__ == "__main__":
    Thread(target=run_sniffer).start()
    socketio.run(app, host='0.0.0.0', port=5000)
