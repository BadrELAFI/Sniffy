const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');
contextBridge.exposeInMainWorld('electronAPI', {
  startSniffing: (pythonPath) => ipcRenderer.invoke('start-sniffing', pythonPath),
  stopSniffing: () => ipcRenderer.invoke('stop-sniffing'),
  getSniffingStatus: () => ipcRenderer.invoke('get-sniffing-status'),
  savePackets: (packets) => ipcRenderer.invoke('save-packets', packets),

  // Event listeners
  onPacketReceived: (callback) => {
    ipcRenderer.removeAllListeners('packet-received');
    ipcRenderer.on('packet-received', (event, packet) => {
      console.log('Preload received packet:', packet);
      callback(packet);
    });
  },

  onSnifferError: (callback) => {
    ipcRenderer.removeAllListeners('sniffer-error');
    ipcRenderer.on('sniffer-error', (event, error) => {
      console.log('Preload received error:', error);
      callback(error);
    });
  },

  onSnifferStopped: (callback) => {
    ipcRenderer.removeAllListeners('sniffer-stopped');
    ipcRenderer.on('sniffer-stopped', (event, code) => {
      console.log('Preload received stop signal:', code);
      callback(code);
    });
  }
});
