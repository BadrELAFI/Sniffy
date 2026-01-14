
const { ipcRenderer } = require('electron');
class SniffyApp {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.isPaused = false;
        this.packets = [];
        this.stats = {
            total: 0,
            http: 0,
            dns: 0,
            tcp: 0,
            udp: 0,
            icmp: 0,
            arp: 0,
            icmpv6: 0
        };
        this.filters = {
            http: true,
            dns: true,
            tcp: true,
            udp: true,
            icmp: true,
            icmpv6: true,
            arp: true,
            loopback: false
        };

        
        this.initializeElements();
        this.bindEvents();
        this.updateUI();
    }

    initializeElements() {
        // header elements
        this.connectBtn = document.getElementById('connectBtn');
        this.clearBtn = document.getElementById('clearBtn');
        this.statusIndicator = document.getElementById('statusIndicator');
        this.statusText = document.getElementById('statusText');
        
        // stats elements
        this.totalPacketsEl = document.getElementById('totalPackets');
        this.httpCountEl = document.getElementById('httpCount');
        this.dnsCountEl = document.getElementById('dnsCount');
        this.tcpCountEl = document.getElementById('tcpCount');
        this.udpCountEl = document.getElementById('udpCount');
        this.icmpCountEl = document.getElementById('icmpCount');
        this.icmpv6CountEl = document.getElementById('icmpv6Count');
        this.arpCountEl = document.getElementById('arpCount');

        // filter elements
        this.filterHTTP = document.getElementById('filterHTTP');
        this.filterDNS = document.getElementById('filterDNS');
        this.filterTCP = document.getElementById('filterTCP');
        this.filterUDP = document.getElementById('filterUDP');
        this.filterICMP = document.getElementById('filterICMP');
        this.filterICMPv6 = document.getElementById('filterICMPv6');
        this.filterARP = document.getElementById('filterARP');

        // packet list elements
        this.packetList = document.getElementById('packetList');
        this.searchInput = document.getElementById('searchInput');
        this.pauseBtn = document.getElementById('pauseBtn');
        this.pauseIcon = document.getElementById('pauseIcon');
        
        // modal elements
        this.modal = document.getElementById('packetModal');
        this.modalClose = document.getElementById('modalClose');
        this.modalBody = document.getElementById('modalBody');
        
        this.loadingOverlay = document.getElementById('loadingOverlay');
    }

    bindEvents() {
        this.connectBtn.addEventListener('click', () => this.toggleConnection());
        this.clearBtn.addEventListener('click', () => this.clearPackets());
        


        this.filterHTTP.addEventListener('change', (e) => {
            this.filters.http = e.target.checked;
            this.filterPackets();
        });
        this.filterDNS.addEventListener('change', (e) => {
            this.filters.dns = e.target.checked;
            this.filterPackets();
        });
        this.filterTCP.addEventListener('change', (e) => {
            this.filters.tcp = e.target.checked;
            this.filterPackets();
        });
        this.filterUDP.addEventListener('change', (e) => {
            this.filters.udp = e.target.checked;
            this.filterPackets();
        });
        this.filterICMP.addEventListener('change', (e) => {
            this.filters.icmp = e.target.checked;
            this.filterPackets();
        });
        this.filterICMPv6.addEventListener('change', (e) => {
            this.filters.icmpv6 = e.target.checked;
            this.filterPackets();
        });
        this.filterARP.addEventListener('change', (e) => {
            this.filters.arp = e.target.checked;
            this.filterPackets();
        })
        
        this.searchInput.addEventListener('input', () => this.filterPackets());
        this.pauseBtn.addEventListener('click', () => this.togglePause());
        
        this.modalClose.addEventListener('click', () => this.closeModal());
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.closeModal();
        });
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                this.searchInput.focus();
            }
        });
    }

    async toggleConnection() {
        if (this.isConnected) {
            this.disconnect();
        } else {
            await this.connect();
        }
    }


    async connect() {
        this.showLoading(true);

        try {
            await ipcRenderer.invoke('start-sniffer');
            console.log('Sniffer backend started, waiting for WebSocket to be available...');

            // Try to connect with retries
            await this.connectWithRetry(5, 1000); // 5 retries, 1 second apart

        } catch (error) {
            console.error('Could not start sniffer backend or connect:', error);
            this.showLoading(false);
            this.showNotification('Connection failed: ' + error.message, 'error');
        }
    }

    async connectWithRetry(maxRetries = 5, delayMs = 1000) {
        let lastError;
        
        for (let i = 0; i < maxRetries; i++) {
            try {
                console.log(`WebSocket connection attempt ${i + 1}/${maxRetries}...`);
                await this.attemptWebSocketConnection();
                return; // Success!
            } catch (error) {
                lastError = error;
                console.log(`Attempt ${i + 1} failed:`, error.message);
                if (i < maxRetries - 1) {
                    await new Promise(resolve => setTimeout(resolve, delayMs));
                }
            }
        }
        
        throw new Error('Failed to connect after ' + maxRetries + ' attempts: ' + lastError.message);
    }

    async attemptWebSocketConnection() {
        return new Promise((resolve, reject) => {
            const socket = new WebSocket('ws://localhost:8765');
            const timeout = setTimeout(() => {
                socket.close();
                reject(new Error('WebSocket connection timeout'));
            }, 5000);

            socket.onopen = () => {
                clearTimeout(timeout);
                this.socket = socket;
                this.isConnected = true;
                this.updateConnectionStatus();
                this.showLoading(false);
                this.showNotification('Connected to packet sniffer', 'success');
                
                // Setup message handler
                this.socket.onmessage = (event) => {
                    if (!this.isPaused) {
                        try {
                            const packet = JSON.parse(event.data);
                            this.handlePacket(packet);
                        } catch (error) {
                            console.error('Error parsing packet:', error);
                        }
                    }
                };

                this.socket.onclose = () => {
                    this.isConnected = false;
                    this.updateConnectionStatus();
                    this.showNotification('Disconnected from packet sniffer', 'warning');
                };

                this.socket.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    this.isConnected = false;
                    this.updateConnectionStatus();
                };
                
                resolve();
            };

            socket.onerror = () => {
                clearTimeout(timeout);
                reject(new Error('WebSocket connection refused'));
            };

            socket.onclose = () => {
                clearTimeout(timeout);
                reject(new Error('WebSocket connection closed'));
            };
        });
    } 

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.isConnected = false;
        this.updateConnectionStatus();
        
        // Stop the backend
        ipcRenderer.invoke('stop-sniffer').catch(error => {
            console.error('Error stopping sniffer:', error);
        });
    }

    updateConnectionStatus() {
        if (this.isConnected) {
            this.statusIndicator.classList.add('connected');
            this.statusText.textContent = 'Connected';
            this.connectBtn.textContent = 'Disconnect';
            this.connectBtn.classList.remove('btn-primary');
            this.connectBtn.classList.add('btn-secondary');
        } else {
            this.statusIndicator.classList.remove('connected');
            this.statusText.textContent = 'Disconnected';
            this.connectBtn.textContent = 'Connect';
            this.connectBtn.classList.remove('btn-secondary');
            this.connectBtn.classList.add('btn-primary');
        }
    }

    handlePacket(packet) {
        this.packets.unshift(packet);
        this.updateStats(packet);
        this.renderPackets();
                
        if (this.shouldShowPacket(packet)) {
          const node = document.createElement('div');
          node.innerHTML = this.renderPacketItem(packet);
          this.packetList.prepend(node.firstElementChild);
        }

        // limit packet history
        if (this.packets.length > 1000) {
            this.packets = this.packets.slice(0, 1000);
        }
        this.packetList.scrollTop = this.packetList.scrollHeight;
    }

    updateStats(packet) {
        this.stats.total++;
        
        if (packet.HTTP) this.stats.http++;
        if (packet.DNS) this.stats.dns++;
        if (packet.TCP) this.stats.tcp++;
        if (packet.UDP) this.stats.udp++;
        if (packet.ICMP) this.stats.icmp++;
        if (packet.ICMPv6) this.stats.icmpv6++;
        if (packet.ARP) this.stats.arp++;
        this.updateStatsUI();
    }

    updateStatsUI() {
        this.totalPacketsEl.textContent = this.stats.total.toLocaleString();
        this.httpCountEl.textContent = this.stats.http.toLocaleString();
        this.dnsCountEl.textContent = this.stats.dns.toLocaleString();
        this.tcpCountEl.textContent = this.stats.tcp.toLocaleString();
        this.udpCountEl.textContent = this.stats.udp.toLocaleString();
        this.icmpv6CountEl.textContent = this.stats.icmpv6.toLocaleString();
        this.arpCountEl.textContent = this.stats.arp.toLocaleString();
          
    }

    getPacketType(packet) {
        if (packet.HTTP) return 'http';
        if (packet.DNS) return 'dns';
        if (packet.TCP) return 'tcp';
        if (packet.UDP) return 'udp';
        if (packet.ICMP) return 'icmp';
        if (packet.ICMPv6) return 'icmpv6';
        if (packet.ARP) return 'arp';
        return 'other';
    }

    shouldShowPacket(packet) {
        const type = this.getPacketType(packet);
        if (!this.filters[type]) return false;
        
        const searchTerm = this.searchInput.value.toLowerCase();
        if (!searchTerm) return true;
        
        const searchText = JSON.stringify(packet).toLowerCase();
        return searchText.includes(searchTerm);
    }

    renderPackets() {
        const filteredPackets = this.packets.filter(packet => this.shouldShowPacket(packet));
        
        if (filteredPackets.length === 0) {
            this.packetList.innerHTML = `
                <div class="no-packets">
                    <div class="no-packets-icon">📡</div>
                    <h3>No packets match your filters</h3>
                    <p>Try another filter</p>
                </div>
            `;
            return;
        }
        
        this.packetList.innerHTML = filteredPackets
            .slice(0, 100) 
            .map(packet => this.renderPacketItem(packet))
            .join('');


        this.packetList.scrollTop = this.packetList.scrollHeight;
    }

    renderPacketItem(packet) {
        const type = this.getPacketType(packet);
        const timestamp = new Date(packet.timestamp).toLocaleTimeString();
        
        let summary = '';
        if (packet.IPv4) {
            summary += `${packet.IPv4.source_ip} → ${packet.IPv4.destination_ip}`;
        } else if (packet.IPv6) {
            summary += `${packet.IPv6.source_ip} → ${packet.IPv6.destination_ip}`;
        }
        
        
        let details = '';
        if (packet.HTTP) {
            details = `${packet.HTTP.method || 'Response'} ${packet.HTTP.path || packet.HTTP.status}`;
        } else if (packet.DNS) {
            const questions = packet.DNS.questions || [];
            details = questions.length > 0 ? questions[0].qname : 'DNS Query';
        } else if (packet.TCP) {
            details = `Port ${packet.TCP.source_port} → ${packet.TCP.destination_port}`;
        } else if (packet.UDP) {
            details = `Port ${packet.UDP.source_port} → ${packet.UDP.destination_port}`;
        } else if (packet.ICMP) {
            if (packet.ICMP.code == 0) {
                details = "echo reply";
            } else {
                details = "echo request";
            }
        } else if (packet.ARP) {
            if (packet.ARP.opcode == 1) {
              details = `who has ${packet.ARP.target_IP} tell ${packet.ARP.sender_IP}`;
            } else if (packet.ARP.opcode == 2){
              details = `${packet.ARP.sender_IP} is at ${packet.ARP.sender_MAC}`;
            }
        } else if (packet.ICMPv6){

    }
        
        return `
            <div class="packet-item" onclick="app.showPacketDetails(${this.packets.indexOf(packet)})">
                <div class="packet-header-info">
                    <span class="packet-type ${type}">${type.toUpperCase()}</span>
                    <span class="packet-timestamp">${timestamp}</span>
                </div>
                <div class="packet-summary">
                    <div class="packet-field">
                        <div class="field-label">Connection</div>
                        <div class="field-value">${summary}</div>
                    </div>
                    <div class="packet-field">
                        <div class="field-label">Details</div>
                        <div class="field-value">${details}</div>
                    </div>
                </div>
            </div>
        `;
    }

    showPacketDetails(index) {
        const packet = this.packets[index];
        if (!packet) return;
        
        this.modalBody.innerHTML = `
            <div class="packet-details">
                <h4>Packet Information</h4>
                <pre class="json-display">${JSON.stringify(packet, null, 2)}</pre>
            </div>
            <style>
                .json-display {
                    background: rgba(0, 0, 0, 0.3);
                    padding: 1rem;
                    border-radius: 6px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    color: #00d4ff;
                    font-size: 0.85rem;
                    max-height: 400px;
                    overflow-y: auto;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
            </style>
        `;
        
        this.modal.classList.add('show');
    }

    closeModal() {
        this.modal.classList.remove('show');
    }

    filterPackets() {
        this.renderPackets();
    }

    togglePause() {
        this.isPaused = !this.isPaused;
        this.pauseIcon.textContent = this.isPaused ? '▶️' : '⏸️';
        this.pauseBtn.title = this.isPaused ? 'Resume capture' : 'Pause capture';
        
        if (this.isPaused) {
            this.showNotification('Packet capture paused', 'info');
        } else {
            this.showNotification('Packet capture resumed', 'success');
        }
    }

    clearPackets() {
        this.packets = [];
        this.stats = {
            total: 0,
            http: 0,
            dns: 0,
            tcp: 0,
            udp: 0,
            icmp: 0
        };
        this.updateStatsUI();
        this.renderPackets();
        this.showNotification('Packet history cleared', 'info');
    }

    showLoading(show) {
        if (show) {
            this.loadingOverlay.classList.add('show');
        } else {
            this.loadingOverlay.classList.remove('show');
        }
    }

    showNotification(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
        
        // notification toast
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 6px;
            border-left: 4px solid ${type === 'success' ? '#2ed573' : type === 'error' ? '#ff4757' : '#00d4ff'};
            z-index: 4000;
            animation: slideInFromRight 0.3s ease-out;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }

    updateUI() {
        this.updateConnectionStatus();
        this.updateStatsUI();
        this.renderPackets();
    }
}


const app = new SniffyApp();

