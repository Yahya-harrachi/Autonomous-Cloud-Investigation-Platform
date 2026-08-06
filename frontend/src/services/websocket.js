/**
 * WebSocket Service - Real-time event streaming
 */
class WebSocketService {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.listeners = [];
        this.reconnectInterval = null;
    }

    /**
     * Connect to WebSocket server
     */
    connect() {
        // Use wss:// in production, ws:// in development
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//localhost:8000/ws/events`;
        
        try {
            this.socket = new WebSocket(wsUrl);
            
            this.socket.onopen = () => {
                console.log('✅ WebSocket connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this._notifyListeners('connected', {});
            };
            
            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this._handleMessage(data);
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };
            
            this.socket.onclose = () => {
                console.log('❌ WebSocket disconnected');
                this.isConnected = false;
                this._notifyListeners('disconnected', {});
                this._attemptReconnect();
            };
            
            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this._notifyListeners('error', { error });
            };
            
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this._attemptReconnect();
        }
    }

    /**
     * Disconnect from WebSocket server
     */
    disconnect() {
        if (this.reconnectInterval) {
            clearTimeout(this.reconnectInterval);
            this.reconnectInterval = null;
        }
        
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.isConnected = false;
    }

    /**
     * Add a listener for WebSocket events
     */
    on(event, callback) {
        this.listeners.push({ event, callback });
    }

    /**
     * Remove a listener
     */
    off(event, callback) {
        this.listeners = this.listeners.filter(
            l => !(l.event === event && l.callback === callback)
        );
    }

    /**
     * Handle incoming messages
     */
    _handleMessage(data) {
        const type = data.type;
        
        if (type === 'connected') {
            console.log('✅ Connected to real-time events');
            this._notifyListeners('connected', data);
            return;
        }
        
        if (type === 'new_event') {
            console.log('📡 New event received:', data.data?.event_name);
            this._notifyListeners('new_event', data.data);
            return;
        }
        
        if (type === 'new_incident') {
            console.log('🚨 New incident received:', data.data?.title);
            this._notifyListeners('new_incident', data.data);
            return;
        }
        
        if (type === 'health_update') {
            this._notifyListeners('health_update', data.data);
            return;
        }
        
        if (type === 'pong') {
            return;
        }
        
        // Unknown message type
        this._notifyListeners('message', data);
    }

    /**
     * Notify all listeners of an event
     */
    _notifyListeners(event, data) {
        this.listeners.forEach(listener => {
            if (listener.event === event) {
                try {
                    listener.callback(data);
                } catch (e) {
                    console.error('Error in WebSocket listener:', e);
                }
            }
        });
    }

    /**
     * Attempt to reconnect
     */
    _attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnect attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
        
        console.log(`🔄 Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        
        this.reconnectInterval = setTimeout(() => {
            this.connect();
        }, delay);
    }

    /**
     * Send a message to the server
     */
    send(message) {
        if (this.socket && this.isConnected) {
            this.socket.send(JSON.stringify(message));
        } else {
            console.warn('WebSocket is not connected');
        }
    }

    /**
     * Get connection status
     */
    getStatus() {
        return {
            isConnected: this.isConnected,
            reconnectAttempts: this.reconnectAttempts,
        };
    }
}

// Singleton instance
const websocketService = new WebSocketService();

export default websocketService;