/**
 * BOQA EventBus — Normalized event pipeline with WebSocket transport
 *
 * Contract:
 *   - All events follow a unified schema (ts, type, url, method, status, headers, payload, source, meta)
 *   - Events are immutable after emit
 *   - Timestamps are monotonic per session
 *   - Order preserved per tab
 *   - Broadcast to all connected dashboard clients via WS
 */

const EventEmitter = require('events');

const EVENT_TYPES = new Set([
  'network_request',
  'network_response',
  'network_failure',
  'websocket_open',
  'websocket_message_in',
  'websocket_message_out',
  'websocket_close',
  'console_log',
  'console_error',
  'page_navigation',
  'cookie_snapshot',
  'auth_signal',
  'performance_resource',
]);

class EventBus extends EventEmitter {
  constructor(wsServer = null) {
    super();
    this.wsServer = wsServer;
    this.sessionStart = Date.now();
    this.eventIndex = 0;
    this.eventLog = [];
    this.maxLogSize = 50000; // in-memory cap
    this.clients = new Set();
    this.paused = false;

    if (wsServer) {
      this._attachWsServer(wsServer);
    }
  }

  /**
   * Attach a WebSocket server for dashboard streaming
   */
  _attachWsServer(wsServer) {
    wsServer.on('connection', (ws) => {
      this.clients.add(ws);
      console.log(`[EventBus] Dashboard client connected (${this.clients.size} total)`);

      // Send session metadata on connect
      this._sendToClient(ws, {
        type: 'session_meta',
        sessionStart: this.sessionStart,
        eventCount: this.eventIndex,
      });

      // Send last N events for late-joining clients (replay buffer)
      const replayBuffer = this.eventLog.slice(-200);
      if (replayBuffer.length > 0) {
        this._sendToClient(ws, {
          type: 'replay',
          events: replayBuffer,
        });
      }

      ws.on('close', () => {
        this.clients.delete(ws);
        console.log(`[EventBus] Dashboard client disconnected (${this.clients.size} remaining)`);
      });

      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw);
          if (msg.action === 'pause') this.paused = true;
          if (msg.action === 'resume') this.paused = false;
          if (msg.action === 'export') this._handleExportRequest(ws);
        } catch (_) {}
      });
    });
  }

  /**
   * Emit a normalized event through the pipeline
   */
  emit(event) {
    if (!EVENT_TYPES.has(event.type)) {
      console.warn(`[EventBus] Unknown event type: ${event.type}`);
      return;
    }

    // Enforce schema
    const normalized = this._normalize(event);
    this.eventIndex++;

    // Store in memory
    this.eventLog.push(normalized);
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog.shift(); // FIFO eviction
    }

    // Local event emitter for programmatic consumers
    super.emit('event', normalized);
    super.emit(normalized.type, normalized);

    // Stream to dashboard clients
    if (!this.paused) {
      this._broadcast(normalized);
    }
  }

  /**
   * Normalize raw event to unified schema
   */
  _normalize(raw) {
    return Object.freeze({
      id: this.eventIndex,
      ts: raw.ts || Date.now(),
      elapsed: Date.now() - this.sessionStart,
      type: raw.type,
      url: raw.url || null,
      method: raw.method || null,
      status: raw.status || null,
      headers: raw.headers || null,
      payload: raw.payload || null,
      source: raw.source || 'playwright',
      meta: raw.meta || {},
    });
  }

  /**
   * Broadcast to all connected dashboard clients
   */
  _broadcast(event) {
    const msg = JSON.stringify(event);
    for (const ws of this.clients) {
      if (ws.readyState === 1) { // OPEN
        ws.send(msg);
      }
    }
  }

  /**
   * Send to a specific client
   */
  _sendToClient(ws, data) {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(data));
    }
  }

  /**
   * Handle export request from dashboard
   */
  _handleExportRequest(ws) {
    const exportData = {
      sessionStart: this.sessionStart,
      sessionEnd: Date.now(),
      totalEvents: this.eventIndex,
      events: this.eventLog,
    };
    this._sendToClient(ws, {
      type: 'export',
      data: exportData,
    });
  }

  /**
   * Get session stats
   */
  getStats() {
    const byType = {};
    for (const evt of this.eventLog) {
      byType[evt.type] = (byType[evt.type] || 0) + 1;
    }
    return {
      sessionStart: this.sessionStart,
      duration: Date.now() - this.sessionStart,
      totalEvents: this.eventIndex,
      inMemory: this.eventLog.length,
      byType,
      clients: this.clients.size,
      paused: this.paused,
    };
  }

  /**
   * Export full session as JSON
   */
  exportSession() {
    return {
      sessionStart: this.sessionStart,
      sessionEnd: Date.now(),
      totalEvents: this.eventIndex,
      events: this.eventLog,
    };
  }

  /**
   * Clear session log (keeps clients connected)
   */
  clear() {
    this.eventLog = [];
    this.eventIndex = 0;
    this.sessionStart = Date.now();
  }
}

module.exports = { EventBus, EVENT_TYPES };

