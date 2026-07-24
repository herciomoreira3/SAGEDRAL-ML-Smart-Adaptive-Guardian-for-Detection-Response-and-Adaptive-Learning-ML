import { useEffect, useRef, useState, useCallback } from 'react';

export function useWebSocket() {
  const ws = useRef(null);
  const [connected, setConnected] = useState(false);
  const [lastAlert, setLastAlert] = useState(null);
  const [trafficStats, setTrafficStats] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);

  const getWsUrl = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws/alerts`;
  };

  const connect = useCallback(() => {
    try {
      const url = getWsUrl();
      ws.current = new WebSocket(url);

      ws.current.onopen = () => {
        setConnected(true);
      };

      ws.current.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };

      ws.current.onerror = (err) => {
        console.error('WebSocket error:', err);
      };

      ws.current.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.event === 'new_alert') setLastAlert(msg.data);
          if (msg.event === 'traffic_stats') setTrafficStats(msg.data);
          if (msg.event === 'system_status') setSystemStatus(msg.data);
        } catch (e) {
          console.error('Failed to parse WS message', e);
        }
      };
    } catch (e) {
      console.error('WS connection error', e);
      setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) ws.current.close();
    };
  }, [connect]);

  return { connected, lastAlert, trafficStats, systemStatus };
}
