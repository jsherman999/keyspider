import { useEffect, useRef, useState, useCallback } from 'react';
import { WebSocketClient } from '../api/websocket';

export function useWebSocket(url: string, enabled = true) {
  const clientRef = useRef<WebSocketClient | null>(null);
  const [messages, setMessages] = useState<Record<string, unknown>[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!enabled) return;

    const client = new WebSocketClient(url);
    clientRef.current = client;

    const unsubscribe = client.onMessage((data) => {
      setMessages((prev) => [...prev.slice(-500), data]); // Keep last 500 messages
      if (data.type !== 'keepalive' && data.type !== 'pong') {
        setConnected(true);
      }
    });

    client.connect();
    setConnected(true);

    return () => {
      unsubscribe();
      client.disconnect();
      setConnected(false);
    };
  }, [url, enabled]);

  const send = useCallback((data: string) => {
    clientRef.current?.send(data);
  }, []);

  return { messages, connected, send };
}
