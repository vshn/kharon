package proxy

import (
	"net"
	"sync/atomic"
)

type ConnCountingListener struct {
	net.Listener
	connCount atomic.Int64
}

type CountingConn struct {
	net.Conn
	connCount *atomic.Int64
}

func (c CountingConn) Close() error {
	c.connCount.Add(-1)
	return c.Conn.Close()
}

func (l *ConnCountingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.connCount.Add(1)
	}
	return CountingConn{Conn: conn, connCount: &l.connCount}, err
}
