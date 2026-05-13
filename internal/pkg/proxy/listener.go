package proxy

import (
	"net"
	"sync"
	"sync/atomic"
)

type ConnCountingListener struct {
	net.Listener
	connCount atomic.Int64
}

type countingConn struct {
	net.Conn

	subtractOnce sync.Once
	connCount    *atomic.Int64
}

func (c *countingConn) Close() error {
	defer c.subtractOnce.Do(func() { c.connCount.Add(-1) })
	return c.Conn.Close()
}

func (l *ConnCountingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.connCount.Add(1)
	return &countingConn{Conn: conn, connCount: &l.connCount}, nil
}
