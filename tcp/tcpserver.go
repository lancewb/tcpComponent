package tcp

import (
	"log"
	"net"
	"time"
  "github.com/felixge/tcpkeepalive"
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/counter"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/water"
	//"github.com/patrickmn/go-cache"
)

func setTcpKeepAlive(conn net.Conn) (*tcpkeepalive.Conn, error) {

	newConn, err := tcpkeepalive.EnableKeepAlive(conn)
	if err != nil {
			log.Println("EnableKeepAlive failed:", err)
			return nil, err
	}

	err = newConn.SetKeepAliveIdle(10*time.Second)
	if err != nil {
			log.Println("SetKeepAliveIdle failed:", err)
			return nil, err
	}


	err = newConn.SetKeepAliveCount(9)
	if err != nil {
			log.Println("SetKeepAliveCount failed:", err)
			return nil, err
	}
	
	err = newConn.SetKeepAliveInterval(10*time.Second)
	if err != nil {
			log.Println("SetKeepAliveInterval failed:", err)
			return nil, err
	}

	return newConn, nil
}
// StartServer starts the udp server
func StartServer(iface *water.Interface, config config.Config) {
	log.Printf("vtun tcp server started on %v", config.LocalAddr)
	localAddr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
	if err != nil {
		log.Fatalln("failed to get tcp socket:", err)
	}
	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		log.Fatalln("failed to listen on tcp socket:", err)
	}
	go toClient(config, iface)
	// client -> server
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
    newConn, err := setTcpKeepAlive(conn)
    if err != nil {
      log.Println("setTcpKeepAlive failed:", err)
      return
    }
		go toServer(config, newConn, iface)
	}
}

func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.BufferSize)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				v.(net.Conn).Write(b)
				counter.IncrWrittenBytes(n)
			}
		}
	}
}

func toServer(config config.Config, tcpconn net.Conn, iface *water.Interface) {
	defer tcpconn.Close()
	packet := make([]byte, config.BufferSize)
	for {
		tcpconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := tcpconn.Read(packet)
		if err != nil {
			netutil.PrintErr(err, config.Verbose)
			break
		}
		b := packet[:n]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				netutil.PrintErr(err, config.Verbose)
				break
			}
		}
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, tcpconn, 10*time.Minute)
			iface.Write(b)
			counter.IncrReadBytes(n)
		}
	}
}
