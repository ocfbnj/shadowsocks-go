package main

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/ocfbnj/shadowsocks-go/crypto/shadow"
	"github.com/ocfbnj/shadowsocks-go/socks5"
)

func tcpLocal(remoteHost, remotePort, localPort, password string) {
	listener, err := net.Listen("tcp", net.JoinHostPort("", localPort))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listen on %s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			addr, err := socks5.Handshake(c)
			if err != nil {
				log.Print(err)
				return
			}

			lc, err := net.Dial("tcp", net.JoinHostPort(remoteHost, remotePort))
			if err != nil {
				log.Print(err)
				return
			}
			defer lc.Close()

			elc := shadow.NewEncryptedConn(lc, []byte(password))

			if _, err := elc.Write(addr); err != nil {
				log.Print(err)
				return
			}

			proxy(elc, c)
		}(conn)
	}
}

func tcpRemote(remotePort, password string) {
	listener, err := net.Listen("tcp", net.JoinHostPort("", remotePort))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listen on %s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			erc := shadow.NewEncryptedConn(c, []byte(password))

			addr, err := socks5.ReadTargetAddress(erc)
			if err != nil {
				log.Print(err)
				return
			}

			rc, err := net.Dial("tcp", addr.String())
			if err != nil {
				log.Print(err)
				return
			}
			defer rc.Close()

			proxy(erc, rc)
		}(conn)
	}
}

func proxy(a io.ReadWriter, b io.ReadWriter) {
	var wg sync.WaitGroup

	ioCopy := func(w io.Writer, r io.Reader) {
		defer wg.Done()

		if _, err := io.Copy(w, r); err != nil {
			log.Println(err)
		}
	}

	wg.Add(2)
	go ioCopy(a, b)
	go ioCopy(b, a)
	wg.Wait()
}
