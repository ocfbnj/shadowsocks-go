package main

import (
	"flag"
	"log"
)

var (
	serverMode bool
	clientMode bool
	remoteHost string
	remotePort string
	localPort  string
	password   string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.BoolVar(&serverMode, "Server", true, "Server mode.")
	flag.BoolVar(&clientMode, "Client", false, "Client mode.")
	flag.StringVar(&remoteHost, "s", "", "Host name or IP address of your remote server.")
	flag.StringVar(&remotePort, "p", "", "Port number of your remote server.")
	flag.StringVar(&localPort, "l", "", "Port number of your local server.")
	flag.StringVar(&password, "k", "", "Password of your remote server.")
	flag.Parse()

	if clientMode {
		if remoteHost == "" || remotePort == "" || localPort == "" || password == "" {
			flag.PrintDefaults()
			return
		}

		tcpLocal(remoteHost, remotePort, localPort, password)
	} else {
		if remotePort == "" || password == "" {
			flag.PrintDefaults()
			return
		}

		tcpRemote(remotePort, password)
	}
}
