package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/MG-RAST/golib/mgo"
)

type HostInfo struct {
	Host string
	Port string
	Dbs  []string
	Weak bool
}

func Connect(host_info HostInfo, chan_host_info chan HostInfo) {
	host := host_info.Host
	port := host_info.Port
	url := fmt.Sprintf("%s:%s", host, port)
	session, err := mgo.DialWithTimeout(url, time.Second*3)

	if err == nil {
		dbs, err := session.DatabaseNames()
		if err == nil {
			host_info.Weak = true
			host_info.Dbs = dbs
		}
	}

	chan_host_info <- host_info
}

func Scan(ip_list []string) {
	n := len(ip_list)
	chan_re := make(chan HostInfo, n)
	chan_done := make(chan bool, n)

	for _, ip := range ip_list {
		ip_pair := strings.Split(ip, ":")
		host, port := ip_pair[0], ip_pair[1]

		host_info := HostInfo{host, port, []string{}, false}

		go Connect(host_info, chan_re)

		for runtime.NumGoroutine() > runtime.NumCPU()*100 {
			time.Sleep(20 * time.Microsecond)
		}
	}

	go func() {
		for i := 0; i < cap(chan_re); i += 1 {
			select {
			case r := <-chan_re:
				if r.Weak {
					fmt.Printf("%s:%s is vulnerability, DBs:%s\n", r.Host, r.Port, r.Dbs)
				}
			case <-time.After(3 * time.Second):
				break
			}
			chan_done <- true
		}
	}()

	for i := 0; i < cap(chan_done); i += 1 {
		<-chan_done
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	Scan([]string{"127.0.0.1:27017"})
}
