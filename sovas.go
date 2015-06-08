/*
    Copyright (C) 2015 Wang Jian <larkwang@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 dated June, 1991, or
    (at your option) version 3 dated 29 June, 2007.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"net"
	"bufio"
	"regexp"
	"time"
	"strconv"
	"fmt"
	"strings"
	"flag"
	"os"
	"os/exec"
)

var (
	openvpnSock string
	openvpnAuth string
	debug bool
)

func init() {
	flag.StringVar(&openvpnSock, "m", "", "openvpn management socket path")
	flag.StringVar(&openvpnAuth, "s", "", "openvpn auth script path")
	flag.BoolVar(&debug, "d", false, "turn on debug information")
	flag.Parse()

	if (len(openvpnSock) == 0 || len(openvpnAuth) == 0) {
		fmt.Printf("Usage: sovas -m openvpn_management_sock_path -s auth_script_path [-d]\n")
		os.Exit(-1)
	}
}

func main() {
	var conn net.Conn
	var err error

	// in case openvpn restarted
	for {
		for {
			// in case openvpn not started yet
			conn, err = net.Dial("unix", openvpnSock)
			if err != nil {
				time.Sleep(time.Second * 1)
			} else {
				break;
			}
		}
		// if unexpected exit
		defer conn.Close()

		banner(conn)
		process(conn)

		conn.Close()
	}
}

// consume banner line
func banner(conn net.Conn) {
	buf := make([]byte, 16384)

	n, err := conn.Read(buf[:])
	if err != nil {
		panic(err)
	}
	_ = n
}

func processConnect(conn net.Conn, r *bufio.Reader, clientID int, keyID int) {
	reClientEnv     := regexp.MustCompile("^>CLIENT:ENV,(?P<VAR>[0-9a-zA-Z_]+)=(?P<VAL>.+)")
	reClientEnvEnd  := regexp.MustCompile("^>CLIENT:ENV,END")

	line, isPrefix, err := r.ReadLine()

	os.Clearenv()
	os.Setenv("PATH", "/usr/bin:/bin")

	for err == nil && !isPrefix {
		if debug {
			fmt.Printf("%s\n", line)
		}
		if res := reClientEnv.FindAllSubmatch(line, -1); res != nil {
			os.Setenv(string(res[0][1]), string(res[0][2]))

		} else if res := reClientEnvEnd.FindAllSubmatch(line, -1); res != nil {
			var (
				cmd string
				reason string
				clientReason string
			)

			if out, err := exec.Command(openvpnAuth).Output(); err != nil {
				lines := strings.Split(string(out), "\n")
				if strings.HasPrefix(lines[0], "CRV1:") {
					reason = "need challenge response"
					clientReason = lines[0]
				} else {
					reason = "authentication failed"
					clientReason = ""
				}
				cmd = fmt.Sprintf("client-deny %d %d \"%s\" \"%s\"\n",
						  clientID, keyID,
						  reason, clientReason)
				print(cmd)
			} else {
				cmd = fmt.Sprintf("client-auth-nt %d %d\n", clientID, keyID)
				print(cmd)
			}
			conn.Write([]byte(cmd))
			return
		}
		line, isPrefix, err = r.ReadLine()
	}
}

func processAddress(conn net.Conn, r *bufio.Reader, clientID int, address []byte) {
	reClientEnv     := regexp.MustCompile("^>CLIENT:ENV,(?P<VAR>[0-9a-zA-Z_]+)=(?P<VAL>.+)")
	reClientEnvEnd  := regexp.MustCompile("^>CLIENT:ENV,END")

	var username []byte

	line, isPrefix, err := r.ReadLine()

	for err == nil && !isPrefix {
		if debug {
			fmt.Printf("%s\n", line)
		}
		res := reClientEnv.FindAllSubmatch(line, -1)
		if res != nil {
			if string(res[0][1]) == "username" {
				username = res[0][2]
				_ = username
			}
		} else {
			res := reClientEnvEnd.FindAllSubmatch(line, -1)
			if res != nil {
				return
			}
		}
		line, isPrefix, err = r.ReadLine()
	}
}

// main loop
// only message blocks concerned are handled, other message block are read
// and ignored.
func process(conn net.Conn) {
	r := bufio.NewReaderSize(conn, 16*1024)
	reClientConnect := regexp.MustCompile("^>CLIENT:CONNECT,(?P<CID>[0-9]+),(?P<KID>[0-9]+)")
	reClientAddress := regexp.MustCompile("^>CLIENT:ADDRESS,(?P<CID>[0-9]+),(?P<IP>[0-9.]+),(?P<NO>[0-9]+)")

	line, isPrefix, err := r.ReadLine()
	for err == nil && !isPrefix {
		if debug {
			fmt.Printf("%s\n", line)
		}
		// >CLIENT:CONNECT
		res := reClientConnect.FindAllSubmatch(line, -1)
		if res != nil {
			clientID, _ := strconv.Atoi(string(res[0][1]))
			keyID, _ := strconv.Atoi(string(res[0][2]))

			processConnect(conn, r, clientID, keyID)
			goto next_chat
		}

		// >CLIENT:ADDRESS
		res = reClientAddress.FindAllSubmatch(line, -1)
		if res != nil {
			clientID, _ := strconv.Atoi(string(res[0][1]))

			processAddress(conn, r, clientID, res[0][2])
			goto next_chat
		}
next_chat:
		line, isPrefix, err = r.ReadLine()
	}
}
