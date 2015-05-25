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
	"encoding/base64"
)

func main() {
	var conn net.Conn
	var err error

	// in case openvpn restarted
	for {
		for {
			// in case openvpn not started yet
			conn, err = net.Dial("unix", "/var/run/openvpn/mobile.sock")
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
	print(string(buf[0:n]))
}

func processConnect(conn net.Conn, r *bufio.Reader, clientID int, keyID int) {
	reClientEnv     := regexp.MustCompile("^>CLIENT:ENV,(?P<VAR>[0-9a-zA-Z_]+)=(?P<VAL>.+)")
	reClientEnvEnd  := regexp.MustCompile("^>CLIENT:ENV,END")
	reCRV1          := regexp.MustCompile("^CRV1::(?P<CH>[0-9a-zA-Z_]+)::(?P<RESP>.+)$")

	line, isPrefix, err := r.ReadLine()
	var username []byte
	var password []byte
	var challenge []byte
	var response []byte
	var status int

	status = 0

	for err == nil && !isPrefix {
		fmt.Printf("%s\n", line)
		res := reClientEnv.FindAllSubmatch(line, -1)
		if res != nil {
			if string(res[0][1]) == "username" {
				username = res[0][2]
				fmt.Printf("+++ username=%s\n", username)
			} else if string(res[0][1]) == "password" {
				password = res[0][2]
				fmt.Printf("+++ password=%s\n", password)
				p := reCRV1.FindAllSubmatch(password, -1)
				if p != nil {
					challenge = p[0][1]
					response = p[0][2]
					fmt.Printf("+++ response is %s\n", response)
					_ = challenge
					_ = response
					status = 1
				}
			}
		} else {
			res := reClientEnvEnd.FindAllSubmatch(line, -1)
			if res != nil {
				if status == 0 {
					// password authentication
					// password is ok, send challenge
					cmd := fmt.Sprintf("client-deny %d %d \"need totp code\" \"CRV1:R,E:xxxxxxxxxxx:%s:TOTP code:\"\n", clientID, keyID, base64.StdEncoding.EncodeToString(username))
					print("--- ", cmd)
					conn.Write([]byte(cmd))
				} else if status == 1 {
					// check challenge
					// challenge response is ok, authentication done
					cmd := fmt.Sprintf("client-auth-nt %d %d\n", clientID, keyID)
					print("--- ", cmd)
					conn.Write([]byte(cmd))
				}
				return
			}
		}
		line, isPrefix, err = r.ReadLine()
	}
}

func processAddress(conn net.Conn, r *bufio.Reader, clientID int, address []byte) {
	reClientEnv     := regexp.MustCompile("^>CLIENT:ENV,(?P<VAR>[0-9a-zA-Z_]+)=(?P<VAL>.+)")
	reClientEnvEnd  := regexp.MustCompile("^>CLIENT:ENV,END")

	var username []byte

	println("+++ ", string(address))

	line, isPrefix, err := r.ReadLine()

	for err == nil && !isPrefix {
		fmt.Printf("%s\n", line)
		res := reClientEnv.FindAllSubmatch(line, -1)
		if res != nil {
			if string(res[0][1]) == "username" {
				username = res[0][2]
				fmt.Printf("+++ username=%s\n", username)
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
		fmt.Printf("%s\n", line)
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
