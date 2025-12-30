package honeypot

import (
	"fmt"
	"net"
	"strings"
	"time"

	"phantom-grid/internal/logger"
)

// handleSSH simulates SSH shell interaction
func (h *Handler) handleSSH(conn net.Conn, remote, t string) {
	time.Sleep(100 * time.Millisecond)

	prompt := "root@server:~# "
	conn.Write([]byte(prompt))

	ip := strings.Split(remote, ":")[0]
	currentDir := "/root"
	commandHistory := []string{}

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		input := strings.TrimSpace(string(buf[:n]))
		if len(input) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		h.logChan <- fmt.Sprintf("[%s] SSH COMMAND: %s", t, input)
		logger.LogAttack(ip, fmt.Sprintf("SSH: %s", input))
		commandHistory = append(commandHistory, input)

		parts := strings.Fields(input)
		if len(parts) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "exit", "logout":
			conn.Write([]byte("Connection closed.\r\n"))
			return
		case "ls":
			output := "total 24\r\ndrwxr-xr-x 2 root root 4096 Dec 15 10:23 .\r\n"
			output += "drwxr-xr-x 3 root root 4096 Dec 10 09:15 ..\r\n"
			output += "-rw-r--r-- 1 root root  220 Dec 10 09:15 .bash_logout\r\n"
			output += "-rw-r--r-- 1 root root 3771 Dec 10 09:15 .bashrc\r\n"
			output += "-rw-r--r-- 1 root root  807 Dec 10 09:15 .profile\r\n"
			output += "-rw-r--r-- 1 root root 1024 Dec 12 14:30 backup.tar.gz\r\n"
			output += "drwxr-xr-x 2 root root 4096 Dec 13 11:45 documents\r\n"
			conn.Write([]byte(output + prompt))
		case "pwd":
			conn.Write([]byte(currentDir + "\r\n" + prompt))
		case "whoami":
			conn.Write([]byte("root\r\n" + prompt))
		case "id":
			conn.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\r\n" + prompt))
		case "uname", "uname -a":
			conn.Write([]byte("Linux server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n" + prompt))
		case "cat":
			if len(args) > 0 {
				filename := args[0]
				if filename == "/etc/passwd" || filename == "passwd" {
					conn.Write([]byte("root:x:0:0:root:/root:/bin/bash\r\n" + prompt))
				} else if filename == "/etc/shadow" || filename == "shadow" {
					conn.Write([]byte("cat: /etc/shadow: Permission denied\r\n" + prompt))
				} else {
					conn.Write([]byte(fmt.Sprintf("cat: %s: No such file or directory\r\n", filename) + prompt))
				}
			} else {
				conn.Write([]byte("cat: missing file operand\r\n" + prompt))
			}
		case "cd":
			if len(args) > 0 {
				dir := args[0]
				if dir == ".." {
					currentDir = "/"
				} else if dir == "/" || dir == "/root" {
					currentDir = dir
				} else {
					currentDir = currentDir + "/" + dir
				}
				prompt = fmt.Sprintf("root@server:%s# ", currentDir)
			}
			conn.Write([]byte(prompt))
		case "history":
			output := ""
			for i, cmd := range commandHistory {
				output += fmt.Sprintf(" %d  %s\r\n", i+1, cmd)
			}
			conn.Write([]byte(output + prompt))
		case "ps", "ps aux":
			output := "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
			output += "root         1  0.0  0.1  22536  3824 ?        Ss   Dec10   0:01 /sbin/init\r\n"
			output += "root       456  0.0  0.2  47864  8960 ?        Ss   Dec10   0:02 /usr/sbin/sshd\r\n"
			output += "root       789  0.0  0.1  23456  5120 ?        S    Dec10   0:00 /usr/sbin/apache2\r\n"
			conn.Write([]byte(output + prompt))
		case "netstat", "netstat -an":
			output := "Active Internet connections (servers and established)\r\n"
			output += "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
			output += "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
			output += "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
			conn.Write([]byte(output + prompt))
		case "ifconfig", "ip", "ip addr":
			output := "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\r\n"
			output += "    inet 127.0.0.1/8 scope host lo\r\n"
			output += "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP\r\n"
			output += "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\r\n"
			conn.Write([]byte(output + prompt))
		case "wget", "curl":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("Connecting to %s...\r\n", args[0])))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
				conn.Write([]byte("Length: 1024 (1.0K) [text/html]\r\n"))
				conn.Write([]byte("Saving to: 'index.html'\r\n"))
				conn.Write([]byte("100%[======================================>] 1,024      --.-K/s   in 0s\r\n"))
				conn.Write([]byte("'index.html' saved [1024/1024]\r\n" + prompt))
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing URL\r\n", cmd) + prompt))
			}
		default:
			time.Sleep(50 * time.Millisecond)
			conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\r\n", cmd) + prompt))
		}
	}
}

// handleHTTP simulates HTTP server interaction
func (h *Handler) handleHTTP(conn net.Conn, remote, t string) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	ip := strings.Split(remote, ":")[0]

	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return
	}

	requestLine := lines[0]
	h.logChan <- fmt.Sprintf("[%s] HTTP REQUEST: %s", t, requestLine)
	logger.LogAttack(ip, fmt.Sprintf("HTTP: %s", requestLine))

	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	path := parts[1]

	var response string

	switch path {
	case "/", "/index.html", "/index.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "Content-Length: 1024\r\n"
		response += "Connection: keep-alive\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Welcome</title></head>"
		response += "<body><h1>Welcome to Server</h1><p>System is running normally.</p>"
		response += "<a href='/admin'>Admin Panel</a> | <a href='/login'>Login</a></body></html>"
	case "/admin", "/admin.php", "/admin.html":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Admin Panel</title></head>"
		response += "<body><h1>Administration Panel</h1>"
		response += "<form method='POST' action='/admin/login'>"
		response += "<input type='text' name='username' placeholder='Username'><br>"
		response += "<input type='password' name='password' placeholder='Password'><br>"
		response += "<button type='submit'>Login</button></form></body></html>"
	case "/login", "/login.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: Apache/2.4.41 (Debian)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Login</title></head>"
		response += "<body><h1>User Login</h1>"
		response += "<form method='POST' action='/login/check'>"
		response += "<input type='text' name='user' placeholder='Username'><br>"
		response += "<input type='password' name='pass' placeholder='Password'><br>"
		response += "<button type='submit'>Sign In</button></form></body></html>"
	case "/api", "/api/v1", "/api/users":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: application/json\r\n"
		response += "\r\n"
		response += `{"status":"ok","data":[{"id":1,"name":"admin"},{"id":2,"name":"user"}]}`
	case "/robots.txt":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: text/plain\r\n"
		response += "\r\n"
		response += "User-agent: *\nDisallow: /admin/\nDisallow: /private/"
	case "/.git", "/.git/config":
		response = "HTTP/1.1 403 Forbidden\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "\r\n"
		response += "403 Forbidden"
	default:
		if method == "POST" && strings.Contains(request, "password") {
			h.logChan <- fmt.Sprintf("[%s] HTTP POST with credentials detected!", t)
			response = "HTTP/1.1 302 Found\r\n"
			response += "Location: /admin/dashboard\r\n"
			response += "\r\n"
		} else {
			response = "HTTP/1.1 404 Not Found\r\n"
			response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
			response += "Content-Type: text/html\r\n"
			response += "\r\n"
			response += "<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>"
		}
	}

	conn.Write([]byte(response))
	time.Sleep(100 * time.Millisecond)
}

// handleTelnet simulates Telnet login interaction
func (h *Handler) handleTelnet(conn net.Conn, remote, t string) {
	conn.Write([]byte("\r\nUbuntu 20.04.3 LTS\r\n\r\n"))
	time.Sleep(200 * time.Millisecond)
	conn.Write([]byte("server login: "))

	buf := make([]byte, 1024)
	loginAttempts := 0

	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	username := strings.TrimSpace(string(buf[:n]))
	h.logChan <- fmt.Sprintf("[%s] TELNET LOGIN ATTEMPT: username='%s'", t, username)

	conn.Write([]byte("\r\nPassword: "))

	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	password := strings.TrimSpace(string(buf[:n]))
	loginAttempts++

	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s (password length: %d)", t, loginAttempts, ip, len(password))
	logger.LogAttack(ip, fmt.Sprintf("TELNET_LOGIN: user=%s, pass=***", username))

	time.Sleep(500 * time.Millisecond)

	if loginAttempts < 3 {
		conn.Write([]byte("\r\nLogin incorrect\r\n\r\n"))
		conn.Write([]byte("server login: "))
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		username = strings.TrimSpace(string(buf[:n]))
		conn.Write([]byte("\r\nPassword: "))
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		loginAttempts++
		h.logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s", t, loginAttempts, ip)
	}

	conn.Write([]byte("\r\nToo many login attempts. Connection closed.\r\n"))
}

// handleMySQL simulates MySQL authentication
func (h *Handler) handleMySQL(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] MySQL connection attempt from %s", t, ip)
	logger.LogAttack(ip, "MySQL_CONNECTION")

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	if n > 4 {
		usernameLen := int(buf[4])
		if usernameLen > 0 && usernameLen < 32 {
			username := string(buf[5 : 5+usernameLen])
			h.logChan <- fmt.Sprintf("[%s] MySQL LOGIN: username='%s'", t, username)
			logger.LogAttack(ip, fmt.Sprintf("MySQL_LOGIN: user=%s", username))
		}
	}

	errorPacket := []byte{0xff, 0x15, 0x04, 0x23, 0x28, 0x30, 0x30, 0x30, 0x30, 0x34}
	errorPacket = append(errorPacket, []byte("Access denied for user")...)
	conn.Write(errorPacket)

	time.Sleep(100 * time.Millisecond)
}

// handleRedis simulates Redis command interaction
func (h *Handler) handleRedis(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] Redis connection from %s", t, ip)
	logger.LogAttack(ip, "REDIS_CONNECTION")

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		h.logChan <- fmt.Sprintf("[%s] REDIS COMMAND: %s", t, command)
		logger.LogAttack(ip, fmt.Sprintf("REDIS: %s", command))

		parts := strings.Fields(command)
		if len(parts) == 0 {
			conn.Write([]byte("-ERR unknown command\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		switch cmd {
		case "PING":
			conn.Write([]byte("+PONG\r\n"))
		case "INFO":
			conn.Write([]byte("$100\r\n# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\nos:Linux 5.4.0 x86_64\r\n"))
		case "GET":
			if len(args) > 0 {
				conn.Write([]byte("$-1\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'get' command\r\n"))
			}
		case "SET":
			if len(args) >= 2 {
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'set' command\r\n"))
			}
		case "KEYS":
			conn.Write([]byte("*0\r\n"))
		case "AUTH":
			if len(args) > 0 {
				h.logChan <- fmt.Sprintf("[%s] REDIS AUTH attempt with password", t)
				conn.Write([]byte("-ERR invalid password\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n"))
			}
		case "QUIT", "EXIT":
			conn.Write([]byte("+OK\r\n"))
			return
		default:
			conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd)))
		}
	}
}

// handleFTP simulates FTP server interaction
func (h *Handler) handleFTP(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	h.logChan <- fmt.Sprintf("[%s] FTP connection from %s", t, ip)
	logger.LogAttack(ip, "FTP_CONNECTION")

	conn.Write([]byte("220 Welcome to FTP Server\r\n"))

	buf := make([]byte, 1024)
	authenticated := false

	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		h.logChan <- fmt.Sprintf("[%s] FTP COMMAND: %s", t, command)
		logger.LogAttack(ip, fmt.Sprintf("FTP: %s", command))

		parts := strings.Fields(command)
		if len(parts) == 0 {
			conn.Write([]byte("500 Syntax error\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		switch cmd {
		case "USER":
			if len(args) > 0 {
				username := args[0]
				h.logChan <- fmt.Sprintf("[%s] FTP USER: %s", t, username)
				conn.Write([]byte("331 Password required\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "PASS":
			if len(args) > 0 {
				password := args[0]
				h.logChan <- fmt.Sprintf("[%s] FTP PASS attempt (password length: %d)", t, len(password))
				logger.LogAttack(ip, "FTP_LOGIN: pass=***")
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("530 Login incorrect\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "SYST":
			conn.Write([]byte("215 UNIX Type: L8\r\n"))
		case "PWD":
			conn.Write([]byte("257 \"/\" is current directory\r\n"))
		case "LIST", "LS":
			if authenticated {
				conn.Write([]byte("150 Opening ASCII mode data connection\r\n"))
				time.Sleep(100 * time.Millisecond)
				conn.Write([]byte("226 Transfer complete\r\n"))
			} else {
				conn.Write([]byte("530 Please login with USER and PASS\r\n"))
			}
		case "CWD":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("250 CWD command successful: %s\r\n", args[0])))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "RETR", "GET":
			if len(args) > 0 {
				conn.Write([]byte("550 File not found\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "STOR", "PUT":
			if len(args) > 0 {
				conn.Write([]byte("553 Requested action not taken\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "QUIT", "BYE":
			conn.Write([]byte("221 Goodbye\r\n"))
			return
		case "HELP":
			conn.Write([]byte("214-The following commands are recognized:\r\n"))
			conn.Write([]byte(" USER PASS SYST PWD LIST CWD RETR STOR QUIT\r\n"))
			conn.Write([]byte("214 Help OK\r\n"))
		default:
			conn.Write([]byte("502 Command not implemented\r\n"))
		}
	}
}

