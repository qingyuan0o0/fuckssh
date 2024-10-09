package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"golang.org/x/crypto/ssh"
)

// 检查 IP 是否在 ./hosts.deny 中
func isIPInHostsDeny(ip string) (bool, error) {
	file, err := os.Open("./hosts.deny")
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), ip) {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// 将 IP 添加到 ./hosts.deny
func addIPToHostsDeny(ip string) error {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo 'ALL: %s' | sudo tee -a ./hosts.deny", ip))
	return cmd.Run()
}

// 实现 PasswordCallback，验证任何密码都有效
func passwordAuthHandler(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// 打印连接的IP地址、用户名和密码
	fmt.Printf("[%s] IP: %s 登录用户 %s，密码：%s\n", time.Now().Format("2006-01-02 15:04:05"), c.RemoteAddr(), c.User(), string(password))
	// 无论什么密码都允许登录
	return nil, nil
}

// 创建假的 SSH 服务器
func startSSHServer() error {
	config := &ssh.ServerConfig{
		PasswordCallback: passwordAuthHandler,
	}

	// 生成伪造的服务器私钥
	privateBytes, err := generatePrivateKey()
	if err != nil {
		return err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return err
	}

	config.AddHostKey(private)

	// 监听端口
	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		return err
	}
	fmt.Println("假 SSH 服务器正在运行...")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("无法接受连接: %v\n", err)
			continue
		}

		// 升级到 SSH 连接
		go handleSSHConnection(nConn, config)
	}
}

// 处理 SSH 连接
func handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig) {
	remoteAddr := nConn.RemoteAddr().String() // 获取IP地址
	serverConn, channels, requests, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		fmt.Printf("[%s] SSH 连接失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return
	}

	// 获取用户名
	username := serverConn.User()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "仅支持 session 类型的通道")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("[%s] 通道接受失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
			return
		}

		go handleSession(channel, requests, remoteAddr, username)
	}
}


// 处理登录后的 session
func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, remoteAddr string, username string) {
	defer channel.Close()

	// 处理所有请求
	for req := range requests {
		switch req.Type {
		case "exec":
			command := string(req.Payload[4:])
			fmt.Printf("[%s] IP: %s 用户: %s 尝试执行命令: %s\n", time.Now().Format("2006-01-02 15:04:05"), remoteAddr, username, command)

			// 检查 IP 是否已经存在于 ./hosts.deny 中
			ip := strings.Split(remoteAddr, ":")[0] // 提取IP地址
			exists, err := isIPInHostsDeny(ip)
			if err != nil {
				fmt.Printf("检查 IP 错误: %v\n", err)
			} else if !exists {
				// IP 不存在，添加到 hosts.deny
				if err := addIPToHostsDeny(ip); err != nil {
					fmt.Printf("添加 IP 错误: %v\n", err)
				} else {
					fmt.Printf("IP %s 已添加到 ./hosts.deny\n", ip)
				}
			} else {
				fmt.Printf("IP %s 已存在于 ./hosts.deny 中，跳过添加\n", ip)
			}

			// 不返回任何响应，等待30秒后断开连接
			time.Sleep(30 * time.Second)
			req.Reply(false, nil)
			return

		case "shell":
			// 等待 30 秒后关闭连接
			fmt.Printf("[%s] IP: %s 用户: %s 打开了shell\n", time.Now().Format("2006-01-02 15:04:05"), remoteAddr, username)
			time.Sleep(30 * time.Second)
			req.Reply(false, nil)
			return
		}
	}
}

// 生成 RSA 私钥
func generatePrivateKey() ([]byte, error) {
	privateKeyPath := "id_rsa"
	if _, err := os.Stat(privateKeyPath); err == nil {
		return os.ReadFile(privateKeyPath)
	}
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-f", privateKeyPath, "-N", "")
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return os.ReadFile(privateKeyPath)
}

func main() {
	if err := startSSHServer(); err != nil {
		log.Fatalf("SSH 服务器启动失败: %v", err)
	}
}