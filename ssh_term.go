package sshTerm

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	EVENT_STDIN = iota
	EVENT_STDOUT
	EVENT_STDERR
)

type SshTerm struct {
	hp       string
	cfg      *ssh.ClientConfig
	conn     *ssh.Client
	sess     *ssh.Session
	timeout  time.Duration
	events   map[uint8][]ioCallback
	stdin    io.WriteCloser
	connSucc bool
}

type ioCallback func([]byte, *SshTerm)
type ioCopy struct {
	parent *SshTerm
	event  uint8
}

func (wh *ioCopy) Write(p []byte) (n int, err error) {
	if len(wh.parent.events[wh.event]) == 0 {
		return 0, nil
	}
	for _, cb := range wh.parent.events[wh.event] {
		cb(p, wh.parent)
	}
	return len(p), nil
}

func NewSshTerm(hostport, user, password string, timeout time.Duration) (*SshTerm, error) {
	st := &SshTerm{hp: hostport, connSucc: false}
	st.cfg = &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	st.events = make(map[uint8][]ioCallback)
	return st, nil
}

func (st *SshTerm) On(et uint8, cb ioCallback) {
	if _, ok := st.events[et]; !ok {
		st.events[et] = make([]ioCallback, 0)
	}
	st.events[et] = append(st.events[et], cb)
}

func (st *SshTerm) Start() error {
	if err := st.connect(); err != nil {
		return err
	}

	session, err := st.conn.NewSession()
	if err != nil {
		return fmt.Errorf("Cannot open new session: %v", err)
	}
	st.sess = session

	fd := int(os.Stdout.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("Terminal make raw: %s", err)
	}
	defer terminal.Restore(fd, state)

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return fmt.Errorf("Terminal get size: %s", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	if err := st.sess.RequestPty(term, h, w, modes); err != nil {
		return fmt.Errorf("Session xterm: %s", err)
	}

	st.stdin, err = st.sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("Create stdinpipe fail")
	}

	if len(st.events[EVENT_STDOUT]) > 0 {
		stdoutCopyer := &ioCopy{parent: st, event: EVENT_STDOUT}
		st.sess.Stdout = io.MultiWriter(stdoutCopyer, os.Stdout)
	} else {
		st.sess.Stdout = os.Stdout
	}

	if len(st.events[EVENT_STDERR]) > 0 {
		stderrCopyer := &ioCopy{parent: st, event: EVENT_STDERR}
		st.sess.Stderr = io.MultiWriter(stderrCopyer, os.Stderr)
	} else {
		st.sess.Stderr = os.Stderr
	}

	// sync stdin to remote
	go func() {
		call := len(st.events[EVENT_STDIN]) > 0
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Read from stdin fail:%s", err)
				return
			}
			if n > 0 {
				_, _ = st.stdin.Write(buf[:n])
			}
			if call {
				for _, cb := range st.events[EVENT_STDIN] {
					cb(buf[:n], st)
				}
			}
		}
	}()

	if err := st.sess.Shell(); err != nil {
		return fmt.Errorf("session shell: %s", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	go func() {
		for {
			<-sig
			w, h, err := terminal.GetSize(int(os.Stdin.Fd()))
			if err == nil {
				st.WindowChange(h, w)
			}
		}
	}()

	st.connSucc = true
	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		if _, ok := err.(*ssh.ExitMissingError); ok {
			return nil
		}
		return fmt.Errorf("ssh: %s", err)
	}
	return nil
}

func (st *SshTerm) WindowChange(h, w int) error {
	if !st.connSucc {
		return nil
	}
	return st.sess.WindowChange(h, w)
}

func (st *SshTerm) connect() error {
	conn, err := ssh.Dial("tcp", st.hp, st.cfg)
	if err != nil {
		return fmt.Errorf("cannot connect %v: %v", st.hp, err)
	}
	st.conn = conn
	return nil
}

func (st *SshTerm) Started() bool {
	return st.connSucc
}

func (st *SshTerm) Shutdown() {
	if st.connSucc {
		if st.sess != nil {
			st.sess.Close()
		}
		st.conn.Close()
		st.connSucc = false
	}
}
