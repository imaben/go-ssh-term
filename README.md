# go-ssh-term

## Usage

```
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	sshTerm "github.com/imaben/go-ssh-term"
)

func main() {
	term, _ := sshTerm.NewSshTerm("192.168.100.100", "root", "root", 10*time.Second)
	term.On(sshTerm.EVENT_STDOUT, func(bytes []byte, st *sshTerm.SshTerm) {
		// ...
	})
	term.On(sshTerm.EVENT_STDERR, func(bytes []byte, st *sshTerm.SshTerm) {
		// ...
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for {
			<-sig
			if term.Started() {
				term.Shutdown()
			} else {
				os.Exit(1)
			}
		}
	}()

	err = term.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}
```
