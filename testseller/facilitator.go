package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	// facilitatorReady is how long a started facilitator has to answer
	facilitatorReady = 30 * time.Second
	// facilitatorStop is how long a stopped facilitator has to exit before it is killed
	facilitatorStop = 5 * time.Second
)

// facilitator is the child process that verifies and settles payments
type facilitator struct {
	cmd    *exec.Cmd
	addr   string
	exited chan struct{}
}

// startFacilitator runs facilitator_cmd with only its key, address and RPC URL, and waits for it
func startFacilitator(ctx context.Context, s settings, key string) (*facilitator, error) {
	cmd := exec.Command(s.FacilitatorCmd[0], s.FacilitatorCmd[1:]...)
	cmd.Dir = s.dir
	cmd.Env = []string{
		"TESTSELLER_FEE_PAYER_KEY=" + key,
		"FACILITATOR_ADDR=" + s.FacilitatorAddr,
		"SOLANA_RPC_URL=" + s.RPCURL,
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("facilitator_cmd did not start: %w", err)
	}
	f := &facilitator{cmd: cmd, addr: s.FacilitatorAddr, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(f.exited)
	}()
	if err := f.waitReady(ctx); err != nil {
		f.stop()
		return nil, err
	}
	return f, nil
}

// waitReady polls the facilitator's /health until it answers 200
func (f *facilitator) waitReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, facilitatorReady)
	defer cancel()
	url := "http://" + f.addr + "/health"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if res, err := http.DefaultClient.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-f.exited:
			return errors.New("the facilitator exited before it answered")
		case <-ctx.Done():
			return errors.New("the facilitator did not answer in time")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// stop ends the process with SIGTERM, and kills it when it has not exited after a short grace
func (f *facilitator) stop() {
	_ = f.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-f.exited:
	case <-time.After(facilitatorStop):
		_ = f.cmd.Process.Kill()
		<-f.exited
	}
}
