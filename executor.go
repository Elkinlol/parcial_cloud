package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config: datos para hablar con una VM.
type Config struct {
	VMName, GuestUser, GuestPass string // Guest Additions (VBoxManage)
	Host, KeyPath                string // SSH
}

// Exec ejecuta scripts bash en una VM. Antes de SSH usa Guest Additions;
// cuando se configura la llave de root pasa a SSH con llave (UseSSH).
type Exec struct {
	mu  sync.RWMutex
	cfg Config
	ssh bool
}

func (e *Exec) UseSSH(on bool) { e.mu.Lock(); e.ssh = on; e.mu.Unlock() }
func (e *Exec) Config() Config { e.mu.RLock(); defer e.mu.RUnlock(); return e.cfg }
func (e *Exec) SetConfig(c Config) {
	e.mu.Lock()
	e.cfg = c
	e.ssh = c.Host != "" && fileExists(c.KeyPath)
	e.mu.Unlock()
}
func (e *Exec) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.ssh {
		return "SSH (llave)"
	}
	return "Guest Additions"
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// Run ejecuta el script y devuelve stdout. El error incluye stderr para diagnóstico.
func (e *Exec) Run(script string) (string, error) {
	script = "set -euo pipefail\nexport DEBIAN_FRONTEND=noninteractive\n" + script
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	e.mu.RLock()
	useSSH, c := e.ssh, e.cfg
	e.mu.RUnlock()

	var cmd *exec.Cmd
	if useSSH {
		cmd = exec.CommandContext(ctx, "ssh", "-i", c.KeyPath, "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
			"root@"+c.Host, "bash -s")
		cmd.Stdin = strings.NewReader(script)
	} else {
		enc := base64.StdEncoding.EncodeToString([]byte(script))
		cmd = exec.CommandContext(ctx, "VBoxManage", "guestcontrol", c.VMName, "run",
			"--username", c.GuestUser, "--password", c.GuestPass,
			"--wait-stdout", "--wait-stderr",
			"--", "/bin/bash", "-c", "echo "+enc+" | base64 -d | bash")
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	logOp(script, so.String(), se.String(), err)
	if err != nil {
		return so.String(), fmt.Errorf("%v\n%s", err, se.String())
	}
	return so.String(), nil
}

// Upload copia un archivo local (ruta relativa) al directorio remoto, por scp o Guest Additions.
func (e *Exec) Upload(local, remoteDir string) error {
	e.mu.RLock()
	useSSH, c := e.ssh, e.cfg
	e.mu.RUnlock()
	var cmd *exec.Cmd
	if useSSH {
		cmd = exec.Command("scp", "-i", c.KeyPath, "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new", filepath.ToSlash(local), "root@"+c.Host+":"+remoteDir+"/")
	} else {
		cmd = exec.Command("VBoxManage", "guestcontrol", c.VMName, "copyto",
			"--username", c.GuestUser, "--password", c.GuestPass,
			"--target-directory", remoteDir, local)
	}
	var se bytes.Buffer
	cmd.Stderr = &se
	err := cmd.Run()
	logOp("UPLOAD "+local+" -> "+remoteDir, "", se.String(), err)
	if err != nil {
		return fmt.Errorf("%v\n%s", err, se.String())
	}
	return nil
}

// logOp guarda información técnica para diagnóstico (ops.log). No registra llaves privadas.
func logOp(script, out, errOut string, err error) {
	f, e := os.OpenFile("ops.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if e != nil {
		return
	}
	defer f.Close()
	if strings.Contains(script, "PRIVATE KEY") || strings.Contains(out, "PRIVATE KEY") {
		out = "[salida con llave privada omitida]"
	}
	fmt.Fprintf(f, "=== %s err=%v\n--- script\n%s\n--- stdout\n%s\n--- stderr\n%s\n", time.Now().Format(time.RFC3339), err, script, out, errOut)
}

// q escapa un valor para usarlo dentro de un script bash.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func protectKey(p string) {
	if runtime.GOOS == "windows" {
		who, err := exec.Command("whoami").Output()
		if err != nil {
			return
		}
		exec.Command("icacls", p, "/inheritance:r", "/grant:r", strings.TrimSpace(string(who))+":(F)").Run()
	}
}
