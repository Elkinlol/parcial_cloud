package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	hx      *Exec // VM del balanceador HAProxy
	reSvc   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,40}$`)
	rePath  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,100}$`)
	reArgs  = regexp.MustCompile(`^[A-Za-z0-9_ ./:=,@-]{0,200}$`)
	reSrv   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,30}$`)
	svcActs = map[string]bool{"start": true, "stop": true, "restart": true, "status": true, "enable": true, "disable": true}
)

type Srv struct{ Name, Addr string }

func registerExtra() {
	http.HandleFunc("POST /config", cfgSave)
	http.HandleFunc("POST /svc/deploy", svcDeploy)
	http.HandleFunc("POST /svc/action", svcAction)
	http.HandleFunc("POST /lb/add", func(w http.ResponseWriter, r *http.Request) { lbApply(w, r, true) })
	http.HandleFunc("POST /lb/del", func(w http.ResponseWriter, r *http.Request) { lbApply(w, r, false) })
	http.HandleFunc("POST /lb/rootkey", lbKey)
}

// ---------- configuración de conexión (config.json) ----------
type saved struct{ VM, LB Config }

func loadConfig(a, b *Config) {
	d, err := os.ReadFile("config.json")
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(d, &s) == nil {
		*a, *b = s.VM, s.LB
	}
}

func cfgSave(w http.ResponseWriter, r *http.Request) {
	c, l := ex.Config(), hx.Config()
	c.VMName, c.GuestUser, c.Host = r.FormValue("vm"), r.FormValue("guser"), strings.TrimSpace(r.FormValue("host"))
	l.VMName, l.GuestUser, l.Host = r.FormValue("lvm"), r.FormValue("luser"), strings.TrimSpace(r.FormValue("lhost"))
	if p := r.FormValue("gpass"); p != "" {
		c.GuestPass = p
	}
	if p := r.FormValue("lpass"); p != "" {
		l.GuestPass = p
	}
	ex.SetConfig(c)
	hx.SetConfig(l)
	d, _ := json.MarshalIndent(saved{c, l}, "", "  ")
	os.WriteFile("config.json", d, 0o600)
	var res []string
	bad := false
	if c.VMName != "" {
		if out, err := ex.Run("hostname"); err != nil {
			bad = true
			res = append(res, "VM principal: ERROR\n"+err.Error())
		} else {
			res = append(res, "VM principal: OK, hostname "+strings.TrimSpace(out))
		}
	}
	if l.VMName != "" {
		if out, err := hx.Run("hostname"); err != nil {
			bad = true
			res = append(res, "Balanceador: ERROR\n"+err.Error())
		} else {
			res = append(res, "Balanceador: OK, hostname "+strings.TrimSpace(out))
		}
	}
	msg := "Configuración guardada y conexión verificada."
	if bad {
		msg = "Configuración guardada, pero falló la verificación de la conexión."
	}
	render(w, View{Module: "config", Done: !bad, Failed: bad, Msg: msg, Detail: strings.Join(res, "\n")})
}

// ---------- 3.3 servicios systemd ----------
func svcDeploy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		fail(w, "svc", "No se pudo leer el formulario.", err.Error())
		return
	}
	name, xp, args := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("exec")), r.FormValue("args")
	if !reSvc.MatchString(name) {
		fail(w, "svc", "Nombre de servicio inválido (minúsculas, números, - y _).", "")
		return
	}
	if !rePath.MatchString(xp) || strings.Contains(xp, "..") || !reArgs.MatchString(args) {
		fail(w, "svc", "Ejecutable o argumentos inválidos.", "")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, "svc", "Debe adjuntar el ejecutable o un .tar.gz.", err.Error())
		return
	}
	defer f.Close()
	os.MkdirAll("uploads", 0o700)
	local := filepath.Join("uploads", name+".upload")
	dst, err := os.Create(local)
	if err == nil {
		_, err = io.Copy(dst, f)
		dst.Close()
	}
	if err != nil {
		fail(w, "svc", "No se pudo guardar el archivo.", err.Error())
		return
	}
	defer os.Remove(local)
	fn := strings.ToLower(hdr.Filename)
	tar := strings.HasSuffix(fn, ".tar.gz") || strings.HasSuffix(fn, ".tgz")
	if !tar {
		xp = path.Base(xp)
	}
	if err := ex.Upload(local, "/tmp"); err != nil {
		fail(w, "svc", "No se pudo transferir el archivo a la VM.", err.Error())
		return
	}
	user := "User=" + name + "\n"
	if r.FormValue("runroot") != "" {
		user = ""
	}
	unit := fmt.Sprintf("[Unit]\nDescription=Servicio %s (consola)\nAfter=network.target\n\n[Service]\n%sWorkingDirectory=/opt/%s\nExecStart=/opt/%s/%s %s\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
		name, user, name, name, xp, args)
	extract := fmt.Sprintf(`cp /tmp/%s.upload "/opt/$N/"%s`, name, q(xp))
	if tar {
		extract = `tar xzf "/tmp/$N.upload" -C "/opt/$N"`
	}
	script := fmt.Sprintf(`N=%s
id -u "$N" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$N"
rm -rf "/opt/$N"; mkdir -p "/opt/$N"
%s
rm -f "/tmp/$N.upload"
chmod +x "/opt/$N/"%s || true
chown -R "$N:$N" "/opt/$N"
echo %s | base64 -d > "/etc/systemd/system/$N.service"
systemctl daemon-reload
cat "/etc/systemd/system/$N.service"`, q(name), extract, q(xp), base64.StdEncoding.EncodeToString([]byte(unit)))
	out, err := ex.Run(script)
	if err != nil {
		fail(w, "svc", "No se pudo configurar el servicio.", out+err.Error())
		return
	}
	render(w, View{Module: "svc", Done: true, Msg: "Servicio " + name + " desplegado. Use los botones para iniciarlo.", Status: out})
}

func svcAction(w http.ResponseWriter, r *http.Request) {
	name, act := strings.TrimSpace(r.FormValue("name")), r.FormValue("act")
	if !reSvc.MatchString(name) || !svcActs[act] {
		fail(w, "svc", "Servicio o acción inválidos.", "")
		return
	}
	cmd := "systemctl " + act + " " + q(name) + ";"
	if act == "status" {
		cmd = ""
	}
	out, err := ex.Run(cmd + "(systemctl status " + q(name) + " --no-pager -l | head -n 20) || true")
	if err != nil {
		render(w, View{Module: "svc", Failed: true, Msg: "La acción '" + act + "' falló sobre " + name + ".", Status: out + err.Error()})
		return
	}
	render(w, View{Module: "svc", Done: true, Msg: "Acción '" + act + "' ejecutada sobre " + name + ".", Status: out})
}

// ---------- 3.4 HAProxy ----------
const lbHead = `C=/etc/haproxy/haproxy.cfg; L=/etc/haproxy/consola-servers.list
command -v haproxy >/dev/null || { echo "haproxy no está instalado"; exit 1; }
touch "$L"; cp "$C" "$C.bak"; cp "$L" "$L.bak"
`
const lbRegen = `
sed -i '/^# BEGIN consola/,/^# END consola/d' "$C"
{ echo "# BEGIN consola"; echo "frontend consola_front"; echo "    bind *:80"; echo "    default_backend consola_back"
  echo "backend consola_back"; echo "    balance roundrobin"
  while read -r n a; do [ -n "$n" ] && echo "    server $n $a check"; done < "$L"
  echo "# END consola"; } >> "$C"
if haproxy -c -f "$C"; then systemctl reload haproxy; else cp "$C.bak" "$C"; cp "$L.bak" "$L"; echo "Configuración inválida: se revirtió"; exit 1; fi
sed -n '/^# BEGIN consola/,/^# END consola/p' "$C"
`

func extraLB(v *View) {
	out, err := hx.Run(`touch /etc/haproxy/consola-servers.list; cat /etc/haproxy/consola-servers.list`)
	if err != nil && v.Msg == "" {
		v.Failed, v.Msg, v.Detail = true, "No se pudo consultar el balanceador (revise la pantalla Conexión).", err.Error()
	}
	for _, l := range strings.Split(out, "\n") {
		if p := strings.Fields(l); len(p) == 2 {
			v.Servers = append(v.Servers, Srv{p[0], p[1]})
		}
	}
}

func lbApply(w http.ResponseWriter, r *http.Request, add bool) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !reSrv.MatchString(name) {
		fail(w, "lb", "Nombre de servidor inválido.", "")
		return
	}
	change, verb := fmt.Sprintf(`sed -i "/^%s /d" "$L"`, name), "eliminado"
	if add {
		ip, port := net.ParseIP(strings.TrimSpace(r.FormValue("ip"))), 0
		port, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
		if ip == nil || port < 1 || port > 65535 {
			fail(w, "lb", "IP o puerto inválidos.", "")
			return
		}
		change = fmt.Sprintf(`grep -q "^%s " "$L" && { echo "ya existe un servidor con ese nombre"; exit 1; }
echo "%s %s:%d" >> "$L"`, name, name, ip.String(), port)
		verb = "agregado"
	}
	out, err := hx.Run(lbHead + change + "\n" + lbRegen)
	if err != nil {
		fail(w, "lb", "No se pudo actualizar el balanceador.", out+err.Error())
		return
	}
	ok(w, "lb", "Servidor "+name+" "+verb+" y HAProxy recargado.", out, "")
}

func lbKey(w http.ResponseWriter, r *http.Request) {
	if err := setupKey(hx, "root", "lb-root"); err != nil {
		fail(w, "lb", "No se pudo configurar la llave SSH del balanceador.", err.Error())
		return
	}
	c := hx.Config()
	c.KeyPath = filepath.Join("keys", "lb-root.pem")
	hx.SetConfig(c)
	if _, err := hx.Run("echo ok"); err != nil {
		hx.UseSSH(false)
		fail(w, "lb", "Llave creada, pero la prueba SSH falló (¿IP del balanceador en Conexión?).", err.Error())
		return
	}
	ok(w, "lb", "Llave SSH del balanceador configurada; ahora se usa SSH.", "", "lb-root")
}
