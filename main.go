package main

import (
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed templates/*.html
var tplFS embed.FS
var tpl = template.Must(template.ParseFS(tplFS, "templates/*.html"))

var (
	ex     *Exec
	reUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	rePkg  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{1,100}$`)
	reHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reCtl  = regexp.MustCompile(`[^\x20-\x7E]`)
)

type View struct {
	Module, Mode, Msg, Detail, KeyName string
	Done, Failed                       bool
	Users                              []string
	Servers                            []Srv
	Cfg, LB                            Config
	Status                             string
}

func main() {
	addr := flag.String("addr", ":8086", "dirección de escucha")
	c := Config{}
	flag.StringVar(&c.VMName, "vm", "debian-pruebas", "nombre de la VM en VirtualBox")
	flag.StringVar(&c.GuestUser, "guser", "root", "usuario para Guest Additions")
	flag.StringVar(&c.GuestPass, "gpass", "", "contraseña para Guest Additions")
	flag.StringVar(&c.Host, "host", "", "IP de la VM (modo puente)")
	flag.StringVar(&c.KeyPath, "key", "keys/root.pem", "llave privada de root")
	flag.Parse()
	os.MkdirAll("keys", 0o700)
	lb := Config{VMName: "balanceador", GuestUser: "root", KeyPath: "keys/lb-root.pem"}
	loadConfig(&c, &lb)
	if c.KeyPath == "" {
		c.KeyPath = "keys/root.pem"
	}
	ex, hx = &Exec{cfg: c}, &Exec{cfg: lb}
	ex.SetConfig(c)
	hx.SetConfig(lb)
	registerExtra()

	for _, m := range []string{"home", "prep", "users", "svc", "lb", "config"} {
		p := "/" + m
		if m == "home" {
			p = "/{$}"
		}
		mod := m
		http.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) { render(w, View{Module: mod}) })
	}
	http.HandleFunc("POST /prep/install", pkgOp("install"))
	http.HandleFunc("POST /prep/remove", pkgOp("remove"))
	http.HandleFunc("POST /prep/rootkey", rootKey)
	http.HandleFunc("POST /prep/issue", issue)
	http.HandleFunc("POST /prep/hostname", hostname)
	http.HandleFunc("POST /users/create", userCreate)
	http.HandleFunc("POST /users/delete", userDelete)
	http.HandleFunc("GET /download", download)
	log.Println("Consola en", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func render(w http.ResponseWriter, v View) {
	v.Mode = ex.Mode()
	switch v.Module {
	case "users":
		out, err := ex.Run(`getent passwd | awk -F: '$3>=1000 && $3<60000 {print $1}'`)
		v.Users = strings.Fields(out)
		if err != nil && v.Msg == "" {
			v.Failed, v.Msg, v.Detail = true, "No se pudo consultar la VM (revise la pantalla Conexión).", err.Error()
		}
	case "lb":
		extraLB(&v)
	case "config":
		v.Cfg, v.LB = ex.Config(), hx.Config()
	}
	if err := tpl.ExecuteTemplate(w, "page.html", v); err != nil {
		log.Println(err)
	}
}

func fail(w http.ResponseWriter, mod, msg, detail string) {
	render(w, View{Module: mod, Failed: true, Msg: msg, Detail: detail})
}
func ok(w http.ResponseWriter, mod, msg, detail string, key string) {
	render(w, View{Module: mod, Done: true, Msg: msg, Detail: detail, KeyName: key})
}

// ---------- 3.1.1 instalar / eliminar ----------
func pkgOp(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pkg := strings.TrimSpace(r.FormValue("pkg"))
		if !rePkg.MatchString(pkg) {
			fail(w, "prep", "Nombre de paquete inválido (use minúsculas, números, + . -).", "")
			return
		}
		cmd := "apt-get install -y "
		if action == "remove" {
			cmd = "apt-get remove -y "
		}
		out, err := ex.Run(cmd + q(pkg))
		if err != nil {
			fail(w, "prep", "No se pudo ejecutar "+action+" de "+pkg+".", out+err.Error())
			return
		}
		ok(w, "prep", "Operación '"+action+"' de "+pkg+" terminó correctamente.", out, "")
	}
}

// ---------- llaves SSH (reutilizado por root y por usuarios nuevos) ----------
const hardenSSH = `printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes\n' > /etc/ssh/sshd_config.d/00-consola.conf
sshd -t && systemctl reload ssh`

func setupKey(e *Exec, user, file string) error {
	home := "/root"
	if user != "root" {
		home = "/home/" + user
	}
	priv, err := e.Run(fmt.Sprintf(`H=%s; U=%s
install -d -m700 -o "$U" -g "$U" "$H/.ssh"
rm -f "$H/.ssh/id_ed25519" "$H/.ssh/id_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -C "$U@consola" -f "$H/.ssh/id_ed25519"
cp "$H/.ssh/id_ed25519.pub" "$H/.ssh/authorized_keys"
chown -R "$U:$U" "$H/.ssh"; chmod 600 "$H/.ssh/authorized_keys"
%s
cat "$H/.ssh/id_ed25519"`, q(home), q(user), hardenSSH))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("keys", file+".pem"), []byte(priv), 0o600); err != nil {
		return err
	}
	protectKey(filepath.Join("keys", file+".pem"))
	// la llave privada ya está en el servidor web: se elimina de la VM
	_, err = e.Run(fmt.Sprintf(`shred -u %s/.ssh/id_ed25519`, q(home)))
	return err
}

// ---------- 3.1.2 llave de root ----------
func rootKey(w http.ResponseWriter, r *http.Request) {
	if err := setupKey(ex, "root", "root"); err != nil {
		fail(w, "prep", "No se pudo configurar la llave SSH de root.", err.Error())
		return
	}
	ex.UseSSH(true)
	if _, err := ex.Run("echo ok"); err != nil { // verificación por SSH
		ex.UseSSH(false)
		fail(w, "prep", "La llave se creó pero la prueba de conexión SSH falló (¿flag -host correcto?).", err.Error())
		return
	}
	ok(w, "prep", "Llave SSH de root configurada. Acceso por contraseña deshabilitado; la consola ahora se comunica por SSH.", "", "root")
}

// ---------- 3.1.3 /etc/issue ----------
func issue(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("Debian GNU/Linux \\l\n")
	if r.FormValue("host") != "" {
		b.WriteString("Host: \\n\n")
	}
	if r.FormValue("fecha") != "" {
		b.WriteString("Fecha: \\d\n")
	}
	if r.FormValue("hora") != "" {
		b.WriteString("Hora: \\t\n")
	}
	if r.FormValue("ip") != "" {
		b.WriteString("IP: \\4\n")
	}
	msg := reCtl.ReplaceAllString(r.FormValue("msg"), "")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg != "" {
		b.WriteString(strings.ReplaceAll(msg, `\`, `\\`) + "\n")
	}
	enc := base64.StdEncoding.EncodeToString([]byte(b.String()))
	out, err := ex.Run("echo " + enc + " | base64 -d > /etc/issue; cat /etc/issue")
	if err != nil {
		fail(w, "prep", "No se pudo escribir /etc/issue.", err.Error())
		return
	}
	ok(w, "prep", "/etc/issue actualizado. Contenido:", out, "")
}

// ---------- 3.1.4 hostname + /etc/hosts ----------
func hostname(w http.ResponseWriter, r *http.Request) {
	h := strings.TrimSpace(r.FormValue("hostname"))
	if !reHost.MatchString(h) {
		fail(w, "prep", "Nombre de host inválido (a-z, 0-9 y guion; máx. 63).", "")
		return
	}
	out, err := ex.Run(fmt.Sprintf(`hostnamectl set-hostname %s
sed -i '/^127\.0\.1\.1/d' /etc/hosts
echo "127.0.1.1	%s" >> /etc/hosts
hostname; cat /etc/hosts`, q(h), h))
	if err != nil {
		fail(w, "prep", "No se pudo asignar el nombre de host.", out+err.Error())
		return
	}
	ok(w, "prep", "Nombre de host asignado y /etc/hosts actualizado.", out, "")
}

// ---------- 3.2.1 crear usuario ----------
func userCreate(w http.ResponseWriter, r *http.Request) {
	u, pass := strings.TrimSpace(r.FormValue("user")), r.FormValue("pass")
	if !reUser.MatchString(u) || u == "root" {
		fail(w, "users", "Nombre de usuario inválido.", "")
		return
	}
	if len(pass) < 6 || strings.ContainsAny(pass, "\r\n") {
		fail(w, "users", "La contraseña debe tener al menos 6 caracteres.", "")
		return
	}
	script := fmt.Sprintf("useradd -m -s /bin/bash %s\necho %s | chpasswd\n", q(u), q(u+":"+pass))
	if r.FormValue("sudo") != "" {
		script += fmt.Sprintf("command -v sudo >/dev/null || apt-get install -y sudo\nusermod -aG sudo %s\n", q(u))
	}
	out, err := ex.Run(script + "id " + q(u))
	if err != nil {
		fail(w, "users", "No se pudo crear el usuario.", out+err.Error())
		return
	}
	key := ""
	if r.FormValue("key") != "" {
		if err := setupKey(ex, u, u); err != nil {
			fail(w, "users", "Usuario creado, pero falló la configuración de la llave SSH.", err.Error())
			return
		}
		key = u
	}
	ok(w, "users", "Usuario "+u+" creado correctamente.", out, key)
}

// ---------- 3.2.2 eliminar usuario ----------
func userDelete(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("user")
	if !reUser.MatchString(u) || u == "root" {
		fail(w, "users", "Usuario inválido.", "")
		return
	}
	flag := ""
	if r.FormValue("files") != "" {
		flag = "-r "
	}
	out, err := ex.Run(fmt.Sprintf(`[ "$(id -u %s)" -ge 1000 ] || { echo "no es un usuario normal"; exit 1; }
pkill -u %s || true
userdel %s%s`, q(u), q(u), flag, q(u)))
	if err != nil {
		fail(w, "users", "No se pudo eliminar el usuario.", out+err.Error())
		return
	}
	ok(w, "users", "Usuario "+u+" eliminado.", out, "")
}

// ---------- descarga de llaves privadas ----------
func download(w http.ResponseWriter, r *http.Request) {
	n := r.URL.Query().Get("f")
	if n != "root" && !reUser.MatchString(n) {
		http.Error(w, "nombre inválido", 400)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+n+`.pem"`)
	http.ServeFile(w, r, filepath.Join("keys", n+".pem"))
}
