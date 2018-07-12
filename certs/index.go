package certs

import (
  "os"
  "os/exec"
  "encoding/json"
  "bufio"
  "fmt"
  path "path/filepath"
  "io/ioutil"
  "sync"
  "github.com/jkk111/indigo/util"
)

var base_path = util.Path("certs")

var config_path = util.Path("certs/config.json")

var ca_key_path = util.Path("certs/ca.key")
var ca_crt_path = util.Path("certs/ca.crt")
var ca_csr_path = util.Path("certs/ca.csr")

var admin_cert_path = util.Path("certs/admin.pfx")
const open_flags = os.O_CREATE|os.O_RDWR|os.O_TRUNC

const key_len = "4096"

var base_key_path = util.Path("certs/keys")

var config * Config
var config_mutex = sync.Mutex{}

type Config struct {
  C  string 
  ST string
  L  string
  O  string
  OU string
  CN string
  Serial int
}

func (this * Config) CASubj() string {
  return fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s",
    this.C,
    this.ST,
    this.L,
    this.O,
    this.OU,
    this.CN,
  )
}

func (this * Config) Subj(email string) string {
  return fmt.Sprintf("%s/emailAddress=%s", this.CASubj(), email)
}

func (this * Config) NextSerial() int {
  config_mutex.Lock()
  next := this.Serial
  this.Serial++
  config_mutex.Unlock()
  return next
}

func (this * Config) Save() {
  marshaled, err := json.Marshal(this)
  Must(err)
  f, err := os.OpenFile(config_path, open_flags, 0755)
  Must(err)
  f.Write(marshaled)
  f.Close()
}

func Must(err error) {
  if err != nil {
    panic(err)
  }
}

func gen_key(path string) {
  params := []string {
    "genrsa",
    "-out",
    path,
    key_len,
  }

  cmd := exec.Command("openssl", params...)
  Must(cmd.Run())
}

func gen_csr(key string, path string, email string) {
  params := []string {
    "req",
    "-new",
    "-key", 
    key,
    "-subj",
    config.Subj(email),
    "-out",
    path,
  }

  cmd := exec.Command("openssl", params...)
  Must(cmd.Run())
}

func gen_crt(key string, csr string, crt string) {
  serial := fmt.Sprintf("%d", config.NextSerial())

  params := []string {
    "x509", 
    "-req", 
    "-days", 
    "365", 
    "-in", 
    csr, 
    "-CA", 
    ca_crt_path, 
    "-CAkey", 
    ca_key_path, 
    "-set_serial", 
    serial, 
    "-out", 
    crt,
  }

  cmd := exec.Command("openssl", params...)
  Must(cmd.Run())
}

func gen_pfx(key string, crt string, pfx string, password string) {
  params := []string {
    "pkcs12", 
    "-export", 
    "-nodes", 
    "-out", 
    pfx, 
    "-inkey", 
    key, 
    "-in", 
    crt,
    "-passout", 
    fmt.Sprintf("pass:%s", password),
  }

  cmd := exec.Command("openssl", params...)
  err := cmd.Run()
  Must(err)
}

func gen_ca_cert(config * Config, path string, key string) {
  params := []string {
    "req", 
    "-subj", 
    config.CASubj(), 
    "-new", 
    "-x509", 
    "-days", 
    "3650", 
    "-key", 
    key, 
    "-out", 
    path,
  }

  cmd := exec.Command("openssl", params...)
  Must(cmd.Run())
}

func gen_ca(config * Config) {
  gen_key(ca_key_path)
  gen_ca_cert(config, ca_crt_path, ca_key_path)
}

func prompt(scanner * bufio.Scanner, message string) string {
  fmt.Printf("%s: ", message)
  scanner.Scan()
  return scanner.Text()
}

func build_config(path string) * Config {
  scanner := bufio.NewScanner(os.Stdin)

  country := prompt(scanner, "Country")
  state := prompt(scanner, "State")
  location := prompt(scanner, "Location")
  organization := prompt(scanner, "Organization")
  organizational_unit := prompt(scanner, "Organizational Unit")
  common_name := prompt(scanner, "Common Name")

  config := &Config{
    C:  country,
    ST: state,
    L:  location,
    O:  organization,
    OU: organizational_unit,
    CN: common_name,
    Serial: 1,
  }

  marshaled, err := json.Marshal(config)
  Must(err)

  f, err := os.OpenFile(path, os.O_CREATE | os.O_RDWR, 0755)
  Must(err)
  f.Write(marshaled)
  f.Close()

  return config
}

func load_config() * Config {
  os.Mkdir(base_key_path, 0700)

  f, err := os.Open(config_path)

  if err != nil {
    fmt.Println("Failed To Read Config")
    return build_config(config_path)
  }

  decoder := json.NewDecoder(f)
  var config * Config
  err = decoder.Decode(&config)

  if err != nil {
    fmt.Println("Failed To Parse Config", err)
    return build_config(config_path)
  }

  return config
}

func Cert(email string, password string) []byte {
  key_path := path.Join(base_key_path, email + ".key")
  csr_path := path.Join(base_key_path, email + ".csr")
  crt_path := path.Join(base_key_path, email + ".crt")
  pfx_path := path.Join(base_key_path, email + ".pfx")

  gen_key(key_path)
  gen_csr(key_path, csr_path, email)
  gen_crt(key_path, csr_path, crt_path)
  gen_pfx(key_path, crt_path, pfx_path, password)

  os.Remove(key_path)
  os.Remove(csr_path)
  os.Remove(crt_path)

  f, err := os.Open(pfx_path)
  Must(err)
  buf, err := ioutil.ReadAll(f)
  Must(err)
  f.Close()

  os.Remove(pfx_path)
  config.Save()
  return buf
}

func Serial() int {
  return config.Serial
}

func init() {
  util.Mkdir(base_path)
  config = load_config()
  _, err := os.Stat(ca_crt_path)
  if err != nil {
    if os.IsNotExist(err) {
      gen_ca(config)
    } else {
      panic(err)   
    }
  }

  if config.Serial == 1 {
    scanner := bufio.NewScanner(os.Stdin)
    email := prompt(scanner, "Enter Email For Admin User")
    password := prompt(scanner, "Enter Password")

    data := Cert(email, password)
    f, err := os.OpenFile(admin_cert_path, open_flags, 0700)
    Must(err)

    f.Write(data)
    f.Close()
  }
}