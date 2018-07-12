package certs

import (
  "fmt"
  "net/http"
  "github.com/jkk111/indigo-certs/certs"
  "github.com/jkk111/indigo-certs/assets"
)

var Router * http.ServeMux

func index(w http.ResponseWriter, req * http.Request) {
  file := assets.MustAsset("resources/index.html")
  w.Write(file)
}

func HandleGenerate(w http.ResponseWriter, req * http.Request) {
  if req.Method == "POST" {
    req.ParseForm()
    email := req.PostForm["email"][0]
    password := req.PostForm["password"][0]
    cert := certs.Cert(email, password)
    header := w.Header()
    filename := fmt.Sprintf("%s.pfx", email)
    header.Set("Content-Disposition", "filename=" + filename)
    w.Write(cert)
  } else {
    index(w, req)
  }
}

func init() {
  Router = http.NewServeMux()
  Router.HandleFunc("/", index)
  Router.HandleFunc("/generate", HandleGenerate)
}