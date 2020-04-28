package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/dchest/captcha"
	"ldap-passwd-webui/app"
)

func init() {
	fileName := app.GetEnvStr("CA_FILE", "ca.crt")
	if fileName == "" {
		return
	}
	ldapCert, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(fmt.Sprintf("failed to read file: %s ", fileName))
	}
	rootCA := x509.NewCertPool()
	ok := rootCA.AppendCertsFromPEM(ldapCert)
	if !ok {
		log.Fatal(fmt.Sprintf("ca file not added: %s", fileName))
	}
	app.CertPool = rootCA
}

func main() {
	reHandler := new(app.RegexpHandler)
	reHandler.HandleFunc(".*.[js|css|png|eof|svg|ttf|woff]", "GET", app.ServeAssets)
	reHandler.HandleFunc("/", "GET", app.ServeIndex)
	reHandler.HandleFunc("/", "POST", app.ChangePassword)
	http.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))
	http.Handle("/", reHandler)
	fmt.Println("Starting server on port 8080")
	err := http.ListenAndServe(":8080", nil)
	log.Fatal(err)
}