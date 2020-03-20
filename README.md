# Web UI for LDAP changing password  

WebUI Client capable of connecting to backend LDAP server and changing the users password.

![Screenshot](screenshots/index.png)

The configuration is made with environment variables:

|Env variable|Default value|Description|
|------------|-------------|-----------|
|LPW_TITLE|Change your global password for example.org|Title that will appear on the page|
|LPW_HOST||LDAP Host to connect to|
|LPW_PORT|636|LDAP Port (389|636 are default LDAP/LDAPS)|
|LPW_ENCRYPTED|true|Use enrypted communication|
|LPW_START_TLS|false|Start TLS communication|
|LPW_SSL_SKIP_VERIFY|true|Skip TLS CA verification|
|LPW_USER_DN|uid=%s,ou=people,dc=example,dc=org|Filter expression to search the user for Binding|
|LPW_USER_BASE|ou=people,dc=example,dc=org|Base to use when doing the binding|

## Running

```sh
dep ensure
LPW_HOST=ldap_host_ip go run main.go
```

Browse [http://localhost:8080/](http://localhost:8080/)

### Running in docker container

```sh
docker run -d -p 8080:8080 --name ldap-passwd-webui \
    -e LPW_TITLE="Change your global password for example.org" \
    -e LPW_HOST="your_ldap_host" \
    -e LPW_PORT="636" \
    -e LPW_ENCRYPTED="true" \
    -e LPW_START_TLS="false" \
    -e LPW_SSL_SKIP_VERIFY="true" \
    -e LPW_USER_DN="uid=%s,ou=people,dc=example,dc=org" \
    -e LPW_USER_BASE="ou=people,dc=example,dc=org" \
    -e LPW_PATTERN='.{8,}' \
    -e LPW_PATTERN_INFO="Password must be at least 8 characters long." \
    npenkov/docker-ldap-passwd-webui:latest
```

## Building and tagging

```sh
go mod download
```

```sh
make build 
```
## Add New Feature
modify below attribute for ldap user:
"sambaNTPassword" and "sambaLMPassword"

## load self sign CA cert
code:
```go
	rootCA, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Failed to load system cert:%v", err)
		// return nil, err
	}
	if rootCA == nil {
		rootCA = x509.NewCertPool()
		fileName := "./certs/ca.crt"
		ldapCert, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Fatal(fmt.Sprintf("failed to read file: %s ", fileName))
		}
		ok := rootCA.AppendCertsFromPEM(ldapCert)
		if !ok {
			log.Fatal(fmt.Sprintf("ca file not added: %s", fileName))
		}
	}
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "YourServerName",
		RootCAs:            rootCA,
	}
    l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", "YourServerName", 636), config)
```
##  ldap response: "Insufficient Access Rights" while try to modify sambaNTPassword
modify olc config, or try to change code: bind admin dn and obtain admin privileges
  
## Credits

 * [Web UI for changing LDAP password - python](https://github.com/jirutka/ldap-passwd-webui)
 * [Gitea](https://github.com/go-gitea/gitea)
 * [dchest/captcha](https://github.com/dchest/captcha)
 * [lmhash](https://github.com/newrelic/nri-mssql/blob/master/vendor/github.com/denisenkom/go-mssqldb/ntlm.go)
 * [nthash](https://cybersecurity.ink/posts/golang-ntlmhash)
