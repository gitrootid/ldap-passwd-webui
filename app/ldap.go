package app

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	ldap "github.com/go-ldap/ldap/v3"
	"ldap-passwd-webui/pkg/util"
	"log"
	"strings"
)

// SecurityProtocol protocol type
type SecurityProtocol int

// Note: new type must be added at the end of list to maintain compatibility.
const (
	SecurityProtocolUnencrypted SecurityProtocol = iota
	SecurityProtocolLDAPS
	SecurityProtocolStartTLS
)

// LDAPClient Basic LDAP authentication service
type LDAPClient struct {
	Name             string // canonical name (ie. corporate.ad)
	Host             string // LDAP host
	Port             int    // port number
	SecurityProtocol SecurityProtocol
	SkipVerify       bool
	UserBase         string // Base search path for users
	UserDN           string // Template for the DN of the user for simple auth
	Enabled          bool   // if this LDAPClient is disabled
}

// bind with admin privileges
//func (ls *LDAPClient) bindAdminDN(l *ldap.Conn, newUserDN, passwd string) error {
//	log.Printf("\nBinding with userDN: %s", newUserDN)
//	log.Printf("\nBinding with userDN passwd: %s", passwd)
//	err := l.Bind(newUserDN, passwd)
//	if err != nil {
//		log.Printf("\nLDAP auth. failed for %s, reason: %v", newUserDN, err)
//		return err
//	}
//	log.Printf("\nBound successfully with bindDN: %s", newUserDN)
//	return err
//}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	log.Printf("\nBinding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		log.Printf("\nLDAP auth. failed for %s, reason: %v", userDN, err)
		return err
	}
	log.Printf("\nBound successfully with userDN: %s", userDN)
	return err
}

func (ls *LDAPClient) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<>"
	if strings.ContainsAny(username, badCharacters) {
		log.Printf("\n'%s' contains invalid DN characters. Aborting.", username)
		return "", false
	}
	return fmt.Sprintf(ls.UserDN, username), true
}

//func loadROOTCA() (rootCA x509.CertPool,err error) {
//	rootCA, err = x509.SystemCertPool()
//	if err != nil{
//		return
//	}
//	if err != nil {
//		log.Printf("Failed to load system cert:%v", err)
//		// return nil, err
//	}
//	if rootCA == nil {
//		rootCA = x509.NewCertPool()
//		fileName := "/home/wu/go/src/ldap-passwd-webui/certs/ca.crt"
//		ldapCert, err := ioutil.ReadFile(fileName)
//		if err != nil {
//			log.Printf(fmt.Sprintf("failed to read file: %s ", fileName))
//		}
//		ok := rootCA.AppendCertsFromPEM(ldapCert)
//		if !ok {
//			log.Printf(fmt.Sprintf("ca file not added: %s", fileName))
//		}
//	}
//	return
//}

func dial(ls *LDAPClient) (*ldap.Conn, error) {
	log.Printf("\nDialing LDAP with security protocol (%v) without verifying: %v", ls.SecurityProtocol, ls.SkipVerify)

	tlsCfg := &tls.Config{
		ServerName:         ls.Host,
		InsecureSkipVerify: ls.SkipVerify,
	}
	if ls.SecurityProtocol == SecurityProtocolLDAPS {
		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port), tlsCfg)
	}
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port))
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}
	if ls.SecurityProtocol == SecurityProtocolStartTLS {
		if err = conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}
	return conn, nil
}

// ModifyPassword : modify user's password
func (ls *LDAPClient) ModifyPassword(name, oldPassword, newPassword string) error {
	if len(oldPassword) == 0 {
		return fmt.Errorf("auth. failed for %s, password cannot be empty", name)
	}
	l, err := dial(ls)
	if err != nil {
		ls.Enabled = false
		return fmt.Errorf("LDAP Connect error, %s:%v", ls.Host, err)
	}
	defer l.Close()

	var userDN string
	log.Printf("\nLDAP will bind directly via UserDN template: %s", ls.UserDN)

	var ok bool
	userDN, ok = ls.sanitizedUserDN(name)
	if !ok {
		return fmt.Errorf("error sanitizing name %s", name)
	}

	err = bindUser(l, userDN, oldPassword)
	if err != nil {
		return err
	}
	log.Printf("\nLDAP v3 will execute sambaNTPassword change on: %s", userDN)
	userPasswordHash, _ := HashPassword(newPassword, "MD5")
	sambaNTPasswordHash, _ := HashPassword(newPassword, "NT")
	sambaLMPasswordHash, _ := HashPassword(newPassword, "LM")
	req := ldap.NewModifyRequest(userDN, nil)
	req.Replace("userPassword", []string{userPasswordHash})
	req.Replace("sambaNTPassword", []string{sambaNTPasswordHash})
	req.Replace("sambaLMPassword", []string{sambaLMPasswordHash})
	err = l.Modify(req)
	return err
}

// NewLDAPClient : Creates new LDAPClient capable of binding and changing passwords
func NewLDAPClient() *LDAPClient {
	securityProtocol := SecurityProtocolUnencrypted
	if envBool("LPW_ENCRYPTED", true) {
		securityProtocol = SecurityProtocolLDAPS
		if envBool("LPW_START_TLS", false) {
			securityProtocol = SecurityProtocolStartTLS
		}
	}
	return &LDAPClient{
		Host:             envStr("LPW_HOST", ""),
		Port:             envInt("LPW_PORT", 636), // 389
		SecurityProtocol: securityProtocol,
		SkipVerify:       envBool("LPW_SSL_SKIP_VERIFY", false),
		UserDN:           envStr("LPW_USER_DN", "uid=%s,ou=people,dc=example,dc=org"),
		UserBase:         envStr("LPW_USER_BASE", "ou=people,dc=example,dc=org"),
	}
}

func HashPassword(value, hashType string) (hash string, err error) {
	hashType = strings.ToUpper(hashType)
	switch hashType {
	case "MD5":
		m := md5.New()
		_, err = m.Write([]byte(value))
		hash = fmt.Sprintf("{MD5}%s\n", base64.StdEncoding.EncodeToString(m.Sum(nil)))
		return
	case "NT":
		hash = strings.ToUpper(util.Md5UTF16toToLittleEndian(value))
		return
	case "LM":
		hash = strings.ToUpper(util.GenerateLMHashString(value))
		return
	}
	err = errors.New(fmt.Sprintf("No such hash type %s", hashType))
	return
}
