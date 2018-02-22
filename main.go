package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"github.com/felipeweb/osin-mysql"
	_ "github.com/go-sql-driver/mysql"
)

var dbConnect *sql.DB

func init() {
	urldb := "root:root@tcp(127.0.0.1:3306)/oauth?parseTime=true"
	db, err := sql.Open("mysql", urldb)

	if err != nil {
		panic(err)
	}
	dbConnect = db
}

func main() {

	store := mysql.New(dbConnect, "osin_")
	err := store.CreateSchemas()
	if err != nil {
		panic(err)
	}

	cfg := osin.NewServerConfig()
	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true

	server := osin.NewServer(cfg, store)

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			// if !example.HandleLoginPage(ar, w, r) {
			// 	return
			// }
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}

		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("Error:%s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}

		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("Error: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}
		osin.OutputJSON(resp, w, r)
	})

	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Login</a><br/>", url.QueryEscape("http://localhost:14000/appauth/code"))))
		w.Write([]byte("</body></html>"))
	})

	http.HandleFunc("/appauth/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.Form.Get("code")
		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - CODE<br/>"))
		defer w.Write([]byte("</body></html>"))

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}
		jr := make(map[string]interface{})

		aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
			url.QueryEscape("http://localhost:14000/appauth/code"), url.QueryEscape(code))

		if r.Form.Get("doparse") == "1" {
			err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:14000%s", aurl), &osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
			if err != nil {
				w.Write([]byte(err.Error()))
				w.Write([]byte("<br/>"))
			}
		}

		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		// output links
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

		cururl := *r.URL
		curq := cururl.Query()
		curq.Add("doparse", "1")
		cururl.RawQuery = curq.Encode()
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
	})

	// 注册一个客户端
	http.HandleFunc("/client/create", func(w http.ResponseWriter, r *http.Request) {
		var client = new(osin.DefaultClient)
		r.ParseForm()
		client.Id = "100001"
		ha, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return
		}
		client.Secret = string(ha)
		client.RedirectUri = "https://blog.tsecloud.club/"
		store := mysql.New(dbConnect, "osin_")
		err = store.CreateClient(client)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("Success")
		}
	})

	//更新一个客户端
	http.HandleFunc("/client/update", func(w http.ResponseWriter, r *http.Request) {

	})

	//删除一个客户端
	http.HandleFunc("/client/delete", func(w http.ResponseWriter, r *http.Request) {

	})

	http.ListenAndServe(":14000", nil)
}
