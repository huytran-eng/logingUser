package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	sessions "github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var db *sql.DB
var store = sessions.NewCookieStore([]byte("super-secret"))

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}
func main() {
	var err error
	db, err = sql.Open("mysql", "root:password@tcp(localhost:3306)/web_project")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}
	http.HandleFunc("/", index)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
}
func index(w http.ResponseWriter, req *http.Request) {
	fmt.Println("hello")
	session, _ := store.Get(req, "session")
	a, ok := session.Values["email"]
	fmt.Println(a)
	fmt.Println("ok:", ok)
	if !ok {
		tpl.ExecuteTemplate(w, "index.html", nil)
		return
	}
	tpl.ExecuteTemplate(w, "content.html", nil)
}
func signup(w http.ResponseWriter, req *http.Request) {

	if req.Method == http.MethodPost {
		req.ParseForm()
		// kiem tra email co hop le khong
		email := req.FormValue("email")
		if !isEmailValid(email) {
			tpl.ExecuteTemplate(w, "register.html", "email khong hop le")
			return
		}
		// kiem tra mat khau co hop le khong
		pass := req.FormValue("password")
		if !validPassword(pass) || (len(pass) < 5 || len(pass) > 20) {
			tpl.ExecuteTemplate(w, "register.html", "mat khau khong hop le")
			return
		}
		role := req.FormValue("role")
		fmt.Println(role)
		// sID := uuid.NewV4()
		// c := &http.Cookie{
		// 	Name:  "session",
		// 	Value: sID.String(),
		// }
		// http.SetCookie(w, c)

		//kiem tra email co ton tai trong database khong
		stmt := "SELECT email FROM hash WHERE email = ?"
		row := db.QueryRow(stmt, email)
		var uID string
		err := row.Scan(&uID)
		if err != sql.ErrNoRows {
			fmt.Println("email da ton tai, err:", err)
			tpl.ExecuteTemplate(w, "register.html", "email da ton tai")
			return
		}
		var hash []byte
		// func GenerateFromPassword(password []byte, cost int) ([]byte, error)
		hash, _ = bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		fmt.Println("hash:", hash)
		fmt.Println("string(hash):", string(hash))
		var insertStmt *sql.Stmt
		insertStmt, err = db.Prepare("INSERT INTO hash (email, hash,role) VALUES (?, ?, ?);")
		if err != nil {
			fmt.Println("error preparing statement:", err)
			tpl.ExecuteTemplate(w, "register.html", "there was a problem registering account")
			return
		}
		defer insertStmt.Close()
		//  func (s *Stmt) Exec(args ...interface{}) (Result, error)
		_, err = insertStmt.Exec(email, hash, role)
		if err != nil {
			fmt.Println("error inserting new user")
			tpl.ExecuteTemplate(w, "register.html", "there was a problem registering account")
			return
		}
		fmt.Println("dang nhap thanh cong")
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return

	}
	tpl.ExecuteTemplate(w, "register.html", nil)
}
func login(w http.ResponseWriter, req *http.Request) {

	if req.Method == http.MethodPost {
		req.ParseForm()
		email := req.FormValue("email")
		pass := req.FormValue("password")
		stmt := "SELECT hash FROM hash WHERE email= ? ; "
		var hash string
		row := db.QueryRow(stmt, email)
		err := row.Scan(&hash)
		if err != nil {
			fmt.Println("error selecting password in db")
			tpl.ExecuteTemplate(w, "login.html", "kiem tra lai")
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
		if err != nil {
			// Get always returns a session, even if empty
			// returns error if exists and could not be decoded
			// Get(r *http.Request, name string) (*Session, error)
			session, _ := store.Get(req, "session")
			// session struct has field Values map[interface{}]interface{}
			session.Values["email"] = email
			// save before writing to response/return from handler
			session.Save(req, w)
			http.Redirect(w, req, "/", http.StatusSeeOther)
			fmt.Println("dang nhap thanh cong")
			return
		}
		fmt.Println("incorrect password")
		tpl.ExecuteTemplate(w, "login.html", "check username and password")
	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}
func logout(w http.ResponseWriter, req *http.Request) {
	session, _ := store.Get(req, "session")
	delete(session.Values, "email")
	session.Save(req, w)
	tpl.ExecuteTemplate(w, "login.html", "log out")
}
