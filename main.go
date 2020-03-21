package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
	"io"
	"os"
	"time"
	
	"encoding/base64"
	"log"
	"net/http"
)

const secretKey = "this_is_my_secret_key"

var SessionStore = sessions.NewCookieStore([]byte(secretKey))
var database *sql.DB

type User struct {
	Id int `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Session struct {
	Id string
	Authenticated bool
	User User
}

var UserSession Session

func Respond(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
}

func GetSessionUID(sid string) int {
	user := User{}
	err := database.QueryRow(fmt.Sprintf("SELECT user_id from sessions where session_id='%s'", sid)).Scan(&user.Id)
	if err!=nil {
		log.Println("get session id error: ", err)
		return 0
	}
	return user.Id
}

func UpdateSession(sid string, uid int) { // enabling a timestamp update or inclusion of a user id if a new log in is attempted
	tstamp := time.Now().Format(time.UnixDate)
	_, err := database.Exec(fmt.Sprintf(
		"insert into sessions" +
		" (session_id, user_id, session_update)" +
		" values ('%s', '%v', '%s') ON CONFLICT (session_id) DO UPDATE SET" +
		" user_id='%v', session_update='%s'", sid, uid, tstamp, uid, tstamp))
	if err!=nil {
		log.Printf("update session error: %s",err)
		os.Exit(3)
	}
}

func GenerateSessionId() string {
	sid := make([]byte, 24)
	_, err := io.ReadFull(rand.Reader, sid)
	if err != nil {
		log.Fatal("Could not generate session id")
	}
	return base64.URLEncoding.EncodeToString(sid)
}

//this function will be called with every request
//to check for a cookie's session or create on if it doesn't exist
func ValidateSession(w http.ResponseWriter, r *http.Request) {
	session, _ := SessionStore.Get(r, "app-session")
	if sid, valid := session.Values["sid"]; valid {
		currentUserID := GetSessionUID(sid.(string))
		UpdateSession(sid.(string), currentUserID)
		UserSession.Id = sid.(string)
	} else {
		newSID := GenerateSessionId()
		session.Values["sid"] = newSID
		err := session.Save(r, w)
		if err!= nil {
			Respond(w, http.StatusInternalServerError, "save the session in the response fail")
			return
		}
		UserSession.Id = newSID
		UpdateSession(newSID, 0)
	}
	fmt.Println(session.ID)
}

func Login(w http.ResponseWriter, r *http.Request) {
	ValidateSession(w, r)
	
	infoRequest := &struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	user := User{}
	err := json.NewDecoder(r.Body).Decode(infoRequest)
	if err!=nil {
		Respond(w, http.StatusBadRequest, "Invalid request")
		return
	}
	err = database.QueryRow(fmt.Sprintf(
		"select *" +
		" from users where username='%s'", infoRequest.Username)).Scan(&user.Id, &user.Username, &user.Password)
	if err!=nil {
		log.Printf("query error: %s", err.Error())
		Respond(w, http.StatusInternalServerError, "")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(infoRequest.Password))
	if err!=nil && err==bcrypt.ErrMismatchedHashAndPassword{ //Password does not match!
		Respond(w, http.StatusBadRequest, "email or password wrong")
		return
	}
	UpdateSession(UserSession.Id, user.Id)
	user.Password = ""
	Respond(w, http.StatusOK, user)
}

func Register(w http.ResponseWriter, r *http.Request) {
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil {
		Respond(w, 400, "Invalid request, please try again")
		return
	}
	
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashPassword)
	_, err = database.Exec(fmt.Sprintf("INSERT INTO users values ('%s', '%s')", user.Username, user.Password))
	user.Password = "" // you don't want to response your password to client
	if err!=nil {
		log.Printf("create account error: %s", err)
		Respond(w, http.StatusInternalServerError, "Connection error. please try again")
		os.Exit(2)
	}
	Respond(w, http.StatusOK, user)
}

func init() {
	
	// fill your config
	username := ""
	password := ""
	dbName := ""
	dbHost := "localhost"
	
	dbUri := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s", dbHost, username, dbName, password)
	
	var err error
	database, err = sql.Open("postgres", dbUri)
	if err!=nil {
		log.Printf("err: %s", err)
		os.Exit(1)
	}
	_, err = database.Exec(fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS Users (id SERIAL " +
		"primary key,username varchar(50) not null,password varchar not null)"))
			
	if err!=nil {
		log.Printf("create table user error: %s",err)
		os.Exit(2)
	}
	
	_, err = database.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS Sessions (" +
		"id SERIAL primary key," +
		"session_id varchar(256) not null default '' unique," +
		"user_id integer default null," +
		"session_start timestamp not null default CURRENT_TIMESTAMP," +
		"session_update timestamp not null)"))
	if err!=nil {
		log.Printf("create table Session error: %s", err)
		os.Exit(2)
	}
}

func main() {
	
	router := mux.NewRouter()
	
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/register", Register).Methods("POST")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		Respond(w, 200, "Hello")
	}).Methods("GET")
	port := 8080
	err := http.ListenAndServe(fmt.Sprintf(":%v", port), router)
	if err!=nil {
		log.Println(err)
	}
}