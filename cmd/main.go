package main

import (
	"fmt"
	"github.com/auth-skeleton/pkg/controller"
	"net/http"
	"time"
)

const (
	TIMER_CHECK_SESSION_INACTIVITY = 86400  // 1 day
	MAX_TIME_SESSION_INACTIVITY    = 864000 // 10 day

	TEMPLATES_PATH = "../pkg/view/templates/*.gohtml"
	DATABASE_NAME  = "mongo-login"
)

var lc *controller.LoginController

func init() {
	lc = controller.NewLoginController(DATABASE_NAME, TEMPLATES_PATH)
}

func main() {
	go cleanSessionLogsTimer()

	fmt.Println("Check localhost:8080")

	http.HandleFunc("/", lc.HomepageHandler)
	http.HandleFunc("/signup", lc.SignupHandler)
	http.HandleFunc("/login", lc.LoginHandler)
	http.HandleFunc("/logout", lc.LogoutHandler)
	http.HandleFunc("/u/", lc.UserHandler)

	http.HandleFunc("/p/", ProjectHandler)
	http.HandleFunc("/help", HelpHandler)

	http.ListenAndServe(":8080", nil)
}

// Handler with authentication
func ProjectHandler(w http.ResponseWriter, req *http.Request) {
	if username, ok := lc.CheckCookie(w, req); ok {
		//
		//
		// PUT SOME CODE
		//
		//
		fmt.Fprintf(w, "Welcome %v", username)
	} else {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
}

// Handler without authentication
func HelpHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Welcome unknown user")
}

func cleanSessionLogsTimer() {
	for {
		time.Sleep(TIMER_CHECK_SESSION_INACTIVITY * time.Second)
		// cleanSessionLogs()
	}
}
