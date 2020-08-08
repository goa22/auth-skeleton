package main

import (
	"fmt"
	"github.com/auth-skeleton/controller"
	"net/http"
	"time"
)

const (
	TIMER_CHECK_SESSION_INACTIVITY = 86400  // 1 day
	MAX_TIME_SESSION_INACTIVITY    = 864000 // 10 day

	TEMPLATES_PATH = "./view/templates/*.gohtml"
	DATABASE_NAME  = "mongo-login"
)

func main() {
	go cleanSessionLogsTimer()
	lc := controller.NewLoginController(DATABASE_NAME, TEMPLATES_PATH)

	fmt.Println("Check localhost:8080")

	http.HandleFunc("/", lc.HomepageHandler)
	http.HandleFunc("/signup", lc.SignupHandler)
	http.HandleFunc("/login", lc.LoginHandler)
	http.HandleFunc("/logout", lc.LogoutHandler)

	http.HandleFunc("/u/", lc.UserHandler)
	http.HandleFunc("/p/", lc.ProjectHandler)

	// try page?

	http.ListenAndServe(":8080", nil)
}

func cleanSessionLogsTimer() {
	for {
		time.Sleep(TIMER_CHECK_SESSION_INACTIVITY * time.Second)
		// cleanSessionLogs()
	}
}
