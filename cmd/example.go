package main

import (
	"crypto/tls"
	"fmt"
	"github.com/yfernandezgou/auth-skeleton/pkg/controller"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	TIMER_CHECK_SESSION_INACTIVITY = 86400 // 1 day

	TEMPLATES_PATH = "../pkg/view/templates/*.gohtml"
	DATABASE_NAME  = "mongo-login"
)

var lc *controller.LoginController

func init() {
	lc = controller.NewLoginController(DATABASE_NAME, TEMPLATES_PATH)
}

//DefaultTLSConfig creates the tls configuration, written by gtank/cryptopasta
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		// Avoids most of the memorably-named TLS attacks
		MinVersion: tls.VersionTLS12,
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have constant-time implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
	}
}

func main() {
	go cleanSessionLogsTimer()

	fmt.Println("Check https://localhost:8080")

	http.HandleFunc("/", lc.HomepageHandler)
	http.HandleFunc("/signup", lc.SignupHandler)
	http.HandleFunc("/login", lc.LoginHandler)
	http.HandleFunc("/logout", lc.LogoutHandler)
	http.HandleFunc("/u/", lc.UserHandler)

	http.HandleFunc("/p/", ProjectHandler)
	http.HandleFunc("/help", HelpHandler)

	// Extractd from gtank/cryptopasta
	config := DefaultTLSConfig()
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: config,
	}

	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
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
		_, err := lc.CleanSessionLogs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error CleanSessionLogs: %v", err)
		}

		time.Sleep(TIMER_CHECK_SESSION_INACTIVITY * time.Second)
	}
}
