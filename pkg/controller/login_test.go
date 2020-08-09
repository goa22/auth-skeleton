package controller

import (
	"context"
	"fmt"
	"github.com/auth-skeleton/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	DATABASE_TEST  = "login-testing"
	TEMPLATES_PATH = "../view/templates/*.gohtml"
)

func TestMain(m *testing.M) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	setup(lc)

	m.Run()

	teardown(lc)
}

func setup(lc *LoginController) {
	// load data

	passwordHashed := "$2a$04$Y90O6l.9iWmtSDhJf.p6lemllskmM.1tW7JvXxXANhCETdrYJUO8W"
	users := []model.User{
		// Unit testing for checkUser, checkEmail, checkPassword
		{"default", "password", "default@default.com", true, true},
		{"user", "password", "user@default.com", true, false},

		// Unit testing checkCredentials
		{"data12345", passwordHashed, "data12345@default.com", true, true},
	}

	for _, user := range users {
		_, err := lc.collectionUser.InsertOne(context.TODO(), user)
		if err != nil {
			log.Fatal(err)
		}
	}

	sessions := []model.UserSession{
		// Unit testing CheckCookie
		{"e820a5a3-5c95-4516-961d-2603103643e1", "username12345", time.Now(), time.Now()},
		// Unit testing CleanSessionLogs
		{"d9cf88f0-b7fc-423e-8906-2993264db803", "2993264db803", time.Now(), time.Now().Add(-(MAX_TIME_SESSION_INACTIVITY - 300) * time.Second)},
		{"bd8936e1-e863-42dd-90a8-7d845852f26c", "7d845852f26c", time.Now(), time.Now().Add(-(MAX_TIME_SESSION_INACTIVITY + 300) * time.Second)},
		{"edb5be8b-1d05-445a-aece-623eb9fbc18b", "623eb9fbc18b", time.Now(), time.Now().Add(-(MAX_TIME_SESSION_INACTIVITY + 200) * time.Second)},
	}

	for _, session := range sessions {
		_, err := lc.collectionSession.InsertOne(context.TODO(), session)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("> Setup completed")

}

func teardown(lc *LoginController) {
	// drop data
	err := lc.collectionUser.Drop(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	err = lc.collectionSession.Drop(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("> Teardown completed")
}

func TestCreateNewSession(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		path     string
		username string
	}{
		{"with username 'user'", "/", "user"},
		{"with username 'user' (for second time)", "/", "user"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.path, nil)
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}

			// Create new session
			rec := httptest.NewRecorder()
			lc.createNewSession(rec, req, tc.username)

			res := rec.Result()
			defer res.Body.Close()

			// Search cookie created
			var index int
			for i, cookie := range res.Cookies() {
				if cookie.Name == COOKIE_ACCES_PATH {
					break
				}
				index = i + 1
			}

			if index == len(res.Cookies()) {
				t.Fatalf("cookie not found, error creating")
			} else {
				// Check in the database if the session is added
				session := model.UserSession{}

				query := bson.M{"uuid": res.Cookies()[index].Value, "username": tc.username}
				err = lc.collectionSession.FindOne(context.TODO(), query).Decode(&session)
				if err != nil {
					// Errors in db
					if err == mongo.ErrNoDocuments {
						t.Fatalf("session created not present in db")
					} else {
						t.Fatalf("error searching in the db")
					}
				}
			}
		})
	}
}

func TestCheckCredentials(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		username string
		password string
		pass     bool
	}{
		{"correct user and password", "data12345", "password12345", true},
		{"correct user; incorrect password", "data12345", "pass_word", false},
		{"correct password; incorrect user", "data", "password12345", false},
		{"incorrect user and password", "data", "pass_word", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := lc.checkCredentials(tc.username, tc.password)
			if ok != tc.pass {
				fmt.Println(err)
				t.Errorf("could not check credentials correctly, expected %v; got %v", tc.pass, ok)
			}
		})

	}
}

func TestCleanSessionLogs(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name            string
		sessionsDeleted int64
	}{
		{"Delete all the sessions older than 10 days", 2},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			nDeleted, err := lc.CleanSessionLogs()
			if err != nil {
				t.Errorf("database error cleaning logs")
			}

			if nDeleted != tc.sessionsDeleted {
				t.Errorf("error removing old logs, expected %v deletions; got %v", tc.sessionsDeleted, nDeleted)
			}
		})
	}

}

func TestCheckCookie(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name             string
		uuid             string
		usernameExpected string
		pass             bool
	}{
		{"uuid present", "e820a5a3-5c95-4516-961d-2603103643e1", "username12345", true},
		{"uuuid with invalid value", "invalid", "", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Create petition
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Errorf("could not create request: %v", err)
			}

			// Create and add cookie
			cookie := http.Cookie{
				Name:   COOKIE_ACCES_PATH,
				Value:  tc.uuid,
				MaxAge: COOKIE_AGE,
			}
			req.AddCookie(&cookie)

			// Create response writer recorder
			rec := httptest.NewRecorder()

			// Check cookie
			username, ok := lc.CheckCookie(rec, req)
			if ok != tc.pass {
				t.Errorf("error checking cookie, expected %v; got %v", tc.pass, ok)
			}

			if username != tc.usernameExpected {
				t.Errorf("error returning username, expected %v; got %v", tc.usernameExpected, username)
			}
		})
	}
}

func TestDeleteCookieSession(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	t.Run("cookie check delete", func(t *testing.T) {
		// Insert session in DB
		session := model.UserSession{
			Uuid:      "value",
			Username:  "default",
			LoginTime: time.Now(),
			LastSeen:  time.Now(),
		}

		_, err := lc.collectionSession.InsertOne(context.Background(), session)
		if err != nil {
			t.Errorf("could not create session in db")
		}

		// Create cookie
		cookie := http.Cookie{
			Name:   COOKIE_ACCES_PATH,
			Value:  "value",
			MaxAge: COOKIE_AGE,
		}

		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Errorf("could not create request: %v", err)
		}

		rec := httptest.NewRecorder()

		// Delete cookie
		err = lc.deleteCookieSession(rec, req, &cookie)
		if err != nil {
			t.Errorf("could not delete correctly %v", err)
		}

		res := rec.Result()
		defer res.Body.Close()

		// Check if cookie is alive
		var index int
		for i, c := range res.Cookies() {
			if c.Name == COOKIE_ACCES_PATH {
				break
			}
			index = i + 1
		}

		// Check cookie MaxAge
		if index != len(res.Cookies()) {
			if res.Cookies()[index].MaxAge != -1 {
				t.Errorf("cookie not deleted correctly")
			}
		} else {
			t.Errorf("could not find cookie")
		}

		// Check if has deleted session from db
		err = lc.collectionSession.FindOne(context.TODO(), bson.M{"uuid": "value", "username": "default"}).Decode(&session)
		if err != mongo.ErrNoDocuments {
			t.Errorf("could not delete session from db")
		}
	})

}

func TestAddNewUser(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		username string
		email    string
		password string
	}{
		{"standard user", "USERNAME", "PASS12345", "user1234@default.com"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := lc.addNewUser(tc.username, tc.email, tc.password)
			if err != nil {
				t.Errorf("could not add new user %v", tc.username)
			}

			// check if password is ciphered
			user := model.User{}
			query := bson.M{"username": tc.username, "email": tc.email}

			err = lc.collectionUser.FindOne(context.TODO(), query).Decode(&user)
			if user.Password == tc.password {
				t.Errorf("password saved as plain text")
			}
		})

	}
}

func TestCheckSignupCredentials(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		username string
		email    string
		password string
		pass     bool
	}{
		{"valid username, password and email", "Username123", "user123@gmail.com", "Password123", true},
		{"valid username, password; invalid email", "Username123", "use r123@gmail.com", "Password123", false},
		{"valid email, password; invalid username", "User name123", "user123@gmail.com", "Password123", false},
		{"valid username; invalid email, password", "Username123", "use r123@gmail.com", "Pass word123", false},
		{"valid email; invalid username, password", "User name123", "user123@gmail.com", "Pass word123", false},
		{"valid password; invalid username, email", "User name123", "use r123@gmail.com", "Password123", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := lc.checkSignupCredentials(tc.username, tc.email, tc.password)
			if ok != tc.pass {
				t.Errorf("invalid result, expected %v; got %v", tc.pass, ok)
			}
		})
	}
}

// Check if username is already
// check user format
func TestCheckUsername(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		username string
		pass     bool
	}{
		{"valid standard username", "user_-10", true},
		{"upper score at the end", "user-", true},
		{"low score at the end", "user_", true},
		{"valid lowest len", "defa", true},
		{"valid max len", "userrrrrrrrrrrrrrrrr", true},
		{"invalid lowest len", "use", false},
		{"invalid max len", "userrrrrrrrrrrrrrrrrb", false},
		{"invalid characters", "use^$$r", false},
		{"invalid characters #2", "use&/·", false},
		{"invalid with spaces", "user rrr", false},
		{"invalid characters #3", "use!?¿", false},
		{"username already in db", "default", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := lc.checkUsername(tc.username)
			if ok != tc.pass {
				t.Errorf("username %v expected %v; got %v", tc.username, tc.pass, ok)
			}
		})
	}
}

func TestCheckEmail(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name  string
		email string
		pass  bool
	}{
		{"valid standard email", "user90-_@default.com", true},
		{"email already in db, but without confirmation", "user@default.com", true},
		{"valid lowest len", "u@de.com", true},
		{"valid max len", "userrrrrrrrrrrrrrrrr@userrrrrrrrrrrrrrrrr.commm", true},
		{"invalid lowest len", "@d.f", false},
		{"invalid max len", "userrrrrrrrrrrrrrrrrd@userrrrrrrrrrrrrrrrr.commm", false},
		{"without name before @", "@default.com", false},
		{"without domain before @", "user@.com", false},
		{"without termination", "user@default.", false},
		{"without dot", "user@defaultcom", false},
		{"invalid with spaces", "user @default.com", false},
		{"without @", "usergmail.com", false},
		{"email already in db confirmed", "default@default.com", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := lc.checkEmail(tc.email)
			if ok != tc.pass {
				t.Errorf("email %v expected %v; got %v", tc.email, tc.pass, ok)
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	lc := NewLoginController(DATABASE_TEST, TEMPLATES_PATH)

	tt := []struct {
		name     string
		password string
		pass     bool
	}{
		{"valid standard password", "paSS90_-word", true},
		{"valid lowest len", "passwo", true},
		{"valid max len", "passworddddddddddddddddddddddd", true},
		{"invalid lowest len", "passw", false},
		{"invalid max len", "passworddddddddddddddddddddddde", false},
		{"invalid characters", "pass^$$d", false},
		{"invalid with spaces", "p assword", false},
		{"invalid characters #2", "pass&/·", false},
		{"invalid characters #3", "pass!?¿", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ok, _ := lc.checkPassword(tc.password)
			if ok != tc.pass {
				t.Errorf("password %v expected %v; got %v", tc.password, tc.pass, ok)
			}
		})
	}
}
