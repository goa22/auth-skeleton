package controller

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"latexhub/model"
	"latexhub/view"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

const (
	// Cookies
	COOKIE_ACCES_PATH = "session"
	COOKIE_AGE        = 86400 // 1 day

	// Check email/pass regex
	REGEX_USERNAME = "^[a-zA-Z0-9_-]{4,20}$"
	REGEX_EMAIL    = "^[a-zA-Z0-9_-]{1,20}@[a-zA-Z0-9_-]{2,20}\\.[a-zA-Z-]{2,5}$"
	REGEX_PASSWORD = "^[a-zA-Z0-9_-]{6,30}$"

	// Time clean database session for users that do not logout
	TIMER_CHECK_SESSION_INACTIVITY = 86400  // 1 day
	MAX_TIME_SESSION_INACTIVITY    = 864000 // 10 day

	// Context time
	CONTEXT_TIME_DB = 3
)

type LoginController struct {
	collectionUser    *mongo.Collection
	collectionSession *mongo.Collection

	regexUsername *regexp.Regexp
	regexEmail    *regexp.Regexp
	regexPassword *regexp.Regexp

	tpl *template.Template
}

func NewLoginController(dbName string, tplPath string) *LoginController {
	lc := LoginController{}

	// Load templates
	lc.tpl = template.Must(template.ParseGlob(tplPath))

	// Connect to mongo database
	clientOpts := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOpts)
	if err != nil {
		log.Fatal(err)
	}

	// Check connection to mongo
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	// Get the pointers to the collections
	lc.collectionUser = client.Database(dbName).Collection("login")
	lc.collectionSession = client.Database(dbName).Collection("session")

	// Compile regex
	lc.regexUsername = regexp.MustCompile(REGEX_USERNAME)
	lc.regexEmail = regexp.MustCompile(REGEX_EMAIL)
	lc.regexPassword = regexp.MustCompile(REGEX_PASSWORD)

	return &lc
}

func (lc LoginController) HomepageHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		err := lc.tpl.ExecuteTemplate(w, "homepage.gohtml", "Homepage")
		if err != nil {
			// Redirect UserHandler to error page
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		err := lc.tpl.ExecuteTemplate(w, "error404.gohtml", "ERROR 404")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (lc LoginController) SignupHandler(w http.ResponseWriter, req *http.Request) {
	signupTplView := view.SignupView{PageName: "Signup", ArrayErr: nil}

	if _, ok := lc.checkCookie(w, req); ok {
		http.Redirect(w, req, "/u/", http.StatusSeeOther)
		return
	} else {
		if req.Method == http.MethodPost {
			username := req.FormValue("user")
			email := req.FormValue("email")
			password := req.FormValue("password")

			if ok, arrayErr := lc.checkSignupCredentials(username, email, password); ok {
				err := lc.addNewUser(username, email, password)
				if err != nil {
					//
				} else {
					http.Redirect(w, req, "/login", http.StatusSeeOther)
					return
				}
			} else {
				signupTplView.ArrayErr = arrayErr
				// http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			}

		}

		err := lc.tpl.ExecuteTemplate(w, "signup.gohtml", signupTplView)
		if err != nil {
			// Redirect UserHandler to error page
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "main.go: LoginHandler: %s", err)
		}
	}
}

func (lc LoginController) LoginHandler(w http.ResponseWriter, req *http.Request) {
	loginTplView := view.LoginView{PageName: "LoginHandler", Err: nil}

	if _, ok := lc.checkCookie(w, req); ok {
		http.Redirect(w, req, "/u/", http.StatusSeeOther)
		return
	} else {
		if req.Method == http.MethodPost {
			u := req.FormValue("user")
			pass := req.FormValue("password")

			if ok, err := lc.checkCredentials(u, pass); ok {
				// Set cookie with session uuid
				lc.createNewSession(w, req, u)

				// Redirect to /u/ webpage
				http.Redirect(w, req, "/u/", http.StatusSeeOther)
				return
			} else {
				loginTplView.Err = err
				// http.Error(w, "Username and/or password do not match", http.StatusForbidden)
			}

		}

		err := lc.tpl.ExecuteTemplate(w, "login.gohtml", loginTplView)
		if err != nil {
			// Redirect UserHandler to error page
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "main.go: LoginHandler: %s", err)
		}
	}
}

func (lc LoginController) LogoutHandler(w http.ResponseWriter, req *http.Request) {
	// Delete cookie by putting max age to negative
	if _, ok := lc.checkCookie(w, req); ok {
		c, err := req.Cookie(COOKIE_ACCES_PATH)
		if err != nil {

		} else {
			err = lc.deleteCookieSession(w, req, c)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	http.Redirect(w, req, "/login", http.StatusSeeOther)
	return

}

func (lc LoginController) UserHandler(w http.ResponseWriter, req *http.Request) {
	if user, ok := lc.checkCookie(w, req); ok {
		err := lc.tpl.ExecuteTemplate(w, "user.gohtml", user)
		if err != nil {
			// Redirect UserHandler to error page
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "main.go: UserHandler: %s", err)
		}
	} else {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

}

func (lc LoginController) ProjectHandler(w http.ResponseWriter, req *http.Request) {
	if user, ok := lc.checkCookie(w, req); ok {
		err := lc.tpl.ExecuteTemplate(w, "project.gohtml", user)
		if err != nil {
			// Redirect UserHandler to error page
			http.Error(w, err.Error(), http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "main.go: ProjectHandler: %s", err)
		}
	} else {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}
}

//
// AUXILIAR FUNCTIONS
//

// createNewSession will create and set the new cookie, for the
// session
func (lc LoginController) createNewSession(w http.ResponseWriter, req *http.Request, user string) {
	token := (uuid.Must(uuid.NewRandom())).String()
	http.SetCookie(w, &http.Cookie{
		Name:  COOKIE_ACCES_PATH,
		Value: token,

		Path:     "/",
		MaxAge:   COOKIE_AGE,
		HttpOnly: true,
		// Secure: true,
	})

	newSession := model.UserSession{
		Uuid:      token,
		Username:  user,
		LoginTime: time.Now(),
		LastSeen:  time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	_, err := lc.collectionSession.InsertOne(ctx, newSession)
	if err != nil {
		log.Fatal(err)
	}
}

// checkCredentials ensure that the data passed by the UserHandler
// in LoginHandler is fine
func (lc LoginController) checkCredentials(username string, password string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	result := model.User{}
	err := lc.collectionUser.FindOne(ctx, bson.M{"username": username, "password": bson.M{"$exists": true}}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			err = errors.New("Username or password not valid")
		} else {
			err = errors.New("Unexpected error, try again")
		}
	} else {
		if bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(password)) == nil {
			return true, nil
		} else {
			err = errors.New("Username or password not valid")
		}
	}

	return false, err
}

// checkCookie ensure that the cookie session is correct
func (lc LoginController) checkCookie(w http.ResponseWriter, req *http.Request) (string, bool) {
	c, err := req.Cookie(COOKIE_ACCES_PATH)
	if err != nil {
		return "", false
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
		defer cancel()

		session := model.UserSession{}
		err = lc.collectionSession.FindOne(ctx, bson.M{"uuid": c.Value, "username": bson.M{"$exists": true}}).Decode(&session)
		if err == nil {
			return session.Username, true
		}
	}

	return "", false
}

func (lc LoginController) deleteCookieSession(w http.ResponseWriter, req *http.Request, c *http.Cookie) error {
	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	res, err := lc.collectionSession.DeleteOne(ctx, bson.M{"uuid": c.Value})

	if res.DeletedCount == 1 {
		c.MaxAge = -1
		http.SetCookie(w, c)
	} else {
		fmt.Printf("Error no elimina correctamente, %v", res.DeletedCount)
	}

	return err
}

func (lc LoginController) addNewUser(username, email, password string) error {
	passwordHashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LoginController: addNewUser: error creating password for %v\n", username)
	}

	newUser := model.User{
		Username:     username,
		Password:     string(passwordHashed),
		Email:        email,
		IsActive:     true,
		EmailChecked: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	_, err = lc.collectionUser.InsertOne(ctx, newUser)

	return err
}

// checkSignupCredentials make sure data is correct
func (lc LoginController) checkSignupCredentials(username string, email string, password string) (bool, []error) {
	// Check user is not present in DB
	var userCheck, emailCheck, passCheck bool
	var errorsRet []error

	if ok, err := lc.checkUsername(username); ok {
		userCheck = true
	} else {
		errorsRet = append(errorsRet, err)
	}

	if ok, err := lc.checkEmail(email); ok {
		emailCheck = true
	} else {
		errorsRet = append(errorsRet, err)
	}

	if ok, err := lc.checkPassword(password); ok {
		passCheck = true
	} else {
		errorsRet = append(errorsRet, err)
	}

	return (userCheck && emailCheck && passCheck), errorsRet
}

func (lc LoginController) checkUsername(username string) (bool, error) {
	var userCheck bool
	var errReturn, err error

	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	// Check format of the user
	if lc.regexUsername.MatchString(username) {
		// Check if the user is already in the database
		err = lc.collectionUser.FindOne(ctx, bson.M{"username": username}).Err()
		if err != nil {
			if err == mongo.ErrNoDocuments {
				userCheck = true
			} else {
				errReturn = errors.New("Server error")
			}
		} else {
			errReturn = errors.New("Username already in use")
		}
	} else {
		errReturn = errors.New("Incorrect username format, only can contain _,- special characters, len need to be between 4 and 20")
	}

	return userCheck, errReturn
}

func (lc LoginController) checkEmail(email string) (bool, error) {
	var emailCheck bool
	var errReturn, err error

	ctx, cancel := context.WithTimeout(context.Background(), CONTEXT_TIME_DB*time.Second)
	defer cancel()

	// Check format
	if lc.regexEmail.MatchString(email) {
		// Check if is already in use
		err = lc.collectionUser.FindOne(ctx, bson.M{"email": email, "emailChecked": true}).Err()
		if err != nil {
			if err == mongo.ErrNoDocuments {
				emailCheck = true
			} else {
				errReturn = errors.New("Unexpected error, try again!")
			}
		} else {
			errReturn = errors.New("Email already in use")
		}
	} else {
		errReturn = errors.New("Incorrect email format, only can contain _,- special characters")
	}

	return emailCheck, errReturn
}

func (lc LoginController) checkPassword(password string) (bool, error) {
	var passCheck bool
	var errReturn error

	if lc.regexPassword.MatchString(password) {
		passCheck = true
	} else {
		errReturn = errors.New("Incorrect password format, only can contain _,- special characters, len need to be between 6 and 30")
	}

	return passCheck, errReturn
}
