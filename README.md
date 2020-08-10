# AUTH SKELETON 
Auth Skeleton it's a basic authentication system based on sessions stored in cookies. It uses the [`google/uuid`](https://github.com/google/uuid) and the standard library [`net/http`](https://godoc.org/net/http). It's builded above the MVC architecture with Mongo as database and implements TLS as transport layer and [`crypto/bcrypt`](https://godoc.org/golang.org/x/crypto/bcrypt) for safe password storage. 

## Routes
By default there are this links: 

| Name        | Link   | Purpose                                                     |
|-------------|--------|-------------------------------------------------------------|
| Homepage    | /      | Home of the website, this handler also checks for 404 errors|
| Signup      | /signup| Check and register users                                    |
| Login       | /login | Check credentials of users and set session if are correct   |
| Logout      | /logout| Delete session from the database and cookie                 |
| User Webpage| /u/    | Initial website of user, user page after login              |


## How it works 
The database design is avaible in `pkg/model/login.go`: 
```MongoDB
User {
    Username     string 
    Email        string 
    Password     string 
    IsActive     bool 
    EmailChecked bool 
}

UserSession {
    Uuid        string 
    Username    string  
    LoginTime   time.Time 
    LastSeen    time.Time 
}
```

The keys `IsActive` and `EmailChecked` from User db will be required in futures implementations. The first are for user deletions, and the second for email validation after signup (can't login if it isn't confirmed). All the password are stored with [`crypto/bcrypt`](https://godoc.org/golang.org/x/crypto/bcrypt) for prevent password leakage. 

In the `UserSession` we can see the unique value `uuid` and the `username`. This data will be checked by the function `CheckCookie` placed in `pkg/controller/login.go`. The last two values are for time purposes, a timer will clean the database from expired sessions, you can see an example in `cmd/example.go`.  

Comming up next we can see a diagram related to the steps that an user can follow: 
![alt text](img/workflow-sessions.png "Logo Title Text 1")

## Testing 
You can run the testing functions with 
```
$ go test pkg/controller/login_test.go 
```
## Usage example 
In `cmd/example.go` you can find the code above: 
```golang 
// Handler with authentication
func ProjectHandler(w http.ResponseWriter, req *http.Request) {
	if username, ok := lc.CheckCookie(w, req); ok {
		//
		// PUT SOME CODE OR QUERY
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
```

Can interact with the authentication status with the function `CheckCookie`, the first statement will check if the cookie is present and verify the uuid credentials. If the uuid is correct, it will return the username and a bool value. If something goes will redirect to login page. 

In the second statement we can see a raw handler without any type of authentication, and only shows a welcome message. 

## Customization 
This implementation is just a proof of concept, but feel free to change any data inside `pkg/view/templates` for html pages customization. 
