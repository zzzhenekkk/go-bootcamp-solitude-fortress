package ex

import (
	"fmt"
	"github.com/gorilla/sessions"
	"net/http"
)

var store = sessions.NewCookieStore([]byte("secret-key"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Проверка логина и пароля (замените на реальную проверку из базы данных)
		if username == "user" && password == "password" {
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Values["username"] = username
			session.Save(r, w)
			fmt.Fprintf(w, "Logged in successfully!")
		} else {
			fmt.Fprintf(w, "Invalid login credentials")
		}
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
            <form method="POST" action="/login">
                Username: <input type="text" name="username" />
                Password: <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
        `)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	fmt.Fprintf(w, "Logged out successfully!")
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	username := session.Values["username"].(string)
	fmt.Fprintf(w, "Hello, %s! Welcome to your dashboard.", username)
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}
