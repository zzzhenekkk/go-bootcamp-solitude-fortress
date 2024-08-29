package ex

import (
	"context"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/time/rate"
	"html/template"
	"net/http"
)

var db *pgxpool.Pool
var limiter = rate.NewLimiter(100, 100)

const (
	adminUsername = "admin"
	adminPassword = "password"
)

func main() {
	connStr := "postgres://mybloguser:1234@localhost/myblogdb"
	var err error
	db, err = pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.Handle("/", rateLimitedHandler(http.HandlerFunc(indexHandler)))
	http.Handle("/admin", rateLimitedHandler(http.HandlerFunc(adminHandler)))
	http.Handle("/admin/panel", rateLimitedHandler(http.HandlerFunc(adminPanelHandler)))

	http.ListenAndServe(":8888", nil)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == adminUsername && password == adminPassword {
			http.Redirect(w, r, "/admin/panel", http.StatusFound)
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin_login.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		title := r.FormValue("title")
		content := r.FormValue("content")
		_, err := db.Exec(context.Background(), "INSERT INTO articles (title, content) VALUES ($1, $2)", title, content)
		if err != nil {
			http.Error(w, "Failed to save article", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin_panel.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(context.Background(), "SELECT title, content FROM articles ORDER BY id DESC LIMIT 3")
	if err != nil {
		http.Error(w, "Failed to load articles", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		err := rows.Scan(&article.Title, &article.Content)
		if err != nil {
			http.Error(w, "Failed to parse article", http.StatusInternalServerError)
			return
		}
		articles = append(articles, article)
	}

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, articles)
}

type Article struct {
	Title   string
	Content string
}

func rateLimitedHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}
