package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jackc/pgx/v4"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/joho/godotenv"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type Article struct {
	Title     string
	Content   string
	CreatedAt time.Time
}

type PageData struct {
	Articles []Article
	PrevPage int
	NextPage int
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var pool *pgxpool.Pool

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}

	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	if dbUser == "" || dbPass == "" || dbHost == "" || dbName == "" {
		log.Fatalln("Environment variables are missing")
	}

	connString := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", dbUser, dbPass, dbHost, dbPort, dbName)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatalln(err)
	}

	db, err := pgxpool.ConnectConfig(context.Background(), config)
	pool = db
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	r := mux.NewRouter()

	r.HandleFunc("/", getArticlesHandler).Methods("GET")
	r.HandleFunc("/admin", adminPanelHandler).Methods("GET")
	r.HandleFunc("/admin/add-article", adminPanelAddArticleHandler).Methods("POST")
	r.HandleFunc("/register", registerPanelHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST") // Новый маршрут для логина

	log.Println("Server started at :8888")
	http.ListenAndServe(":8888", r)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds LoginRequest
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	auth, err := authenticateUser(pool, creds.Username, creds.Password)
	if err != nil {
		http.Error(w, "Error authenticating user", http.StatusInternalServerError)
		return
	}

	if !auth {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received POST request at /register")

	js, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	loginRequest := LoginRequest{}
	err = json.Unmarshal(js, &loginRequest)
	if err != nil {
		log.Println("Error unmarshalling JSON:", err)
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	err = registerUser(pool, loginRequest.Username, loginRequest.Password)
	if err != nil {
		log.Println("Error registering user:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("success register"))
}

func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("templates/add_article.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Write(html)
}

func adminPanelAddArticleHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Println("Error parsing form:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	title := r.FormValue("title")
	content := r.FormValue("content")

	_, err = pool.Exec(context.Background(), "INSERT INTO articles (title, content) VALUES ($1, $2)", title, content)
	if err != nil {
		log.Println("Error adding article to database:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Article added successfully"))
}

func isAuthorized(r *http.Request) bool {
	c, err := r.Cookie("token")
	if err != nil {
		return false
	}

	tokenStr := c.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	return err == nil && token.Valid
}

func authenticateUser(pool *pgxpool.Pool, username, password string) (bool, error) {
	var hashedPassword string
	err := pool.QueryRow(context.Background(), "SELECT password_hash FROM users WHERE username=$1", username).Scan(&hashedPassword)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil // Пользователь не найден
		}
		return false, err // Другая ошибка
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil // Неверный пароль
	}

	return true, nil // Успешная аутентификация
}

func getArticlesHandler(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
	pageNumber, err := strconv.Atoi(page)
	if err != nil || pageNumber < 1 {
		pageNumber = 1
	}

	articlesSizePage := 3
	offset := (pageNumber - 1) * articlesSizePage

	rows, err := pool.Query(context.Background(), "SELECT title, content, created_at FROM articles order by id limit $1 offset $2", articlesSizePage, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		rows.Scan(&article.Title, &article.Content, &article.CreatedAt)
		articles = append(articles, article)
	}
	if rows.Err() != nil {
		http.Error(w, fmt.Sprintf("Error during row iteration: %v", rows.Err()), http.StatusInternalServerError)
		return
	}

	var nextPage int
	if articlesSizePage == len(articles) {
		var hasMoreArticles bool
		err = pool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM articles OFFSET $1 LIMIT 1)", offset+articlesSizePage).Scan(&hasMoreArticles)
		if err != nil {
			http.Error(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
			return
		}
		if hasMoreArticles {
			nextPage = pageNumber + 1
		}
	}

	var prevPage int
	if pageNumber > 1 {
		prevPage = pageNumber - 1
	}

	data := PageData{
		Articles: articles,
		PrevPage: prevPage,
		NextPage: nextPage,
	}

	tmpl, err := template.ParseFiles("templates/articles.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to parse template: %v", err), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("Unable to execute template: %v", err), http.StatusInternalServerError)
	}
}

func registerUser(pool *pgxpool.Pool, name, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = pool.Exec(context.Background(), "INSERT INTO users (username, password_hash) VALUES ($1, $2)", name, string(hashedPassword))
	return err
}
