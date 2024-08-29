package main

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

//const (
//	adminUsername = "admin"
//	adminPassword = "password"
//)

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

var jwtKey = []byte("your_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

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
		log.Fatalln("Enviroment variables are missing")
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

	//addingTable(db)

	r := mux.NewRouter()

	r.HandleFunc("/", getArticlesHandler).Methods("GET")
	r.HandleFunc("/admin", adminPanelHandler).Methods("GET")
	//r.HandleFunc("/admin", adminPanelAddArticleHandler).Methods("POST")
	r.HandleFunc("/register", registerPanelHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/add-article-form", addArticleFormHandler).Methods("GET")

	http.ListenAndServe(":8888", r)
}

// func registerPostHandler(w http.ResponseWriter, r *http.Request) {
// 	js, err := io.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	loginRequest := LoginRequest{}
// 	err = json.Unmarshal(js, &loginRequest)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	//hashedPassword, err := bcrypt.GenerateFromPassword([]byte(loginRequest.Password), bcrypt.DefaultCost)
// 	//if err != nil {
// 	//	http.Error(w, err.Error(), http.StatusInternalServerError)
// 	//}

// 	err = registerUser(pool, loginRequest.Username, loginRequest.Password)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusCreated)
// 	w.Write([]byte("succes register"))

// }

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
	var lr LoginRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal(body, &lr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("login success"))
}

func registerPanelHandler(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("templates/register.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	//w.Header().Set("Content-Type", "text/html")
	//fmt.Fprintf(w, string(html))
	//
	w.Write(html)

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

func addingTable(db *pgxpool.Pool) {
	var exists bool
	query := `
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = 'articles'
        )
    `

	err := db.QueryRow(context.Background(), query).Scan(&exists)
	if err != nil {
		log.Fatalf("QueryRow failed: %v\n", err)
	}

	if exists {
		fmt.Println("Table 'articles' exists.")
	} else {
		query = `CREATE TABLE articles (
		id SERIAL PRIMARY KEY,
		title VARCHAR(255) NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      );
`

		_, err := db.Exec(context.Background(), query)
		if err != nil {
			log.Fatalln(err)
		}
	}

}

func registerUser(pool *pgxpool.Pool, name, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = pool.Exec(context.Background(), "INSERT INTO users (username, password_hash) VALUES ($1, $2)", name, string(hashedPassword))
	if err != nil {
		return err
	}

	return nil
}

func authenticateUser(pool *pgxpool.Pool, username, password string) (bool, error) {
	var pashedPassword string
	err := pool.QueryRow(context.Background(), "SELECT password_hash FROM users WHERE username=$1", username).Scan(&pashedPassword)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(pashedPassword), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
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

	expirationTime := time.Now().Add(1 * time.Hour)
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

func adminPanelAddArticleHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthorized(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var article Article
	err := json.NewDecoder(r.Body).Decode(&article)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	_, err = pool.Exec(context.Background(), "INSERT INTO articles (title, content) VALUES ($1, $2)", article.Title, article.Content)
	if err != nil {
		log.Println("Error adding article to database:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Article added successfully"))
}

func addArticleFormHandler(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("templates/add_article.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}
