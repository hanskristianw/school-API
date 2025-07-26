package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var db *pgx.Conn

func main() {
	// ✅ Inisialisasi router chi
	r := chi.NewRouter()

	// ✅ Tambahkan middleware CORS langsung ke router
	r.Use(func(next http.Handler) http.Handler {
		return withCORS(next)
	})

	// ✅ Koneksi ke database Neon
	dsn := "postgresql://neondb_owner:npg_TRZkvJyO64hd@ep-divine-term-a1jftj2r-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
	var err error
	db, err = pgx.Connect(context.Background(), dsn)
	if err != nil {
		log.Fatalf("❌ Gagal konek ke Neon: %v", err)
	}
	defer db.Close(context.Background())
	log.Println("✅ Berhasil konek ke Neon DB")

	// ✅ Daftarkan endpoint API
	r.Post("/login", loginHandler)
	r.Get("/menu/{role}", menuHandler)

	// ✅ Jalankan server
	log.Println("🚀 Server jalan di http://localhost:8080")
	err = http.ListenAndServe(":8080", r)
	if err != nil {
		log.Fatalf("❌ Gagal menjalankan server: %v", err)
	}
}

// ✅ CORS middleware
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:3000" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		// ✅ Jawab OPTIONS biar gak error CORS
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Bad Request")
		return
	}

	var userID int
	var hashedPassword string
	var roleName string

	query := `
		SELECT users.user_id, users.user_password, role.role_name
		FROM users
		JOIN role ON users.user_role_id = role.role_id
		WHERE users.user_username = $1
	`

	err = db.QueryRow(context.Background(), query, req.Username).Scan(&userID, &hashedPassword, &roleName)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Username tidak ditemukan")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Password salah")
		return
	}

	// ✅ Jika sukses
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		UserID: userID,
		Role:   roleName,
	})
}

func menuHandler(w http.ResponseWriter, r *http.Request) {
	role := chi.URLParam(r, "role") // ex: "admin"

	query := `
	SELECT m.menu_name, m.menu_path, m.menu_icon
	FROM menus m
	JOIN menu_roles mr ON m.menu_id = mr.menu_id
	JOIN role r ON r.role_id = mr.role_id
	WHERE r.role_name = $1
	ORDER BY m.menu_id;
	`

	rows, err := db.Query(context.Background(), query, role)
	if err != nil {
		log.Println("❌ Query error:", err)
		respondWithError(w, http.StatusInternalServerError, "Query error")
		return
	}
	defer rows.Close()

	var menus []map[string]string
	for rows.Next() {
		var name, path, icon string
		if err := rows.Scan(&name, &path, &icon); err == nil {
			menus = append(menus, map[string]string{
				"name": name,
				"path": path,
				"icon": icon,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(menus)
}
