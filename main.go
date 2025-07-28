package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *pgxpool.Pool

type Menu struct {
	MenuID       int     `json:"menu_id"`
	MenuName     string  `json:"menu_name"`
	MenuPath     *string `json:"menu_path"`
	MenuIcon     *string `json:"menu_icon"`
	MenuOrder    int     `json:"menu_order"`
	MenuParentID *int    `json:"menu_parent_id"`
}

type User struct {
	UserID           int    `json:"user_id"`
	UserNamaDepan    string `json:"user_nama_depan"`
	UserNamaBelakang string `json:"user_nama_belakang"`
	UserUsername     string `json:"user_username"`
	UserPassword     string `json:"user_password"`
	UserRoleID       int    `json:"user_role_id"`
	RoleName         string `json:"role_name"`
	IsAdmin          bool   `json:"is_admin"`
	IsActive         bool   `json:"is_active"`
}

type MenuResponse struct {
	Status string `json:"status"`
	Menus  []Menu `json:"menus"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Role    string `json:"role,omitempty"`
	UserID  int    `json:"user_id,omitempty"`
}

type Role struct {
	RoleID   int    `json:"role_id"`
	RoleName string `json:"role_name"`
	IsAdmin  bool   `json:"is_admin"`
}

type Unit struct {
	UnitID   int    `json:"unit_id"`
	UnitName string `json:"unit_name"`
}

type CreateUserRequest struct {
	UserNamaDepan    string `json:"user_nama_depan"`
	UserNamaBelakang string `json:"user_nama_belakang"`
	UserUsername     string `json:"user_username"`
	UserPassword     string `json:"user_password"`
	UserRoleID       int    `json:"user_role_id"`
}

type UpdateUserRequest struct {
	UserNamaDepan    string `json:"user_nama_depan"`
	UserNamaBelakang string `json:"user_nama_belakang"`
	UserUsername     string `json:"user_username"`
	UserPassword     string `json:"user_password,omitempty"` // Optional for updates
	UserRoleID       int    `json:"user_role_id"`
	IsActive         bool   `json:"is_active"`
}

func initDB() error {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, using system environment variables")
	}

	// Get database URL from environment variable
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return err
	}
	config.MaxConns = 10
	config.MinConns = 1
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute
	config.ConnConfig.RuntimeParams = map[string]string{"application_name": "school-admin"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}
	err = pool.Ping(ctx)
	if err != nil {
		return err
	}
	db = pool
	log.Println("✅ Database connected to Neon successfully!")
	return nil
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authenticateUser(username, password string) (*User, error) {
	log.Printf("🔍 Authenticating user: %s against Neon database", username)

	query := `
		SELECT u.user_id, u.user_nama_depan, u.user_nama_belakang, u.user_username, u.user_password, u.user_role_id, r.role_name, r.is_admin, u.is_active
		FROM users u
		JOIN role r ON u.user_role_id = r.role_id
		WHERE u.user_username = $1 AND u.is_active = true
	`

	var user User
	err := db.QueryRow(context.Background(), query, username).Scan(
		&user.UserID,
		&user.UserNamaDepan,
		&user.UserNamaBelakang,
		&user.UserUsername,
		&user.UserPassword,
		&user.UserRoleID,
		&user.RoleName,
		&user.IsAdmin,
		&user.IsActive,
	)

	if err != nil {
		log.Printf("❌ User %s not found in Neon database: %v", username, err)
		return nil, fmt.Errorf("user not found in database")
	}

	// Use bcrypt to compare password hash
	err = bcrypt.CompareHashAndPassword([]byte(user.UserPassword), []byte(password))
	if err != nil {
		log.Printf("❌ Invalid password for user %s: %v", username, err)
		return nil, fmt.Errorf("invalid password")
	}

	log.Printf("✅ User authenticated from Neon: %s (role: %s, admin: %v)", user.UserUsername, user.RoleName, user.IsAdmin)
	return &user, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("🔐 Login attempt for username: %s", req.Username)

	user, err := authenticateUser(req.Username, req.Password)
	if err != nil {
		log.Printf("❌ Authentication failed for %s: %v", req.Username, err)
		response := LoginResponse{
			Status:  "error",
			Message: "Invalid username or password",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf("✅ Login successful: %s (role: %s)", req.Username, user.RoleName)

	response := LoginResponse{
		Status:  "success",
		Message: "Login successful",
		Role:    user.RoleName,
		UserID:  user.UserID,
	}
	json.NewEncoder(w).Encode(response)
}

func checkIfAdmin(roleName string) (bool, error) {
	query := `SELECT is_admin FROM role WHERE role_name = $1`
	var isAdmin bool
	err := db.QueryRow(context.Background(), query, roleName).Scan(&isAdmin)
	if err != nil {
		return false, fmt.Errorf("role not found: %v", err)
	}
	return isAdmin, nil
}

func getAllRoles() ([]Role, error) {
	log.Println("🔍 Getting all roles from Neon database...")
	query := `SELECT role_id, role_name, is_admin FROM role ORDER BY role_id ASC`

	rows, err := db.Query(context.Background(), query)
	if err != nil {
		log.Printf("❌ Database query error: %v", err)
		return nil, fmt.Errorf("query error: %v", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		err := rows.Scan(&role.RoleID, &role.RoleName, &role.IsAdmin)
		if err != nil {
			log.Printf("❌ Row scan error: %v", err)
			return nil, fmt.Errorf("scan error: %v", err)
		}
		roles = append(roles, role)
	}

	log.Printf("✅ Successfully loaded %d roles from Neon database", len(roles))
	return roles, nil
}

func getAllUsers() ([]User, error) {
	log.Println("🔍 Getting all users from Neon database...")
	query := `
		SELECT u.user_id, u.user_nama_depan, u.user_nama_belakang, u.user_username, 
		       u.user_password, u.user_role_id, r.role_name, r.is_admin, u.is_active
		FROM users u
		JOIN role r ON u.user_role_id = r.role_id
		ORDER BY u.user_id ASC
	`

	rows, err := db.Query(context.Background(), query)
	if err != nil {
		log.Printf("❌ Database query error: %v", err)
		return nil, fmt.Errorf("query error: %v", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.UserID,
			&user.UserNamaDepan,
			&user.UserNamaBelakang,
			&user.UserUsername,
			&user.UserPassword,
			&user.UserRoleID,
			&user.RoleName,
			&user.IsAdmin,
			&user.IsActive,
		)
		if err != nil {
			log.Printf("❌ Row scan error: %v", err)
			return nil, fmt.Errorf("scan error: %v", err)
		}
		// Don't return password hash in response
		user.UserPassword = ""
		users = append(users, user)
	}

	log.Printf("✅ Successfully loaded %d users from Neon database", len(users))
	return users, nil
}

func createUser(req CreateUserRequest) (*User, error) {
	log.Printf("🔍 Creating new user: %s", req.UserUsername)

	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.UserPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %v", err)
	}

	query := `
		INSERT INTO users (user_nama_depan, user_nama_belakang, user_username, user_password, user_role_id, is_active)
		VALUES ($1, $2, $3, $4, $5, true)
		RETURNING user_id
	`

	var userID int
	err = db.QueryRow(context.Background(), query,
		req.UserNamaDepan, req.UserNamaBelakang, req.UserUsername,
		string(hashedPassword), req.UserRoleID).Scan(&userID)

	if err != nil {
		log.Printf("❌ Error creating user: %v", err)
		return nil, fmt.Errorf("error creating user: %v", err)
	}

	// Get the created user with role information
	getUserQuery := `
		SELECT u.user_id, u.user_nama_depan, u.user_nama_belakang, u.user_username, 
		       u.user_role_id, r.role_name, r.is_admin, u.is_active
		FROM users u
		JOIN role r ON u.user_role_id = r.role_id
		WHERE u.user_id = $1
	`

	var user User
	err = db.QueryRow(context.Background(), getUserQuery, userID).Scan(
		&user.UserID,
		&user.UserNamaDepan,
		&user.UserNamaBelakang,
		&user.UserUsername,
		&user.UserRoleID,
		&user.RoleName,
		&user.IsAdmin,
		&user.IsActive,
	)

	if err != nil {
		return nil, fmt.Errorf("error retrieving created user: %v", err)
	}

	log.Printf("✅ User created successfully: %s (ID: %d)", user.UserUsername, user.UserID)
	return &user, nil
}

func updateUser(userID int, req UpdateUserRequest) (*User, error) {
	log.Printf("🔍 Updating user ID: %d", userID)

	// Check current user status - is the current user an admin?
	var currentIsAdmin bool
	var currentIsActive bool
	checkCurrentQuery := `
		SELECT r.is_admin, u.is_active
		FROM users u 
		JOIN role r ON u.user_role_id = r.role_id 
		WHERE u.user_id = $1
	`
	err := db.QueryRow(context.Background(), checkCurrentQuery, userID).Scan(&currentIsAdmin, &currentIsActive)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if the new role will be admin
	var newRoleIsAdmin bool
	checkNewRoleQuery := `SELECT is_admin FROM role WHERE role_id = $1`
	err = db.QueryRow(context.Background(), checkNewRoleQuery, req.UserRoleID).Scan(&newRoleIsAdmin)
	if err != nil {
		return nil, fmt.Errorf("invalid role ID")
	}

	log.Printf("📋 User %d - Current Admin: %t, New Admin: %t, Current Active: %t, New Active: %t",
		userID, currentIsAdmin, newRoleIsAdmin, currentIsActive, req.IsActive)

	// If this user is currently an admin AND active, and we're changing them to non-admin OR deactivating them
	if currentIsAdmin && currentIsActive && (!newRoleIsAdmin || !req.IsActive) {
		// Check if there will be at least one active admin left after this change
		var activeAdminCount int
		countAdminQuery := `
			SELECT COUNT(*) 
			FROM users u 
			JOIN role r ON u.user_role_id = r.role_id 
			WHERE r.is_admin = true AND u.is_active = true AND u.user_id != $1
		`
		err = db.QueryRow(context.Background(), countAdminQuery, userID).Scan(&activeAdminCount)
		if err != nil {
			return nil, fmt.Errorf("error checking admin count: %v", err)
		}

		log.Printf("📊 Active admin count (excluding user %d): %d", userID, activeAdminCount)

		if activeAdminCount == 0 {
			log.Printf("🚫 Cannot modify last admin user %d", userID)
			return nil, fmt.Errorf("tidak dapat mengubah role atau menonaktifkan admin terakhir yang aktif")
		}
	}

	var query string
	var args []interface{}

	if req.UserPassword != "" {
		// Update with new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.UserPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("error hashing password: %v", err)
		}

		query = `
			UPDATE users 
			SET user_nama_depan = $1, user_nama_belakang = $2, user_username = $3, 
			    user_password = $4, user_role_id = $5, is_active = $6, updated_at = CURRENT_TIMESTAMP
			WHERE user_id = $7
		`
		args = []interface{}{req.UserNamaDepan, req.UserNamaBelakang, req.UserUsername,
			string(hashedPassword), req.UserRoleID, req.IsActive, userID}
	} else {
		// Update without changing password
		query = `
			UPDATE users 
			SET user_nama_depan = $1, user_nama_belakang = $2, user_username = $3, 
			    user_role_id = $4, is_active = $5, updated_at = CURRENT_TIMESTAMP
			WHERE user_id = $6
		`
		args = []interface{}{req.UserNamaDepan, req.UserNamaBelakang, req.UserUsername,
			req.UserRoleID, req.IsActive, userID}
	}

	_, err = db.Exec(context.Background(), query, args...)
	if err != nil {
		log.Printf("❌ Error updating user: %v", err)
		return nil, fmt.Errorf("error updating user: %v", err)
	}

	// Get the updated user with role information
	getUserQuery := `
		SELECT u.user_id, u.user_nama_depan, u.user_nama_belakang, u.user_username, 
		       u.user_role_id, r.role_name, r.is_admin, u.is_active
		FROM users u
		JOIN role r ON u.user_role_id = r.role_id
		WHERE u.user_id = $1
	`

	var user User
	err = db.QueryRow(context.Background(), getUserQuery, userID).Scan(
		&user.UserID,
		&user.UserNamaDepan,
		&user.UserNamaBelakang,
		&user.UserUsername,
		&user.UserRoleID,
		&user.RoleName,
		&user.IsAdmin,
		&user.IsActive,
	)

	if err != nil {
		return nil, fmt.Errorf("error retrieving updated user: %v", err)
	}

	log.Printf("✅ User updated successfully: %s (ID: %d)", user.UserUsername, user.UserID)
	return &user, nil
}

func getAllMenus() ([]Menu, error) {
	log.Println("🔍 Getting all menus from Neon database...")
	query := `SELECT menu_id, menu_name, menu_path, menu_icon, menu_order, menu_parent_id FROM menus ORDER BY menu_order ASC`

	rows, err := db.Query(context.Background(), query)
	if err != nil {
		log.Printf("❌ Database query error: %v", err)
		return nil, fmt.Errorf("query error: %v", err)
	}
	defer rows.Close()

	var menus []Menu
	for rows.Next() {
		var menu Menu
		err := rows.Scan(&menu.MenuID, &menu.MenuName, &menu.MenuPath, &menu.MenuIcon, &menu.MenuOrder, &menu.MenuParentID)
		if err != nil {
			log.Printf("❌ Row scan error: %v", err)
			return nil, fmt.Errorf("scan error: %v", err)
		}
		menus = append(menus, menu)
		log.Printf("📄 Loaded menu: %s (ID: %d)", menu.MenuName, menu.MenuID)
	}

	log.Printf("✅ Successfully loaded %d menus from Neon database", len(menus))
	return menus, nil
}

func getMenusByRole(roleName string) ([]Menu, error) {
	log.Printf("🔍 Getting menus for role: %s from Neon database", roleName)
	query := `
		SELECT DISTINCT m.menu_id, m.menu_name, m.menu_path, m.menu_icon, m.menu_order, m.menu_parent_id
		FROM menus m
		INNER JOIN menu_permissions mp ON m.menu_id = mp.menu_id
		INNER JOIN role r ON mp.role_id = r.role_id
		WHERE r.role_name = $1
		ORDER BY m.menu_order ASC`

	rows, err := db.Query(context.Background(), query, roleName)
	if err != nil {
		log.Printf("❌ Query error for role %s: %v", roleName, err)
		return nil, fmt.Errorf("query error: %v", err)
	}
	defer rows.Close()

	var menus []Menu
	for rows.Next() {
		var menu Menu
		err := rows.Scan(&menu.MenuID, &menu.MenuName, &menu.MenuPath, &menu.MenuIcon, &menu.MenuOrder, &menu.MenuParentID)
		if err != nil {
			log.Printf("❌ Scan error: %v", err)
			return nil, fmt.Errorf("scan error: %v", err)
		}
		menus = append(menus, menu)
		log.Printf("📄 Role %s can access: %s", roleName, menu.MenuName)
	}

	log.Printf("✅ Role %s has access to %d menus", roleName, len(menus))
	return menus, nil
}

func menuHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	role := chi.URLParam(r, "role")
	log.Printf("🔍 Getting menus for role: %s", role)

	isAdmin, err := checkIfAdmin(role)
	if err != nil {
		log.Printf("❌ Error checking admin status: %v", err)
		http.Error(w, fmt.Sprintf("Error checking role: %v", err), http.StatusInternalServerError)
		return
	}

	var menus []Menu
	if isAdmin {
		log.Println("👑 Admin role - showing all menus")
		menus, err = getAllMenus()
	} else {
		log.Printf("👤 Non-admin role (%s) - showing permitted menus", role)
		menus, err = getMenusByRole(role)
	}

	if err != nil {
		log.Printf("❌ Error getting menus: %v", err)
		http.Error(w, fmt.Sprintf("Error getting menus: %v", err), http.StatusInternalServerError)
		return
	}

	response := MenuResponse{Status: "success", Menus: menus}
	log.Printf("✅ Returning %d menus for role %s", len(menus), role)
	json.NewEncoder(w).Encode(response)
}

func debugMenuRaw(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	menus, err := getAllMenus()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}
	response := map[string]interface{}{"count": len(menus), "menus": menus}
	json.NewEncoder(w).Encode(response)
}

// User CRUD Handlers
func usersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		users, err := getAllUsers()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting users: %v", err), http.StatusInternalServerError)
			return
		}
		response := map[string]interface{}{
			"status": "success",
			"users":  users,
		}
		json.NewEncoder(w).Encode(response)

	case "POST":
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Validation
		if req.UserNamaDepan == "" || req.UserNamaBelakang == "" || req.UserUsername == "" || req.UserPassword == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		if len(req.UserPassword) < 6 {
			http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
			return
		}

		user, err := createUser(req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			response := map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		response := map[string]interface{}{
			"status": "success",
			"user":   user,
		}
		json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func userByIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userIDStr := chi.URLParam(r, "id")

	userID := 0
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "PUT":
		var req UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Validation
		if req.UserNamaDepan == "" || req.UserNamaBelakang == "" || req.UserUsername == "" {
			http.Error(w, "Name and username fields are required", http.StatusBadRequest)
			return
		}

		if req.UserPassword != "" && len(req.UserPassword) < 6 {
			http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
			return
		}

		user, err := updateUser(userID, req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			response := map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		response := map[string]interface{}{
			"status": "success",
			"user":   user,
		}
		json.NewEncoder(w).Encode(response)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func rolesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roles, err := getAllRoles()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting roles: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status": "success",
		"roles":  roles,
	}
	json.NewEncoder(w).Encode(response)
}

// Units handlers
func unitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		handleGetUnits(w, r)
	case "POST":
		handleCreateUnit(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func unitByIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "PUT":
		handleUpdateUnit(w, r)
	case "DELETE":
		handleDeleteUnit(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleGetUnits(w http.ResponseWriter, _ *http.Request) {
	units, err := getAllUnits()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting units: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status": "success",
		"units":  units,
	}
	json.NewEncoder(w).Encode(response)
}

func handleCreateUnit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UnitName string `json:"unit_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.UnitName == "" {
		http.Error(w, "unit_name is required", http.StatusBadRequest)
		return
	}

	// Insert unit into database
	insertQuery := `INSERT INTO unit (unit_name) VALUES ($1) RETURNING unit_id`
	var unitID int
	err := db.QueryRow(context.Background(), insertQuery, req.UnitName).Scan(&unitID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating unit: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Unit created successfully",
		"unit_id": unitID,
	}
	json.NewEncoder(w).Encode(response)
}

func handleUpdateUnit(w http.ResponseWriter, r *http.Request) {
	unitID := chi.URLParam(r, "id")

	var req struct {
		UnitName string `json:"unit_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.UnitName == "" {
		http.Error(w, "unit_name is required", http.StatusBadRequest)
		return
	}

	// Update unit in database
	updateQuery := `UPDATE unit SET unit_name = $1 WHERE unit_id = $2`
	result, err := db.Exec(context.Background(), updateQuery, req.UnitName, unitID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating unit: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Unit not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Unit updated successfully",
	}
	json.NewEncoder(w).Encode(response)
}

func handleDeleteUnit(w http.ResponseWriter, r *http.Request) {
	unitID := chi.URLParam(r, "id")

	// Delete unit from database
	deleteQuery := `DELETE FROM unit WHERE unit_id = $1`
	result, err := db.Exec(context.Background(), deleteQuery, unitID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error deleting unit: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Unit not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Unit deleted successfully",
	}
	json.NewEncoder(w).Encode(response)
}

func getAllUnits() ([]Unit, error) {
	query := `SELECT unit_id, unit_name FROM unit ORDER BY unit_id`

	rows, err := db.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var units []Unit
	for rows.Next() {
		var unit Unit
		err := rows.Scan(&unit.UnitID, &unit.UnitName)
		if err != nil {
			return nil, err
		}
		units = append(units, unit)
	}

	return units, nil
}

func initUserManagementMenu(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if User Management menu already exists
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM menus WHERE menu_name = 'User Management' AND menu_path = '/data/user')`
	err := db.QueryRow(context.Background(), checkQuery).Scan(&exists)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error checking menu existence: %v", err), http.StatusInternalServerError)
		return
	}

	if exists {
		response := map[string]interface{}{
			"status":  "success",
			"message": "User Management menu already exists",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Insert the User Management menu under Data Management (parent_id = 57)
	insertMenuQuery := `
		INSERT INTO menus (menu_name, menu_path, menu_icon, menu_order, menu_parent_id) 
		VALUES ('User Management', '/data/user', 'users', 3, 57)
		RETURNING menu_id
	`

	var menuID int
	err = db.QueryRow(context.Background(), insertMenuQuery).Scan(&menuID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting menu: %v", err), http.StatusInternalServerError)
		return
	}

	// Grant permission to admin role (role_id = 1) for this new menu
	insertPermissionQuery := `INSERT INTO menu_permissions (menu_id, role_id) VALUES ($1, 1)`
	_, err = db.Exec(context.Background(), insertPermissionQuery, menuID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error inserting menu permission: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "User Management menu created successfully",
		"menu_id": menuID,
	}
	json.NewEncoder(w).Encode(response)
}

func initUnitTable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create unit table if it doesn't exist
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS unit (
			unit_id SERIAL PRIMARY KEY,
			unit_name VARCHAR(255) UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`

	_, err := db.Exec(context.Background(), createTableQuery)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating unit table: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  "success",
		"message": "Unit table created successfully",
	}
	json.NewEncoder(w).Encode(response)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.Ping(ctx)
	dbStatus := "connected to Neon"
	if err != nil {
		dbStatus = fmt.Sprintf("error: %v", err)
	}

	var menuCount, userCount int
	db.QueryRow(ctx, "SELECT COUNT(*) FROM menus").Scan(&menuCount)
	db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount)

	response := map[string]interface{}{
		"status":     "ok",
		"message":    "Server running with Neon database",
		"time":       time.Now().Format(time.RFC3339),
		"database":   dbStatus,
		"menu_count": menuCount,
		"user_count": userCount,
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	log.Println("🚀 Starting School Admin API Server with Neon Database...")
	if err := initDB(); err != nil {
		log.Fatal("❌ Failed to initialize Neon database:", err)
	}
	defer db.Close()

	r := chi.NewRouter()
	r.Use(enableCORS)
	r.Get("/test", testHandler)
	r.Post("/login", loginHandler)
	r.Get("/menu/{role}", menuHandler)
	r.Get("/debug/menu-raw", debugMenuRaw)

	// User CRUD endpoints
	r.Route("/users", func(r chi.Router) {
		r.Get("/", usersHandler)
		r.Post("/", usersHandler)
		r.Put("/{id}", userByIDHandler)
		r.Delete("/{id}", userByIDHandler)
	})

	// Roles endpoint
	r.Get("/roles", rolesHandler)

	// Units CRUD endpoints
	r.Route("/units", func(r chi.Router) {
		r.Get("/", unitsHandler)
		r.Post("/", unitsHandler)
		r.Put("/{id}", unitByIDHandler)
		r.Delete("/{id}", unitByIDHandler)
	})

	// Admin endpoints
	r.Post("/admin/init-user-menu", initUserManagementMenu)
	r.Post("/admin/init-unit-table", initUnitTable)

	// Get port from environment variable, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🌐 Server starting on http://localhost:%s", port)
	log.Printf("📍 Endpoints:")
	log.Printf("   GET /test - Server status & Neon database info")
	log.Printf("   POST /login - User login (authenticate against Neon)")
	log.Printf("   GET /menu/{role} - Get menus by role from Neon")
	log.Printf("   GET /debug/menu-raw - Show all menus in Neon database")
	log.Printf("   GET /users - Get all users")
	log.Printf("   POST /users - Create new user")
	log.Printf("   PUT /users/{id} - Update user by ID")
	log.Printf("   DELETE /users/{id} - Delete user by ID")
	log.Printf("   GET /roles - Get all roles")
	log.Printf("   GET /units - Get all units")
	log.Printf("   POST /units - Create new unit")
	log.Printf("   PUT /units/{id} - Update unit by ID")
	log.Printf("   DELETE /units/{id} - Delete unit by ID")
	log.Printf("   POST /admin/init-user-menu - Initialize user management menu")
	log.Printf("   POST /admin/init-unit-table - Initialize unit table")

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("❌ Server failed to start:", err)
	}
}
