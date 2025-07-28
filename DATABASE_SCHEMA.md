# Database Schema Documentation - School Admin System

## Overview
Dokumentasi ini menjelaskan struktur database PostgreSQL (Neon) untuk sistem administrasi sekolah. Database ini menggunakan autentikasi bcrypt dan sistem role-based access control (RBAC).

## Database Connection
- **Provider**: Neon PostgreSQL
- **Connection String**: `postgresql://neondb_owner:npg_TRZkvJyO64hd@ep-divine-term-a1jftj2r-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require`
- **Application Name**: `school-admin`

---

## Table Structures

### 1. Table: `role`
**Purpose**: Menyimpan informasi role/peran pengguna dalam sistem

| Column Name | Data Type | Constraints | Description |
|-------------|-----------|-------------|-------------|
| `role_id` | SERIAL | PRIMARY KEY | ID unik untuk setiap role |
| `role_name` | VARCHAR(50) | NOT NULL, UNIQUE | Nama role (admin, teacher, student, staff) |
| `is_admin` | BOOLEAN | DEFAULT FALSE | Menandakan apakah role memiliki akses admin |

**Sample Data:**
```sql
INSERT INTO role (role_id, role_name, is_admin) VALUES 
(1, 'admin', true),
(2, 'teacher', false),
(3, 'student', false),
(4, 'staff', false);
```

---

### 2. Table: `users`
**Purpose**: Menyimpan informasi pengguna sistem dengan autentikasi bcrypt

| Column Name | Data Type | Constraints | Description |
|-------------|-----------|-------------|-------------|
| `user_id` | SERIAL | PRIMARY KEY | ID unik untuk setiap user |
| `user_nama_depan` | VARCHAR(100) | NOT NULL | Nama depan pengguna |
| `user_nama_belakang` | VARCHAR(100) | NOT NULL | Nama belakang pengguna |
| `user_username` | VARCHAR(50) | UNIQUE, NOT NULL | Username untuk login |
| `user_password` | VARCHAR(255) | NOT NULL | Password hash menggunakan bcrypt |
| `user_role_id` | INTEGER | NOT NULL, FK to role(role_id) | Foreign key ke tabel role |
| `is_active` | BOOLEAN | DEFAULT TRUE | Status aktif pengguna |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Waktu pembuatan record |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Waktu update terakhir |

**Foreign Key Constraints:**
- `user_role_id` REFERENCES `role(role_id)`

**Indexes:**
- `idx_users_username` ON `user_username` (UNIQUE BTREE)
- `idx_users_role` ON `user_role_id` (BTREE)

**Sample Admin User:**
```sql
-- Password: "123456" (bcrypt hashed)
INSERT INTO users (
    user_id, user_nama_depan, user_nama_belakang, 
    user_username, user_password, user_role_id, is_active
) VALUES (
    1, 'Administrator', 'System', 'admin',
    '$2a$10$qqE7esxoiQIKH8uU6xa6ieF5XCTC2q4Gtj3oNHpqZugVgRtbxXUke',
    1, true
);
```

---

### 3. Table: `menus`
**Purpose**: Menyimpan struktur menu sistem dengan hierarki parent-child

| Column Name | Data Type | Constraints | Description |
|-------------|-----------|-------------|-------------|
| `menu_id` | SERIAL | PRIMARY KEY | ID unik untuk setiap menu |
| `menu_name` | VARCHAR(100) | NOT NULL | Nama menu yang ditampilkan |
| `menu_path` | VARCHAR(200) | NULL | Path/URL menu (null untuk parent menu) |
| `menu_icon` | VARCHAR(50) | NULL | Nama icon FontAwesome |
| `menu_order` | INTEGER | DEFAULT 0 | Urutan tampilan menu |
| `menu_parent_id` | INTEGER | NULL, FK to menus(menu_id) | ID parent menu (null untuk menu utama) |

**Foreign Key Constraints:**
- `menu_parent_id` REFERENCES `menus(menu_id)`

**Sample Menu Data:**
```sql
INSERT INTO menus (menu_id, menu_name, menu_path, menu_icon, menu_order, menu_parent_id) VALUES 
(1, 'Dashboard', '/dashboard', 'fas fa-tachometer-alt', 1, NULL),
(2, 'Data Management', NULL, 'fas fa-database', 2, NULL),
(3, 'User Access', '/data/akses', 'fas fa-user', 1, 2),
(4, 'View Data', '/data/lihat', 'fas fa-eye', 2, 2);
```

---

### 4. Table: `menu_permissions`
**Purpose**: Mengatur hak akses role terhadap menu (many-to-many relationship)

| Column Name | Data Type | Constraints | Description |
|-------------|-----------|-------------|-------------|
| `permissions_id` | SERIAL | PRIMARY KEY | ID unik untuk setiap permission |
| `menu_id` | INTEGER | NOT NULL, FK to menus(menu_id) | Foreign key ke tabel menus |
| `role_id` | INTEGER | NOT NULL, FK to role(role_id) | Foreign key ke tabel role |

**Foreign Key Constraints:**
- `menu_id` REFERENCES `menus(menu_id)`
- `role_id` REFERENCES `role(role_id)`

**Unique Constraints:**
- UNIQUE(`menu_id`, `role_id`) - Mencegah duplikasi permission

**Sample Permissions:**
```sql
-- Admin memiliki akses ke semua menu
INSERT INTO menu_permissions (menu_id, role_id) VALUES 
(1, 1), (2, 1), (3, 1), (4, 1);

-- Teacher memiliki akses terbatas
INSERT INTO menu_permissions (menu_id, role_id) VALUES 
(1, 2), (4, 2);
```

---

## Go Code Mapping

### User Struct (main.go)
```go
type User struct {
    UserID           int    `json:"user_id"`           // users.user_id
    UserNamaDepan    string `json:"user_nama_depan"`   // users.user_nama_depan
    UserNamaBelakang string `json:"user_nama_belakang"` // users.user_nama_belakang
    UserUsername     string `json:"user_username"`     // users.user_username
    UserPassword     string `json:"user_password"`     // users.user_password (bcrypt hash)
    UserRoleID       int    `json:"user_role_id"`      // users.user_role_id
    RoleName         string `json:"role_name"`         // role.role_name (JOIN)
    IsAdmin          bool   `json:"is_admin"`          // role.is_admin (JOIN)
    IsActive         bool   `json:"is_active"`         // users.is_active
}
```

### Menu Struct (main.go)
```go
type Menu struct {
    MenuID       int     `json:"menu_id"`        // menus.menu_id
    MenuName     string  `json:"menu_name"`      // menus.menu_name
    MenuPath     *string `json:"menu_path"`      // menus.menu_path (nullable)
    MenuIcon     *string `json:"menu_icon"`      // menus.menu_icon (nullable)
    MenuOrder    int     `json:"menu_order"`     // menus.menu_order
    MenuParentID *int    `json:"menu_parent_id"` // menus.menu_parent_id (nullable)
}
```

---

## Key SQL Queries

### Authentication Query
```sql
SELECT u.user_id, u.user_nama_depan, u.user_nama_belakang, u.user_username, 
       u.user_password, u.user_role_id, r.role_name, r.is_admin, u.is_active
FROM users u
JOIN role r ON u.user_role_id = r.role_id
WHERE u.user_username = $1 AND u.is_active = true
```

### Menu by Role Query
```sql
SELECT DISTINCT m.menu_id, m.menu_name, m.menu_path, m.menu_icon, m.menu_order, m.menu_parent_id
FROM menus m
INNER JOIN menu_permissions mp ON m.menu_id = mp.menu_id
INNER JOIN role r ON mp.role_id = r.role_id
WHERE r.role_name = $1
ORDER BY m.menu_order ASC
```

### All Menus Query (Admin)
```sql
SELECT menu_id, menu_name, menu_path, menu_icon, menu_order, menu_parent_id 
FROM menus 
ORDER BY menu_order ASC
```

---

## Important Notes

### 1. Column Naming Convention
- **BENAR**: `user_username`, `user_password`, `user_role_id`
- **SALAH**: `username`, `password_hash`, `role_id`

### 2. Password Security
- Passwords di-hash menggunakan **bcrypt** dengan cost 10
- Gunakan `bcrypt.CompareHashAndPassword()` untuk verifikasi
- Contoh hash untuk password "123456": `$2a$10$qqE7esxoiQIKH8uU6xa6ieF5XCTC2q4Gtj3oNHpqZugVgRtbxXUke`

### 3. Role-Based Access
- Role `admin` dengan `is_admin = true` memiliki akses ke semua menu
- Role lain hanya bisa akses menu sesuai `menu_permissions`

### 4. Nullable Fields
- `menu_path`: NULL untuk parent menu yang tidak clickable
- `menu_icon`: NULL jika tidak ada icon
- `menu_parent_id`: NULL untuk menu level utama

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | Autentikasi user dengan bcrypt |
| GET | `/menu/{role}` | Ambil menu berdasarkan role |
| GET | `/test` | Status koneksi database |
| GET | `/debug/users` | Debug: lihat semua user |
| GET | `/debug/menu-raw` | Debug: lihat semua menu |

---

## Default Login Credentials

| Username | Password | Role | Access |
|----------|----------|------|--------|
| `admin` | `123456` | admin | Full access to all menus |

---

*Dokumentasi ini harus selalu di-update ketika ada perubahan struktur database.*
