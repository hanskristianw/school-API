# School Admin API

API backend untuk sistem administrasi sekolah menggunakan Go dan PostgreSQL.

## Setup

1. Clone repository ini
2. Copy file environment template:
   ```bash
   cp .env.example .env
   ```
3. Edit file `.env` dan isi dengan kredensial database yang sebenarnya
4. Install dependencies:
   ```bash
   go mod tidy
   ```
5. Jalankan server:
   ```bash
   go run main.go
   ```

## Environment Variables

- `DATABASE_URL`: Connection string untuk PostgreSQL database
- `PORT`: Port untuk server (default: 8080)

## Security

- **JANGAN PERNAH** commit file `.env` ke repository
- File `.env` sudah ditambahkan ke `.gitignore`
- Gunakan environment variables untuk production deployment

## API Endpoints

- `GET /test` - Server status & database info
- `POST /login` - User authentication
- `GET /menu/{role}` - Get menus by role
- `GET|POST /users` - User CRUD operations
- `GET|POST|PUT|DELETE /units` - Unit management
- `GET /roles` - Get all roles

## Database

Menggunakan Neon PostgreSQL cloud database dengan struktur tabel:
- `users` - User management
- `role` - User roles
- `menus` - Menu system
- `menu_permissions` - Role-based menu access
- `unit` - Unit management
