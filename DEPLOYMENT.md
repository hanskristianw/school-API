# Production Deployment Guide

## Environment Variables untuk Production

Untuk deployment production, set environment variables berikut:

### Heroku
```bash
heroku config:set DATABASE_URL="postgresql://username:password@host:port/database?sslmode=require"
heroku config:set PORT=8080
```

### Docker
Buat file `docker-compose.yml`:
```yaml
version: '3.8'
services:
  school-api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://username:password@host:port/database?sslmode=require
      - PORT=8080
```

### Linux/Ubuntu Server
```bash
export DATABASE_URL="postgresql://username:password@host:port/database?sslmode=require"
export PORT=8080
./school-API
```

### Windows Server
```cmd
set DATABASE_URL=postgresql://username:password@host:port/database?sslmode=require
set PORT=8080
school-API.exe
```

## Security Checklist

- ✅ Kredensial database tidak ada di source code
- ✅ File `.env` ditambahkan ke `.gitignore`
- ✅ Environment variables digunakan untuk konfigurasi sensitif
- ✅ Template `.env.example` tersedia untuk developer baru
- ✅ README berisi instruksi setup yang jelas

## Langkah Selanjutnya

1. **Ganti password database** untuk keamanan ekstra
2. **Setup SSL/TLS** untuk koneksi HTTPS
3. **Setup monitoring** untuk production
4. **Setup backup database** otomatis
5. **Setup CI/CD pipeline** untuk deployment otomatis
