package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Generate bcrypt hash for password "123456"
	password := "123456"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Error generating hash:", err)
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Bcrypt Hash: %s\n", string(hash))
	fmt.Println("\n--- SQL to update Neon database ---")
	fmt.Printf("UPDATE users SET password_hash = '%s' WHERE username = 'admin';\n", string(hash))

	// Test the hash
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		fmt.Println("❌ Hash verification failed!")
	} else {
		fmt.Println("✅ Hash verification successful!")
	}
}
