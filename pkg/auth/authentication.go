package auth
import (
	"crypto/rand"
	//"errors"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
)
//simplifying the wrappers for bcrypt functions
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
//returns true if passwords match
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
