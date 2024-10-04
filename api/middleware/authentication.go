package auth

import (
	"crypto/rand"
	"errors"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"

)


func HashAndSalt(password string) (hashedpass string, salt string, err error){
	
	saltSeed := make([]byte, 16)
	rand.Read(saltSeed)
	salt := base64.StdEncoding.EncodeToString(saltSeed)
	saltedPass := password + salt
	hash := bcrypt.GenerateFromPassword([]byte(saltedPass), 16)
	hashedPass = base64.StdEncoding.EncodeToString(hash)

	return hash, salt, nil

}

func VerifyPass(password, hash, salt string) (error){

	saltedPassword = password +  salt
	decodedHash, err := base64.StdEncoding.DecodeString(storedHash)

	return bcrypt.CompareHashAndPassword(decodedHash, []byte(saltedPassword))


}