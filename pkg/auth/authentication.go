package auth
import (
	"crypto/rand"
	//"errors"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
)
func HashAndSalt(password string) (hashedPass string, salt string, err error){
	
	saltSeed := make([]byte, 16) // create salt
	rand.Read(saltSeed)
	salt = base64.StdEncoding.EncodeToString(saltSeed)
	saltedPass := password + salt // append salt to pass
	hash, err := bcrypt.GenerateFromPassword([]byte(saltedPass), 16) 
	hashedPass = base64.StdEncoding.EncodeToString(hash) // hash the password
	return hashedPass, salt, err
}
func VerifyPass(password, hash, salt string) (error){
	saltedPassword := password +  salt
	decodedHash, err := base64.StdEncoding.DecodeString(hash)
	if(err != nil) {
		return err
	}
	return bcrypt.CompareHashAndPassword(decodedHash, []byte(saltedPassword))
}