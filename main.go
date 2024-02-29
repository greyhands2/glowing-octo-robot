package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type payload struct {
	Password string `json:"password"`
}

func main() {
	http.HandleFunc("/bcrypt", func(res http.ResponseWriter, req *http.Request) {
		var data payload
		if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
			http.Error(res, "Invalid Input", http.StatusBadRequest)
			return
		}
		// hash password
		hashedPassword, err := bcryptHandler(data.Password)
		if err != nil {
			http.Error(res, "Error Processing Data, Please Try Again", http.StatusInternalServerError)
			return
		}

		result := struct {
			Data string
		}{
			Data: hashedPassword,
		}

		resultJSON, _ := json.Marshal(result)

		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, err = res.Write(resultJSON)
		if err != nil {
			log.Println(err)
			http.Error(res, "User Created but Something Went Wrong Returning the Data. An OTP Has Been Sent To Your Email", http.StatusCreated)
			return
		}
	})

	http.HandleFunc("/argon2", func(res http.ResponseWriter, req *http.Request) {
		var data payload
		if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
			http.Error(res, "Invalid Input", http.StatusBadRequest)
			return
		}
		// hash password
		hashedPassword, err := argon2Handler(data.Password)
		if err != nil {
			http.Error(res, "Error Processing Data, Please Try Again", http.StatusInternalServerError)
			return
		}

		result := struct {
			Data string
		}{
			Data: hashedPassword,
		}

		resultJSON, _ := json.Marshal(result)
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, err = res.Write(resultJSON)
		if err != nil {
			log.Println(err)
			http.Error(res, "User Created but Something Went Wrong Returning the Data. An OTP Has Been Sent To Your Email", http.StatusCreated)
			return
		}
	})
	fmt.Println("server running on port 8080")
	http.ListenAndServe(":8080", nil)
}

func bcryptHandler(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	var hashErr error
	if err != nil {
		hashErr = err
	}

	return string(hash), hashErr
}

func argon2Handler(password string) (string, error) {
	// generate a salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// hash the password using Argon2
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	return encodedHash, nil
}
