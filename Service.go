package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	mux "github.com/gorilla/mux"
)

var publicKeyData, fileReadError = ioutil.ReadFile("keys/id_rsa.pem")
var pemBlock, _ = pem.Decode(publicKeyData)
var publicKey, _ = x509.ParsePKCS1PublicKey(pemBlock.Bytes)

// var publicKey, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyData))

var privateKeyData, _ = ioutil.ReadFile("keys/id_rsa")
var privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)

func main() {
	router := mux.NewRouter()
	router.Handle("/", http.FileServer(http.Dir("./views/")))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	router.Handle("/method1", jwtMiddleware(method1Handler)).Methods("GET")
	router.Handle("/method2", NotImplemented).Methods("GET")

	fmt.Print(publicKey.E)
	router.Handle("/sampletoken", GetTokenHandler).Methods("GET")
	if fileReadError != nil {
		fmt.Errorf("Error reading public key from file", fileReadError)
		return
	}
	http.ListenAndServe(":3000", router)
}

// Item type
type ResponseItem struct {
	Id          int
	Name        string
	Description string
}

// Items array
var oneKiloJSONArray = []ResponseItem{
	ResponseItem{Id: 1, Name: "Item1", Description: "fmas;fmksal;df,a"},
	ResponseItem{Id: 2, Name: "Item2", Description: "dasjdndscsmdfnasd;klnf;kds"},
	ResponseItem{Id: 3, Name: "Item3", Description: "dhnaeuwhfqwbe"},
	ResponseItem{Id: 4, Name: "Item4", Description: "mfoqpmfqwefqmwem"},
}

// NotImplemented - Not Imlemented placeholder
var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("products not Implemented"))
})

// method1Handler - method1 handler
var method1Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	responseArray, _ := json.Marshal(oneKiloJSONArray)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(responseArray))
})

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		token, err := request.ParseFromRequestWithClaims(r, request.HeaderExtractor{"ACCESS-TOKEN"}, jwt.MapClaims{}, keyfunc)

		if err != nil {
			fmt.Println(err)
			fmt.Println("Inavlid token:", token)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		} else {
			if !token.Valid {

				fmt.Println("Token is not valid:", token)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
			} else {

				claimsJSON, _ := json.Marshal(token.Claims)
				w.Header().Set("JWT-TOKEN", string(claimsJSON))
				next.ServeHTTP(w, r)
			}
		}
	})
}

var signingKey = []byte("secret")

var keyfunc = func(*jwt.Token) (interface{}, error) {
	return publicKey, nil
}

//GetTokenHandler - sample token
var GetTokenHandler = http.HandlerFunc(func(w http.ResponseWriter,
	r *http.Request) {
	// creating new token
	token := jwt.New(jwt.SigningMethodRS256)
	claims := make(jwt.MapClaims)
	// Setting token claims
	claims["admin"] = false
	claims["name"] = "Michael Oznobkin"
	claims["aud"] = "service1"
	claims["scope"] = "method1, method2"
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	token.Claims = claims
	// sign token with our secret key

	tokenString, _ := token.SignedString(privateKey)

	w.Write([]byte(tokenString))
})
