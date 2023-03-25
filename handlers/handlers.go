package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtkey = []byte("alukachalu")//secret-key

var users = map[string]string{
	"user1":"password1",
	"user2":"password2",
}

type Credentials struct{
	Username string `json:"username"`
	Password string	`json:"password"`
}

type Claims struct{
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter,r *http.Request){
	var credentials Credentials
	err:=json.NewDecoder(r.Body).Decode(&credentials)
	if err!=nil{
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[credentials.Username]

	if !ok || expectedPassword != credentials.Password{
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//JWT CODE begins
	expirationTime := time.Now().Add(time.Minute*5)

	claims :=  &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	tokenString,err := token.SignedString(jwtkey)

	if err!=nil{
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//JWT CODE Ends

	http.SetCookie(w,&http.Cookie{
		Name: "token",
		Value: tokenString,
		Expires: expirationTime,
	})
}

func Home(w http.ResponseWriter,r *http.Request){
	cookie,err := r.Cookie("token")
	if err !=nil{
		if err == http.ErrNoCookie{
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn,err := jwt.ParseWithClaims(tokenStr,claims,
		func(t *jwt.Token) (interface{},error){
			return jwtkey,nil
		})

	if err!=nil{
		if err == jwt.ErrSignatureInvalid{
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid{
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s",claims.Username)))
}

func Refresh(w http.ResponseWriter,r *http.Request){
	cookie,err := r.Cookie("token")
	if err !=nil{
		if err == http.ErrNoCookie{
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn,err := jwt.ParseWithClaims(tokenStr,claims,
		func(t *jwt.Token) (interface{},error){
			return jwtkey,nil
		})

	if err!=nil{
		if err == jwt.ErrSignatureInvalid{
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid{
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//Till here same as Home code, now creating a new token as this is refresh end point

	//This below is a check which is used to check if current token has left time less than 30sec, if time of current token is still >30sec then dont refresh the token
	// if time.Unix(claims.ExpiresAt,0).Sub(time.Now()) > 30*time.Second{
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }
	//JWT CODE begins
	expirationTime := time.Now().Add(time.Minute*5)

	claims.ExpiresAt=expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	tokenString,err := token.SignedString(jwtkey)

	if err!=nil{
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//JWT CODE Ends

	http.SetCookie(w,&http.Cookie{
		Name: "refresh_token",
		Value: tokenString,
		Expires: expirationTime,
	})

}