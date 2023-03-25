package main

import (
	handlers "golang/jwt-api/handlers"
	"log"
	"net/http"
)
func main(){
	http.HandleFunc("/login",handlers.Login)
	http.HandleFunc("/home",handlers.Home)
	http.HandleFunc("/refresh",handlers.Refresh)

	log.Fatal(http.ListenAndServe(":8080",nil))

}