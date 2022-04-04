package main

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"os"
	"time"
)

var client *mongo.Client
var usersCol *mongo.Collection
var chatsCol *mongo.Collection
var messagesCol *mongo.Collection
var friendsCol *mongo.Collection

func main() {
	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017")) // TODO: read host from env variable
	if err != nil {
		// TODO: log
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	usersCol = client.Database("vk-chat").Collection("users")
	chatsCol = client.Database("vk-chat").Collection("chats")
	messagesCol = client.Database("vk-chat").Collection("messages")
	friendsCol = client.Database("vk-chat").Collection("friends")

	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/addFriend", AddFriend)
	http.HandleFunc("/showFriends", ShowFriends)
	http.HandleFunc("/getChat", GetChatWithFriend)
	http.HandleFunc("/sendMessage", SendMessage)

	// start the server on port 8080
	log.Fatal(http.ListenAndServe(":8080", nil))
}
