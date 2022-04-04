package main

import (
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// this map stores the users sessions. For larger scale applications,
// we can use a database or cache for this purpose
var sessions = map[string]session{}

// each session contains the username of the user and the time at which it expires
type session struct {
	username string
	expiry   time.Time
}

// we'll use this method later to determine if the session has expired
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChatType int

const (
	Private ChatType = iota
	Group
)

type User struct {
	Login    string `bson:"login"`
	Password string `bson:"password"`
}

type Chat struct {
	Name         string    `bson:"name"`
	CreationTime time.Time `bson:"creationTime"`
	Type         ChatType  `bson:"type"`
}

type UserChat struct {
	UserID primitive.ObjectID `bson:"userId"`
	ChatID primitive.ObjectID `bson:"chatId"`
}

type Message struct {
	Sender    string `bson:"sender"`
	Recipient string `bson:"recipient"`
	Content   string `bson:"content"`
}

var curUser string

func Register(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost) // TODO: think about memory for []byte and string conversions
	if err != nil {
		log.Println("error while generating hash for password: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user := &User{}
	err = usersCol.FindOne(ctx, bson.D{{"login", credentials.Username}}).Decode(user)
	if err != nil {
		log.Println("error while fetching user from database: ", err)
		user = nil
	}
	if user != nil {
		w.WriteHeader(http.StatusConflict) // means that user already exists, we can use this in frontend
		return
	}
	_, err = usersCol.InsertOne(ctx, bson.D{{"login", credentials.Username}, {"password", string(hashedPassword)}})
	if err != nil {
		log.Println("error while storing user at the database: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// if status is OK, we can redirect to sign-in page in frontend
	w.WriteHeader(http.StatusOK)
}

func ShowFriends(w http.ResponseWriter, r *http.Request) {
	if verifySession(w, r) != true {
		return
	}
	filter := bson.D{
		{
			"$or",
			bson.A{
				bson.D{{"firstName", curUser}}, bson.D{{"secondName", curUser}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	cursor, err := friendsCol.Find(ctx, filter)
	if err != nil {
		log.Println("error while searching in a database: ", err)
	}
	defer cancel()

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		panic(err)
	}
	var ans []string
	for _, result := range results {
		if result["firstName"] == curUser {
			ans = append(ans, result["secondName"].(string))
		}
		if result["secondName"] == curUser {
			ans = append(ans, result["firstName"].(string))
		}
	}

	j, err := json.Marshal(ans)
	if err != nil {
		log.Println("error on marshalling: ", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(j)
	if err != nil {
		log.Println("error on writing response: ", err)
	}
}

func AddFriend(w http.ResponseWriter, r *http.Request) {
	if verifySession(w, r) != true {
		return
	}
	var friend string
	friend = r.URL.Query().Get("friend")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	friendUser := &User{}
	err := usersCol.FindOne(ctx, bson.D{{"login", friend}}).Decode(friendUser)
	if err != nil {
		log.Println("error while fetching user from database: ", err)
		friendUser = nil
	}
	if friendUser == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	firstUser := friendUser.Login
	secondUser := curUser
	if secondUser < firstUser {
		secondUser, firstUser = firstUser, secondUser
	}

	_, err = friendsCol.InsertOne(ctx, bson.D{{"firstName", friend}, {"secondName", curUser}})
	if err != nil {
		log.Println("error on inserting user: ", err)
	}
}

func SendMessage(w http.ResponseWriter, r *http.Request) {
	if verifySession(w, r) != true {
		return
	}
	var message Message
	err := json.NewDecoder(r.Body).Decode(&message)
	if err != nil {
		log.Println("error on reading request body: ", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	messagesCol.InsertOne(ctx, message)
}

func GetChatWithFriend(w http.ResponseWriter, r *http.Request) {
	if verifySession(w, r) != true {
		return
	}
	var friend string
	friend = r.URL.Query().Get("friend")
	type messagesBson bson.D
	filter := bson.D{{"$or",
		bson.A{bson.D{{"sender", curUser},
			{"recipient", friend}},
			bson.D{{"recipient", curUser}, {"sender", friend}}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cursor, err := messagesCol.Find(ctx, filter)
	if err != nil {
		//TODO log
	}
	var message Message
	messagesCol.FindOne(ctx, filter).Decode(&message)
	var messages []Message
	if err = cursor.All(context.TODO(), &messages); err != nil {
		panic(err)
	}
	j, err := json.Marshal(messages)
	if err != nil {
		//TODO log
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var expectedUser bson.D
	err = usersCol.FindOne(ctx, bson.D{{"login", creds.Username}}).Decode(&expectedUser)
	if err != nil {
		log.Println("error while fetching user from database: ", err)
	}
	expectedPassword, ok := expectedUser.Map()["password"].(string)
	if !ok {
		// TODO: log
	}
	err = bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(creds.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create a new random session token
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)

	// Set the token in the session map, along with the user whom it represents
	sessions[sessionToken] = session{
		username: creds.Username,
		expiry:   expiresAt,
	}

	// Finally, we set the client cookie for "session_token" as the session token we just generated
	// we also set an expiry time of 120 seconds
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})
	curUser = creds.Username
}

func verifySession(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, we return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		// For any other type of error
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	sessionToken := c.Value

	// We then get the name of the user from our session map, where we set the session token
	userSession, exists := sessions[sessionToken]
	if !exists {
		// If the session token is not present in session map, we return an unauthorized error
		w.WriteHeader(http.StatusUnauthorized)
		return false

	}

	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	userSession, exists := sessions[sessionToken]
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newSessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Second)

	sessions[newSessionToken] = session{
		username: userSession.username,
		expiry:   expiresAt,
	}

	delete(sessions, sessionToken)

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   newSessionToken,
		Expires: time.Now().Add(120 * time.Second),
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, we will return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// remove the user session from the session map
	delete(sessions, sessionToken)

	// We need to let the client know that the cookie is expired
	// In the response, we set the session token to an empty
	// value and set its expiry as the current time
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})
}
