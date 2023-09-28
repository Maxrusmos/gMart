package user

import (
	"encoding/json"
	"gMart/cmd/gophermart/internal/database"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("12345678")

func GenerateJWTToken(user User) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID
	claims["username"] = user.Login
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	user.UserBalance = 1000
	user.UserWithdrawals = 1000
	token, err := GenerateJWTToken(user)
	w.Header().Set("Authorization", "Bearer "+token)
	if err != nil {
		panic(err)
	}
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if isLoginTaken(user.Login) {
		http.Error(w, "Login already taken", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	session, err := database.GetSession()
	if err != nil {
		panic(err)
	}
	_, err = session.Exec("INSERT INTO gofermartUsersTable (login, password, userbalance, userwithdrawals) VALUES ($1, $2, $3, $4)", user.Login, hashedPassword, user.UserBalance, user.UserWithdrawals)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, err := GetUserIDByCredentials(user.Login, hashedPassword)
	if err != nil {
		panic(err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "UserID",
		Value:    strconv.Itoa(userID),
		HttpOnly: true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)
}
