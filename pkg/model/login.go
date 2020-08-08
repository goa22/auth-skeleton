package model

import (
	"time"
)

type User struct {
	Username     string `bson:"username"`
	Password     string `bson:"password"`
	Email        string `bson:"email"`
	IsActive     bool   `bson:"isActive"`
	EmailChecked bool   `bson:"emailChecked"`
}

type UserSession struct {
	Uuid      string    `bson:"uuid"`
	Username  string    `bson:"username"`
	LoginTime time.Time `bson:"loginTime"`
	LastSeen  time.Time `bson:"lastSeen"`
}
