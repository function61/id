package idtypes

import (
	"time"
)

type User struct {
	Id      string    `json:"id"`
	Created time.Time `json:"created"`
	Email   string    `json:"email"`
}
