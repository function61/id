package idtypes

import (
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Email     string    `json:"email"`
	AvatarURL string    `json:"avatar_url"`
}
