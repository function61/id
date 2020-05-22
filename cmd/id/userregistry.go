package main

import (
	"github.com/function61/gokit/storedpassword"
	"github.com/function61/id/pkg/idtypes"
)

type sensitiveUser struct {
	user           idtypes.User // non-sensitive bits
	passwordHashed string
}

type userRegistry struct {
	usersData []*sensitiveUser
}

func (u *userRegistry) CheckLogin(email string, givenPassword string) *idtypes.User {
	userData := u.userByEmail(email)

	if userData == nil {
		return nil
	}

	_, err := storedpassword.Verify(
		storedpassword.StoredPassword(userData.passwordHashed),
		givenPassword,
		storedpassword.BuiltinStrategies)

	if err != nil {
		return nil
	}

	return &userData.user
}

func (u *userRegistry) UserById(id string) *idtypes.User {
	for _, userData := range u.usersData {
		if userData.user.Id == id {
			return &userData.user
		}
	}

	return nil
}

func (u *userRegistry) userByEmail(email string) *sensitiveUser {
	for _, userData := range u.usersData {
		if userData.user.Email == email {
			return userData
		}
	}

	return nil
}
