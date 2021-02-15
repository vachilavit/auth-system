package testdata

import "github.com/vachilavit/auth-system/internal/auth/model"

func UserData() model.User {
	return model.User{
		ID:             "e3e832db-b725-4fd5-94be-0ca4bc112e7d",
		Username:       "admin",
		HashedPassword: "ab0a8644e8ba7ffd7bdbde3773c66203117e41580b791be0ef7af5c96d794446",
		Salt:           "724409f8-92e1-4e1c-b0cc-cc463da985ee",
	}
}
