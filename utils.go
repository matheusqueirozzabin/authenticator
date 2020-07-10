package authenticator

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"fmt"

	"github.com/matheusqueirozzabin/bitpermission"
	"github.com/matheusqueirozzabin/exception"
)

func (a *Authenticator) getBoolPermissionsByUserID(userID int64, audience string, tx *sql.Tx) (permissions []bool, err error) {
	defer exception.Catch(&err, func(_ error) {
		permissions = []bool{}
	})

	var rawPermissions string
	if err := tx.QueryRow(`
			SELECT
				permission
			FROM audience
			WHERE
				user_id = ? AND
				audience = ?
			LIMIT 1
		`,
		userID,
		audience,
	).Scan(&rawPermissions); err != nil {
		return nil, err
	}
	bytePermissions, err := bitpermission.Decode(rawPermissions)
	if err != nil {
		return []bool{}, nil
	}
	return bitpermission.DecodeToBoolean(bytePermissions), nil
}

func (a *Authenticator) encodePassword(username string, password string) (encoded string, err error) {
	defer exception.Catch(&err, func(err error) {
		encoded = ""
	})
	encoded, err = a.sha256WithSecret(fmt.Sprintf("#username%s.#password%s", username, password))
	if err != nil {
		return "", err
	}
	return encoded, nil
}

func (a *Authenticator) getPermissionSignature(permissions string, audience string, userID int64) (signature string, err error) {
	defer exception.Catch(&err, func(err error) {
		signature = ""
	})

	signature, err = a.sha256WithSecret(fmt.Sprintf("%s%d%s%d", permissions, userID, audience, userID))
	if err != nil {
		return "", err
	}

	return signature, nil
}

func (a *Authenticator) getTokenSignature(payload string) (signature string, err error) {
	defer exception.Catch(&err, func(err error) {
		signature = ""
	})
	signature, err = a.sha256WithSecret(fmt.Sprintf("%s.%s", tokenHeader, payload))
	if err != nil {
		return "", err
	}
	return signature, nil
}

func (a *Authenticator) sha256WithSecret(message string) (encrypted string, err error) {
	defer exception.Catch(&err, func(err error) {
		encrypted = ""
	})
	mac := hmac.New(sha256.New, a.secret)
	_, err = mac.Write([]byte(message))
	if err != nil {
		return "", err
	}
	return string(mac.Sum(nil)), nil
}
