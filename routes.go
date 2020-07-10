package authenticator

import (
	"database/sql"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/matheusqueirozzabin/bitpermission"
	"github.com/matheusqueirozzabin/exception"
)

func (a *Authenticator) Login(username string, password string, audience string) (token string, err error) {
	defer exception.Catch(&err, func(_ error) {
		token = ""
	})
	var tokenObj jwt
	if err = a.database.Transact(func(tx *sql.Tx) error {
		var userID int64
		var dbPassword string
		var permissions string
		var signature string
		if err := tx.QueryRow(`
				SELECT
					u.id,
					u.password,
					a.permissions,
					a.signature
				FROM user AS u
				LEFT JOIN audience AS a ON
					a.user_id = u.id
				WHERE
					u.username = ? AND
					a.audience = ?
				LIMIT 1
			`, username, audience).Scan(
			&userID,
			&dbPassword,
			&permissions,
			&signature,
		); err != nil {
			return err
		}
		encodedPassword, err := a.encodePassword(username, password)
		if err != nil {
			return err
		}
		if encodedPassword != dbPassword {
			return errors.New("wrong password")
		}

		encodedSignature, err := a.getPermissionSignature(permissions, audience, userID)
		if err != nil {
			return err
		}

		if encodedSignature != signature {
			return errors.New("invalid signature")
		}

		now := int64(time.Now().Unix())

		tokenObj = jwt{
			ExpireAt:    now + a.tokenDuration,
			IssuedAt:    now,
			Permissions: permissions,
			Issuer:      a.issuer,
			Audience:    audience,
			Subject:     userID,
			ID:          0,
			Route:       "",
		}

		return nil
	}); err != nil {
		return "", err
	}

	byteToken, err := json.Marshal(tokenObj)
	if err != nil {
		return "", err
	}
	payload := b64.StdEncoding.EncodeToString(byteToken)

	signature, err := a.getTokenSignature(payload)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", tokenHeader, payload, signature), nil
}

func (a *Authenticator) Authorize(username string, password string, audience string, route string) (token string, err error) {
	defer exception.Catch(&err, func(_ error) {
		token = ""
	})

	var tokenObj jwt
	if err := a.database.Transact(func(tx *sql.Tx) (err error) {
		defer exception.Catch(&err)

		var userID int64
		var dbPassword string
		var permissions string
		var signature string
		if err := tx.QueryRow(`
		SELECT
			u.id,
			u.password,
			a.permissions,
			a.signature
		FROM user AS u
		INNER JOIN audience AS a ON
			a.user_id = u.id
		WHERE
			u.username = ? AND
			a.audience = ?
		LIMIT 1
		`, username, audience).Scan(
			&userID,
			&dbPassword,
			&permissions,
			&signature,
		); err != nil {
			return err
		}
		encodedPassword, err := a.encodePassword(username, password)
		if err != nil {
			return err
		}
		if encodedPassword != dbPassword {
			return errors.New("wrong password")
		}

		encodedSignature, err := a.getPermissionSignature(permissions, audience, userID)
		if err != nil {
			return err
		}

		if encodedSignature != signature {
			return errors.New("invalid signature")
		}

		stmt, err := tx.Prepare("INSERT INTO token DEFAULT VALUES")
		if err != nil {
			return err
		}
		defer stmt.Close()
		result, err := stmt.Exec()
		if err != nil {
			return err
		}
		tokenID, err := result.LastInsertId()
		if err != nil {
			return err
		}

		now := int64(time.Now().Unix())

		tokenObj = jwt{
			ExpireAt:    now + a.singleUseTokenDuration,
			IssuedAt:    now,
			Permissions: permissions,
			Issuer:      a.issuer,
			Audience:    audience,
			Subject:     userID,
			ID:          tokenID,
			Route:       route,
		}

		return nil
	}); err != nil {
		return "", err
	}

	byteToken, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	payload := b64.StdEncoding.EncodeToString(byteToken)

	signature, err := a.getTokenSignature(payload)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", tokenHeader, payload, signature), nil
}

func (a *Authenticator) ChangePermission(userID int64, targetUserID int64, audience string, permissionsToChange map[bitpermission.ID]bool) (err error) {
	defer exception.Catch(&err)
	if err = a.database.Transact(func(tx *sql.Tx) (err error) {
		defer exception.Catch(&err)
		targetPermissions, err := a.getBoolPermissionsByUserID(targetUserID, audience, tx)
		if err != nil {
			return err
		}
		userPermissions, err := a.getBoolPermissionsByUserID(userID, audience, tx)
		if err != nil {
			return err
		}

		maxUserPermission := bitpermission.ID(len(userPermissions))
		for id, newValue := range permissionsToChange {
			if id < maxUserPermission && userPermissions[id] {
				targetPermissions[id] = newValue
			}
		}
		changedPermissions := bitpermission.Encode(targetPermissions)
		permissionSignature, err := a.getPermissionSignature(changedPermissions, audience, targetUserID)

		stmt, err := tx.Prepare(`
			UPDATE audience SET
				permissions = ?,
				signature = ?
			WHERE
				user_id = ? AND
				audience = ?
			`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		result, err := stmt.Exec(targetPermissions, permissionSignature, targetUserID, audience)
		if err != nil {
			return err
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("rows affected %d != 1", rowsAffected)
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
