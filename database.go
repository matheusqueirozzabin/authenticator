package authenticator

func getMigrations() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS user (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audience (
			id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			audience TEXT NOT NULL,
			permissions NOT NULL TEXT,
			signature NOT NULL TEXT,
			FOREIGN KEY(user_id) REFERENCES user(id)
		)`,
		`CREATE TABLE IF NOT EXISTS token (
			id INTEGER PRIMARY KEY,
			date TEXT NOT NULL DEFAULT (datetime('now','localtime')),
			used INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS fail_attempt (
			id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			date TEXT NOT NULL DEFAULT (datetime('now','localtime')),
			password TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES user_id(id)
		)`,
		`CREATE TABLE IF NOT EXISTS cleanup (
			id INTEGER PRIMARY KEY,
			date TEXT DEFAULT (datetime('now','localtime')),
			fail_attempt_records INTEGER,
			forbidden_records INTEGER
		)`,
	}
}
