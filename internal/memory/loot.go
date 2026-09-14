package memory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// LootDB manages the structured storage of discovered assets and encrypted credentials.
type LootDB struct {
	mu  sync.Mutex
	db  *sql.DB
	key []byte // AES-256 encryption key
}

// NewLootDB creates or opens the SQLite database and initializes encryption.
func NewLootDB() (*LootDB, error) {
	dataDir := filepath.Join("data")
	_ = os.MkdirAll(dataDir, 0755)

	dbPath := filepath.Join(dataDir, "drogonclaw_loot.db")
	// WAL + busy timeout so multiple agent workers (parallel benchmark, subagent
	// fan-out) can share the ledger without "database is locked" failures.
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open loot db: %w", err)
	}

	key, err := loadOrGenerateKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption key: %w", err)
	}

	loot := &LootDB{db: db, key: key}
	if err := loot.initSchema(); err != nil {
		return nil, err
	}

	return loot, nil
}

func loadOrGenerateKey(dataDir string) ([]byte, error) {
	keyPath := filepath.Join(dataDir, ".loot_key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		key := make([]byte, 32) // AES-256
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		// Secure permissions: owner read/write only
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			return nil, err
		}
		return key, nil
	}
	return os.ReadFile(keyPath)
}

func encryptData(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (l *LootDB) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);`,
		`CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT NOT NULL UNIQUE,
			ip TEXT,
			os TEXT,
			status TEXT DEFAULT 'alive',
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS ports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			service TEXT,
			version TEXT,
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip, port)
		);`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			username TEXT,
			password_enc TEXT,
			hash_enc TEXT,
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			cve TEXT,
			description TEXT,
			severity TEXT,
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS flags (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			flag TEXT NOT NULL UNIQUE,
			discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, query := range queries {
		if _, err := l.db.Exec(query); err != nil {
			return fmt.Errorf("schema init failed: %w", err)
		}
	}
	return nil
}

// InsertPort adds a discovered port to the loot database.
func (l *LootDB) InsertPort(ip string, port int, service, version string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.db.Exec(`INSERT OR IGNORE INTO ports (ip, port, service, version, discovered_at) VALUES (?, ?, ?, ?, ?)`, ip, port, service, version, time.Now())
	return err
}

// InsertCredential adds a discovered password or hash to the loot database.
// The password and hash are AES-GCM encrypted before storage.
func (l *LootDB) InsertCredential(target, username, password, hash string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	encPassword, err := encryptData(l.key, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	encHash, err := encryptData(l.key, hash)
	if err != nil {
		return fmt.Errorf("failed to encrypt hash: %w", err)
	}

	_, err = l.db.Exec(`INSERT INTO credentials (target, username, password_enc, hash_enc, discovered_at) VALUES (?, ?, ?, ?, ?)`,
		target, username, encPassword, encHash, time.Now())
	return err
}

// InsertTarget records an identified target host or IP.
func (l *LootDB) InsertTarget(host, ip, os string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.db.Exec(`INSERT OR IGNORE INTO targets (host, ip, os, discovered_at) VALUES (?, ?, ?, ?)`, host, ip, os, time.Now())
	return err
}

// InsertFlag records a captured CTF or proof-of-compromise flag.
func (l *LootDB) InsertFlag(target, flag string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.db.Exec(`INSERT OR IGNORE INTO flags (target, flag, discovered_at) VALUES (?, ?, ?)`, target, flag, time.Now())
	return err
}

// InsertVulnerability adds a CVE or vulnerability to the loot database.
func (l *LootDB) InsertVulnerability(target, cve, description, severity string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.db.Exec(`INSERT INTO vulnerabilities (target, cve, description, severity, discovered_at) VALUES (?, ?, ?, ?, ?)`, target, cve, description, severity, time.Now())
	return err
}

// FindingItem is one human-readable line from the findings ledger.
type FindingItem struct {
	Category string
	Target   string
	Detail   string
	Severity string
}

// FindingsReport summarises the loot ledger: per-category totals plus the most
// recent items (capped at limit per category). Credentials are decrypted so the
// operator can review them; the report is only ever delivered to the whitelisted
// chat or the local operator.
type FindingsReport struct {
	Ports           int
	Credentials     int
	Vulnerabilities int
	Items           []FindingItem
}

// Findings reads the current findings ledger. Credential passwords/hashes are
// AES-GCM decrypted before being returned.
func (l *LootDB) Findings(limit int) (FindingsReport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var rep FindingsReport

	if err := l.db.QueryRow(`SELECT COUNT(*) FROM ports`).Scan(&rep.Ports); err != nil {
		return rep, err
	}
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&rep.Credentials); err != nil {
		return rep, err
	}
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`).Scan(&rep.Vulnerabilities); err != nil {
		return rep, err
	}

	rows, err := l.db.Query(`SELECT ip, port, service, version FROM ports ORDER BY discovered_at DESC LIMIT ?`, limit)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var ip, service, version string
		var port int
		if err := rows.Scan(&ip, &port, &service, &version); err != nil {
			rows.Close()
			return rep, err
		}
		detail := fmt.Sprintf("%s/%d %s", ip, port, service)
		if version != "" {
			detail += " " + version
		}
		rep.Items = append(rep.Items, FindingItem{Category: "port", Target: ip, Detail: detail})
	}
	rows.Close()

	rows, err = l.db.Query(`SELECT target, cve, description, severity FROM vulnerabilities ORDER BY discovered_at DESC LIMIT ?`, limit)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var target, cve, desc, sev string
		if err := rows.Scan(&target, &cve, &desc, &sev); err != nil {
			rows.Close()
			return rep, err
		}
		detail := cve
		if desc != "" {
			if detail != "" {
				detail += " — " + desc
			} else {
				detail = desc
			}
		}
		rep.Items = append(rep.Items, FindingItem{Category: "vuln", Target: target, Detail: detail, Severity: sev})
	}
	rows.Close()

	rows, err = l.db.Query(`SELECT target, username, password_enc, hash_enc FROM credentials ORDER BY discovered_at DESC LIMIT ?`, limit)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var target, user, passEnc, hashEnc string
		if err := rows.Scan(&target, &user, &passEnc, &hashEnc); err != nil {
			rows.Close()
			return rep, err
		}
		pass, _ := l.decryptData(passEnc)
		hash, _ := l.decryptData(hashEnc)
		detail := user
		if pass != "" {
			detail += " / " + pass
		}
		if detail == "" && hash != "" {
			detail = "hash " + hash
		}
		rep.Items = append(rep.Items, FindingItem{Category: "cred", Target: target, Detail: detail})
	}
	rows.Close()

	return rep, nil
}

func (l *LootDB) decryptData(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(l.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, body := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Close gracefully closes the database.
func (l *LootDB) Close() error {
	return l.db.Close()
}
