package linceClient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/big"
	"time"
)

type DB struct {
	db *sql.DB
}

func (db *DB) init() {
	var err error
	//db.db, err = sql.Open("mysql", "phpmyadmin:28aprelz@tcp(127.0.0.1:3306)/")
	db.db, err = sql.Open("mysql", "root:28aprelz@tcp(127.0.0.1:3306)/")
	if err != nil {
		log.Fatal(err)
	}
	db.db.SetConnMaxLifetime(time.Minute * 3)
	db.db.SetMaxOpenConns(10)
	db.db.SetMaxIdleConns(10)
}

func (db *DB) Close() {
	db.db.Close()
}

func (db *DB) CreateDB() {
	_, err := db.db.Exec("CREATE DATABASE IF NOT EXISTS linse")
	if err != nil {
		log.Fatal(err)
	}
}

func (db *DB) CreateTables() {
	_, err := db.db.Exec("CREATE TABLE IF NOT EXISTS linse.licenses (product VARCHAR(255), license VARCHAR(255), buildId VARCHAR(255), maxConnections INT, connections INT,  UNIQUE(license, buildId))")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.db.Exec("CREATE TABLE IF NOT EXISTS linse.service_info (privKey TEXT, pubKey TEXT)")
	if err != nil {
		log.Fatal(err)
	}
}

func (db *DB) getLicenses(buildId string) []*Licenses {
	licenses := make([]*Licenses, 0)
	rows, err := db.db.Query("SELECT product, license, maxConnections, connections FROM linse.licenses WHERE buildId = ?", buildId)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		lic := Licenses{}
		err = rows.Scan(&lic.product, &lic.license, &lic.maxConnections, &lic.connections)
		if err != nil {
			log.Fatal(err)
		}
		licenses = append(licenses, &lic)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	return licenses
}

func (db *DB) addLicense(product string, buildId string, maxConnections int) string {
	license := generateLicense()
	_, err := db.db.Exec("INSERT INTO linse.licenses (product, buildId, maxConnections, connections, license) VALUES (?, ?, ?, ?, ?)", product, buildId, maxConnections, 0, license)
	if err != nil {
		log.Fatal(err)
	}
	return license
}

func (db *DB) addConnection(license string, buildId string) {
	_, err := db.db.Exec("UPDATE linse.licenses SET connections = connections + 1 WHERE license = ? AND buildId = ?", license, buildId)
	if err != nil {
		log.Fatal(err)
	}
}

func (db *DB) removeConnection(license string, buildId string) {
	_, err := db.db.Exec("UPDATE linse.licenses SET connections = connections - 1 WHERE license = ? AND buildId = ?", license, buildId)
	if err != nil {
		log.Fatal(err)
	}
}

//check buildId exists
func (db *DB) checkBuildId(buildId string) bool {
	rows, err := db.db.Query("SELECT buildId FROM linse.licenses WHERE buildId = ?", buildId)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		return true
	}
	return false
}

//check license exists
func (db *DB) checkLicense(product string, license string, buildId string) bool {
	rows, err := db.db.Query("SELECT license FROM linse.licenses WHERE product = ? AND license = ? AND buildId = ?", product, license, buildId)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		return true
	}
	return false
}

func (db *DB) getPrivateKey() *rsa.PrivateKey {
	rows, err := db.db.Query("SELECT privKey FROM linse.service_info")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var privKey string
		err = rows.Scan(&privKey)
		if err != nil {
			log.Fatal(err)
		}
		privKeyBytes, err := base64.StdEncoding.DecodeString(privKey)
		if err != nil {
			log.Fatal(err)
		}
		privKeyParsed, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		return privKeyParsed
	}
	return nil
}

func (db *DB) createPrivateKey() {
	rows, err := db.db.Query("SELECT COUNT(*) FROM linse.service_info")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		var count int
		err = rows.Scan(&count)
		if err != nil {
			log.Fatal(err)
		}
		if count > 0 {
			return
		}
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyStr := base64.StdEncoding.EncodeToString(privKeyBytes)

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pubKeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)
	_, err = db.db.Exec("INSERT INTO linse.service_info (privKey, pubKey) VALUES (?, ?)", privKeyStr, pubKeyStr)
	if err != nil {
		log.Fatal(err)
	}
}

func generateLicense() string {
	license := ""
	for i := 0; i < 20; i++ {
		nBig, err := rand.Int(rand.Reader, big.NewInt(26))
		if err != nil {
			log.Fatal(err)
		}
		n := nBig.Int64()
		license += string(rune(n + 65))
		if i == 4 || i == 9 || i == 14 {
			license += "-"
		}
	}
	return license
}

/*func main() {
	db := DB{}
	db.init()
	defer db.Close()

	db.CreateDB()
	db.CreateTables()

	//licence := db.addLicense("shop_bot", "3333333", 1)
	//fmt.Print(licence)
}*/
