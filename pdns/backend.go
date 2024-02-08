package main

import (
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"os"
	"slices"
	"strconv"
	"strings"
)

const (
	dbname = "localhostcert-pdns"
	NS1    = "ns1.getlocalcert.net."
	NS2    = "ns2.getlocalcert.net."
)

var TOP_DOMAINS = []string{
	"localcert.net",
	"localhostcert.net",
	"corpnet.work",
}
var TOP_DOMAINS_PSL = []string{
	"_psl.localcert.net",
	"_psl.localhostcert.net",
	"_psl.corpnet.work",
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func emitMXRecord(qname string, qtype string, ttl int, priority string, content string) {
	emitRecord(qname, qtype, ttl, priority+"\t"+content)
}

func emitRecord(qname string, qtype string, ttl int, content string) {
	var recordLine = "0\t1\t" + qname + "\tIN\t" + qtype + "\t" + strconv.Itoa(ttl) + "\t-1\t" + content
	//fmt.Println("LOG\t" + recordLine)
	fmt.Println("DATA\t" + recordLine)
}

func getParentDomain(qname string) (string, bool) {
	for _, v := range TOP_DOMAINS {
		if qname == v || strings.HasSuffix(qname, "."+v) {
			return v, true
		}
	}
	return "", false
}

func handleNSLookup(parentDomain string, qname string) {
	emitRecord(parentDomain, "NS", 3600, NS1)
	emitRecord(parentDomain, "NS", 3600, NS2)
}

func handleALookup(qname string) {
	// Only localhostcert has A records
	if strings.HasSuffix(qname, ".localhostcert.net") {
		emitRecord(qname, "A", 3600, "127.0.0.1")
	}
}

func handleMXLookup(qname string) {
	emitMXRecord(qname, "MX", 3600, "0", ".")
}

func handleSOALookup(parentDomain string, qname string) {
	emitRecord(parentDomain, "SOA", 3600, NS1+" soa-admin.robalexdev.com. 0 10800 3600 604800 3600")
}

func queryChallengeResponses(qname string) {
	// TODO: timeouts
	rows, err := db.Query(
		"SELECT name, old_challenge_response, new_challenge_response FROM domains_manageddomainname WHERE name = $1",
		qname+".",
	)
	// Error handling here ignores failures
	// Any challenge responses we failed to get will be omitted
	// ACME says the software should retry daily on failures
	if err != nil {
		fmt.Println("LOG\t" + err.Error())
		return
	}
	for rows.Next() {
		var name sql.NullString
		var a sql.NullString
		var b sql.NullString
		err = rows.Scan(&name, &a, &b)
		if err != nil {
			fmt.Println("LOG\t" + err.Error())
			return
		}
		if a.Valid && a.String != "" {
			emitRecord(qname, "TXT", 60, a.String)
		}
		if b.Valid && b.String != "" {
			emitRecord(qname, "TXT", 60, b.String)
		}
	}
}

func handleTXTLookup(qname string) {
	// Top domains have TXT for PSL
	if slices.Contains(TOP_DOMAINS_PSL, qname) {
		// See: https://github.com/publicsuffix/list/pull/1798
		emitRecord(qname, "TXT", 3600, "https://github.com/publicsuffix/list/pull/1798")
	}
	// SPF - deny all
	if !strings.Contains(qname, "_") {
		emitRecord(qname, "TXT", 3600, "v=spf1 -all")
	}
	if strings.HasPrefix(qname, "_dmarc.") {
		// reject, reject subdomain, strict dkim and spf
		emitRecord(qname, "TXT", 3600, "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s")
	}
	if strings.Contains(qname, "._domainkey.") {
		emitRecord(qname, "TXT", 3600, "v=DKIM1; p=")
	}
	queryChallengeResponses(qname)
}

func handleLookup(parentDomain string, qname string, qtype string) {
	// https://doc.powerdns.com/authoritative/backends/pipe.html#answers
	if qtype == "A" || qtype == "ANY" {
		handleALookup(qname)
	}
	if qtype == "NS" || qtype == "ANY" {
		handleNSLookup(parentDomain, qname)
	}
	if qtype == "TXT" || qtype == "ANY" {
		handleTXTLookup(qname)
	}
	// TODO: consider skipping this for subdomains?
	if qtype == "MX" || qtype == "ANY" {
		handleMXLookup(qname)
	}
	if qtype == "SOA" || qtype == "ANY" {
		handleSOALookup(parentDomain, qname)
	}
}

func handleQuestion(qname string, qclass string, qtype string) {
	var parentDomain, isAllowedDomain = getParentDomain(qname)
	if qclass == "IN" && isAllowedDomain {
		handleLookup(parentDomain, qname, qtype)
	}
	fmt.Println("END")
}

var db *sql.DB

func main() {
	psqlconn := fmt.Sprintf(
		"host=db port=5432 user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("LOCALCERT_WEB_DB_NAME"),
	)
	var connected = false

	var reader = bufio.NewReader(os.Stdin)
	for {
		message, err := reader.ReadString('\n')
		CheckError(err)
		message = strings.TrimSpace(message)

		parts := strings.Split(message, "\t")
		if len(parts) < 2 {
			fmt.Println("LOG\tPDNS sent short line: ", parts)
			fmt.Println("FAIL")
			break
		}

		if parts[0] == "HELO" {
			if parts[1] != "3" {
				fmt.Println("LOG\tWrong version: ", parts[1])
				fmt.Println("FAIL")
				break
			}
			fmt.Println("OK\tlocalcert-pipe-backend")
			continue
		}

		//fmt.Println("LOG\tDEBUG:", message)

		if len(parts) != 8 {
			// Make sure ABI version is 3
			fmt.Println("LOG\tPDNS sent invalid line: ", parts)
			fmt.Println("FAIL")
			break
		}

		// Delay connecting until needed
		// This helps Django setup the test database in the test env
		if !connected {
			db, err = sql.Open("postgres", psqlconn)
			CheckError(err)
			defer db.Close()
			err = db.Ping()
			CheckError(err)
		}

		q := parts[0]
		qname := parts[1]
		qclass := parts[2]
		qtype := parts[3]
		if q != "Q" {
			fmt.Println("FAIL")
		} else {
			handleQuestion(qname, qclass, qtype)
		}
	}
}
