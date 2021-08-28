package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/esachser/obbsubjectextractor"
)

func main() {
	flag.Usage = func() {
		cmdName := filepath.Base(os.Args[0])
		fmt.Printf("Usage:\n%s <path-of-pem>\n", cmdName)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	filename := flag.Arg(0)
	pemFile, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading file %s: %v", filename, err)
		os.Exit(1)
	}

	pemBlock, _ := pem.Decode(pemFile)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		fmt.Printf("Error parsing certificate: %v", err)
		os.Exit(1)
	}

	subjectDN, err := obbsubjectextractor.ExtractSubject(cert)
	if err != nil {
		fmt.Printf("Error parsing subject DN: %v", err)
		os.Exit(1)
	}

	fmt.Println(subjectDN)
}
