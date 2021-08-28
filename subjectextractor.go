package obbsubjectextractor

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

var oidNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.6":                    "C",
	"2.5.4.9":                    "STREET",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
	"2.5.4.15":                   "businessCategory",
	"1.3.6.1.4.1.311.60.2.1.3":   "jurisdictionCountryName",
	"2.5.4.5":                    "serialNumber",
}

// ExtractSubject Returns the subject DN of certificate in accordance to Brazilian Security specs <https://openbanking-brasil.github.io/specs-seguranca>
func ExtractSubject(cert *x509.Certificate) (string, error) {
	lenSP := len(cert.Subject.Names)
	subjectParts := make([]string, lenSP)
	for i, n := range cert.Subject.Names {
		name, found := oidNames[n.Type.String()]
		var s string
		if found {
			valueString := fmt.Sprint(n.Value)
			escaped := make([]rune, 0, len(valueString))
			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}
			s = name + "=" + string(escaped)
		} else {
			name = n.Type.String()
			v, err := asn1.Marshal(n.Value)

			if err != nil {
				return "", err
			}

			valueString := "#" + hex.EncodeToString(v)
			s = name + "=" + valueString
		}

		subjectParts[lenSP-i-1] = s
	}
	subject := strings.Join(subjectParts, ",")
	return subject, nil
}
