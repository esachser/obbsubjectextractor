package obbsubjectextractor

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		// This is technically not allowed in a PrintableString.
		// However, x509 certificates with wildcard strings don't
		// always use the correct string type so we permit it.
		b == '*' ||
		// This is not technically allowed either. However, not
		// only is it relatively common, but there are also a
		// handful of CA certificates that contain it. At least
		// one of which will not expire until 2027.
		b == '&'
}

func parseASN1String(tag cryptobyte_asn1.Tag, value []byte) (string, error) {
	switch tag {
	case cryptobyte_asn1.T61String:
		return string(value), nil
	case cryptobyte_asn1.PrintableString:
		for _, b := range value {
			if !isPrintable(b) {
				return "", errors.New("invalid PrintableString")
			}
		}
		return string(value), nil
	case cryptobyte_asn1.UTF8String:
		if !utf8.Valid(value) {
			return "", errors.New("invalid UTF-8 string")
		}
		return string(value), nil
	case cryptobyte_asn1.Tag(asn1.TagBMPString):
		if len(value)%2 != 0 {
			return "", errors.New("invalid BMPString")
		}

		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}

		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			s = append(s, uint16(value[0])<<8+uint16(value[1]))
			value = value[2:]
		}

		return string(utf16.Decode(s)), nil
	case cryptobyte_asn1.IA5String:
		s := string(value)
		if isIA5String(s) != nil {
			return "", errors.New("invalid IA5String")
		}
		return s, nil
	case cryptobyte_asn1.Tag(asn1.TagNumericString):
		for _, b := range value {
			if !('0' <= b && b <= '9' || b == ' ') {
				return "", errors.New("invalid NumericString")
			}
		}
		return string(value), nil
	}
	return "", fmt.Errorf("unsupported string type: %v", tag)
}

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
}

func parseName(raw cryptobyte.String) (string, error) {
	if !raw.ReadASN1(&raw, cryptobyte_asn1.SEQUENCE) {
		return "", errors.New("x509: invalid RDNSequence")
	}

	s := ""

	for !raw.Empty() {
		// var rdnSet pkix.RelativeDistinguishedNameSET
		var set cryptobyte.String
		if !raw.ReadASN1(&set, cryptobyte_asn1.SET) {
			return "", errors.New("x509: invalid RDNSequence")
		}
		for !set.Empty() {
			var atav cryptobyte.String
			if !set.ReadASN1(&atav, cryptobyte_asn1.SEQUENCE) {
				return "", errors.New("x509: invalid RDNSequence: invalid attribute")
			}
			var attr pkix.AttributeTypeAndValue
			if !atav.ReadASN1ObjectIdentifier(&attr.Type) {
				return "", errors.New("x509: invalid RDNSequence: invalid attribute type")
			}
			var rawValue cryptobyte.String
			var valueTag cryptobyte_asn1.Tag
			if !atav.ReadAnyASN1(&rawValue, &valueTag) {
				return "", errors.New("x509: invalid RDNSequence: invalid attribute value")
			}
			t := attr.Type.String()
			if name, f := oidNames[t]; f {
				valueString, err := parseASN1String(valueTag, rawValue)
				if err != nil {
					return "", fmt.Errorf("x509: invalid RDNSequence: invalid attribute value: %s", err)
				}
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
				s = name + "=" + string(escaped) + "," + s
			} else {
				bts := make([]byte, 0, len(rawValue)+2)
				builder := cryptobyte.NewBuilder(bts)
				builder.AddASN1(valueTag, func(child *cryptobyte.Builder) {
					child.AddBytes(rawValue)
				})

				bts, err := builder.Bytes()
				if err != nil {
					return "", fmt.Errorf("x509: invalid RDNSequence: error building name: %s", err)
				}
				s = t + "=#" + hex.EncodeToString(bts) + "," + s
			}
		}
	}

	if len(s) > 0 {
		s = s[:len(s)-1]
	}

	return s, nil
}

// ExtractSubject Returns the subject DN of certificate in accordance to Brazilian Security specs <https://openbanking-brasil.github.io/specs-seguranca>
func ExtractSubject(cert *x509.Certificate) (string, error) {
	s := cryptobyte.String(cert.RawSubject)
	return parseName(s)
}
