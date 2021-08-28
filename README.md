# OpenBanking Brasil Subject DN extractor

Using this lib you will be capable of extract the subject DN following RFC 4514 definitions,
with aditional translation of OIDs to names specified by the 
[OpenBanking Brasil security specs](https://openbanking-brasil.github.io/specs-seguranca).

The implementation follows the rules at **August 26, 2021**.

## History

| Version | Date (aprox.) of spec |
| -- | -- |
| initial | **August 26, 2021** |

## Installation

### Lib

```bash
go get github.com/esachser/obbsubjectextractor
```

### Command

```bash
go get github.com/esachser/obbsubjectextractor/cmd/obbsubextractor
```

## Usage - lib

Example from the cmd folder;

```go
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
	filename := os.Args[1]
	pemFile, _ := os.ReadFile(filename)
	pemBlock, _ := pem.Decode(pemFile)
	cert, _ := x509.ParseCertificate(pemBlock.Bytes)

	subjectDN, err := obbsubjectextractor.ExtractSubject(cert)

	fmt.Println(subjectDN, err)
}
```

## Usage - command

```bash
obbsubextractor <path-to-pem>
```