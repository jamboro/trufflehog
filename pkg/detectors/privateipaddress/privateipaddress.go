package privateipaddress

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	ipPat = regexp.MustCompile(`[\'\"\:]+\s?(((?!10\.10\.[0-9]{0,3}\.[0-9]{0,3}|192\.168\.[0-9]{0,3}\.|169\.254\.[0-9]{0,3}\.|1\.1\.1\.1|8\.8\.8\.8[0-9]{0,3})[0-9]{1,3}\.+){3}[0-9]{1,3})[\'\"\:]+\s?`)

)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"privateipaddress"
	}
}


// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	ipMatches := ipPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range ipMatches {
		resIDMatch := strings.TrimSpace(idMatch[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PrivateIPAddress,
			Raw:          []byte(resIDMatch),
		}
		results = append(results, s1)
		
		
	}
	return detectors.CleanResults(results), nil
}