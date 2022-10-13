//go:build detectors
// +build detectors

package privateipaddress

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestPrivateIPAddress_FromChunk(t *testing.T) {
	
}

func BenchmarkFromData(benchmark *testing.B) {
	
}
