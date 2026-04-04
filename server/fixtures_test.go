package server

import (
	"encoding/base64"
	"testing"
)

var keyPackageFixtures = map[int64]string{
	501: "AAEAAkBBBBoSujDDF1qzYBAnD2jJ2hecTzbOleqEGvvlnPPjJMlb/FMXz9LmD7g4xEeot6IC8N74fhfpN2yGdAPK45esd2tAQQSYZLJhQdGPOfVUtEycQjVRAoq25NBxzaWtqngwkhEthAsFKpIGDX6DAvVS2VUj0O7GtEvuDoMiHcM4YmIRvZfgQEEEQWD9v0QUlBKHzjrNhqX5JduWo7BvOS74KMGD5lCdfH7BYhDQxZum4F2qPO2CTUUAl2b/EOCcdaVZ/lM16RsVpgABCAAAAAAAAAH1AgABAgACAAACAAEBAAAAAAAAAAD//////////wBARzBFAiEA6BtADgVSJ3kr/LwXt4fFVZcBqabPSfqmnA4JqWQz+E0CICnwze3Cserp1dEYe8awDnfTJjqzQeaJlFNJhPJe2qWfAEBHMEUCIQCL2i+ux9W9mrV2KHYvQrf6iFu1sEGi2cf2iqKSf634tQIgNeLXtd1a+szYhtWJXTRTcd+hBxWLAOqn03r9OY4WA4A=",
	502: "AAEAAkBBBDMqRkt2euRV4MrR7y0sWgQNqDfk3NLcK9O/ukaDOkykA1xeWp0r23XQutI9Usy4etMYk/uWWWuRX67nrh6nZPRAQQR3Uln1qePIdu6H4/BhHY1YZAiEdTyKWr0FjM92kjDinkuxemPStmZL5j/qTvd0U+KHlFNWF6rymTCuDt+4n9HrQEEEk7fWAbDxho33M5YHDfzMtxvVInGFW+K6KrD8AJpNOmaA6i9i8TjP6aqNs2v8XQzkVKpAds4Rsbk1rgOR2HXvSAABCAAAAAAAAAH2AgABAgACAAACAAEBAAAAAAAAAAD//////////wBARzBFAiAjcpoWuZiQoVWGNmUVc9thxuNIUzsd5l7QkY9QbRf+KQIhAKAY6Cgv5ACUZ4Mu2ofgsnYVR8KKmkdCgybIXuzTBILYAEBGMEQCIE/2omCFfGN3m2xAaFLkA7bK/UYpH+63jQNyVOU/2remAiAy8V1jYa88NFdE2HoTFCfRDcDhcP7TzKTptfDT/PDsnw==",
}

func mustFixtureKeyPackage(t *testing.T, userID int64) []byte {
	t.Helper()

	raw, ok := keyPackageFixtures[userID]
	if !ok {
		t.Fatalf("missing fixture for user %d", userID)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode key package fixture: %v", err)
	}
	return decoded
}
