package system

import (
	"os"
)

func getHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		return ""
	}

	return hn
}
