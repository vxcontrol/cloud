package system

import (
	"crypto/md5" //nolint:gosec

	"github.com/google/uuid"
)

func GetInstallationID() uuid.UUID {
	salt := "49564c1fb63a7d2dd88f20a849be41ac439c2d8d3e433b2556364d9be9ae96f4"
	id, err := getMachineID()
	if err != nil || id == "" {
		// fallback to hostname-based ID when machine ID is not available
		id = getHostname()
		if id == "" {
			// final fallback to static value to ensure stability
			id = "unknown-host"
		}
	}
	hash := md5.Sum([]byte(id + salt)) //nolint:gosec
	return uuid.NewMD5(uuid.NameSpaceURL, hash[:])
}
