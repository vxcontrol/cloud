package sdk

import (
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	mrand "math/rand/v2"
	"strings"
	"time"
)

type LicenseType uint8

const (
	LicenseUnknown LicenseType = iota
	LicenseExpireable
	LicensePerpetual
)

func (t LicenseType) String() string {
	switch t {
	case LicenseExpireable:
		return "expireable"
	case LicensePerpetual:
		return "perpetual"
	default:
		return "unknown"
	}
}

func (t *LicenseType) Scan(value any) error {
	switch value {
	case "expireable":
		*t = LicenseExpireable
	case "perpetual":
		*t = LicensePerpetual
	default:
		return errors.New("invalid license type")
	}

	return nil
}

var ErrInvalidLicence = errors.New("invalid license")

type LicenseInfo struct {
	Type      LicenseType // license type (expireable or perpetual)
	Flags     [7]bool     // permission flags
	ExpiredAt time.Time   // license expired at
	CreatedAt time.Time   // license created at
}

func (l *LicenseInfo) IsValid() bool {
	return ((l.Type == LicenseExpireable && !l.ExpiredAt.IsZero() && !l.IsExpired()) ||
		(l.Type == LicensePerpetual && l.ExpiredAt.IsZero())) &&
		!l.CreatedAt.IsZero() && !l.CreatedAt.After(alignDays(time.Now().UTC()))
}

func (l *LicenseInfo) IsExpired() bool {
	return l.Type == LicenseExpireable && l.ExpiredAt.Before(alignDays(time.Now().UTC()))
}

type licenseData struct {
	data      [10]byte // license data
	seed      uint16   // seed 12 bits
	baseConst uint64
	seedConst uint64
	LicenseInfo
}

const (
	constBase uint64 = 0xC5618DA3 // 32 bits
	maxDays   uint16 = 0x0FFF     // 12 bits
	mask18           = 0x3FFFF
	mask12           = 0xFFF
	mask8            = 0xFF
	mask4            = 0xF
	mask2            = 0x3
)

type constXorShiftType uint8

const (
	constXorShiftCreatedAt constXorShiftType = 0
	constXorShiftExpiredAt constXorShiftType = 12
	constXorShiftFlags     constXorShiftType = 24
)

type constXorMaskType uint64

const (
	constXorMaskCreatedAt constXorMaskType = mask12
	constXorMaskExpiredAt constXorMaskType = mask12
	constXorMaskFlags     constXorMaskType = mask8
)

var (
	emptyLicenseKey = [10]byte{}
	emptyLicenseFP  = [16]byte{}
)

var timeSince = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

var seed = [32]byte{
	0x4c, 0x7c, 0x16, 0x80, 0xb4, 0xdf, 0x5a, 0xfe,
	0x37, 0x0a, 0xb2, 0x83, 0xbe, 0x91, 0x3f, 0x44,
	0x45, 0x49, 0xb1, 0x43, 0xd0, 0xf3, 0xe5, 0xe2,
	0x13, 0xdd, 0x4d, 0x4e, 0x2c, 0xb6, 0xb3, 0x6b,
}

func decodeLicenseKey(key string) [10]byte {
	key = strings.ReplaceAll(key, "-", "")
	if len(key) != 16 {
		return emptyLicenseKey
	}

	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234679"
	indices := [16]byte{}
	for idx, char := range key {
		index := strings.IndexByte(alphabet, byte(char))
		if index == -1 {
			return emptyLicenseKey
		}

		indices[idx] = byte(index)
	}

	compact := func(indices [8]byte) []byte {
		result, value := [8]byte{}, uint64(0)
		for idx := range 8 {
			value |= uint64(indices[idx]) << (5 * idx)
		}
		binary.BigEndian.PutUint64(result[:], value)
		for idx := range 4 {
			result[7-idx], result[idx] = result[idx], result[7-idx]
		}
		return result[0:5]
	}
	compacted := [10]byte{}
	copy(compacted[0:5], compact([8]byte(indices[0:8])))
	copy(compacted[5:10], compact([8]byte(indices[8:16])))

	return [10]byte(compacted)
}

func computeLicenseKeyFP(key [10]byte) [16]byte {
	var fp [16]byte

	if key == emptyLicenseKey {
		return fp
	}

	salt := md5.Sum(key[:])
	for idx := byte(0); idx < 128 && salt[0] != idx; idx++ {
		salt = md5.Sum(salt[:])
	}
	for salt[0] > 128 {
		salt = md5.Sum(salt[:])
	}

	skey := hex.EncodeToString(salt[:])
	rkey, err := pbkdf2.Key(sha256.New, skey, salt[0:16], 100_000, 64)
	if err != nil {
		return fp
	}

	copy(fp[0:16], rkey[0:16])
	xor(fp[0:16], rkey[16:32])
	xor(fp[0:16], rkey[32:48])
	xor(fp[0:16], rkey[48:64])

	return fp
}

func IntrospectLicenseKey(key string) (*LicenseInfo, error) {
	license := licenseData{}

	if err := license.restore(decodeLicenseKey(key)); err != nil {
		return nil, err
	}

	return &license.LicenseInfo, nil
}

func (l *licenseData) restore(data [10]byte) error {
	copy(l.data[:], data[:])

	data, l.seed = extractSeed(data)
	if restored := fillChecksum(data); data != restored {
		return ErrInvalidLicence
	}

	lcg := mrand.NewChaCha8(seed)
	for range l.seed {
		l.seedConst = lcg.Uint64()
	}

	id := binary.BigEndian.Uint32(l.data[0:4])
	flags := binary.BigEndian.Uint16(l.data[4:6])
	expiredAt := binary.BigEndian.Uint16(l.data[6:8])
	createdAt := binary.BigEndian.Uint16(l.data[8:10])
	salt := extractSalt(id, flags)

	if err := l.decodeCreatedAt(salt, createdAt); err != nil {
		return err
	}

	for range encodeDays(l.CreatedAt) {
		l.baseConst = lcg.Uint64()
	}

	if err := l.decodeExpiredAt(salt, expiredAt); err != nil {
		return err
	}
	if err := l.decodeFlags(flags); err != nil {
		return err
	}

	return nil
}

func (l *licenseData) decodeCreatedAt(salt, days uint16) error {
	days &= mask12
	days ^= l.seed & mask12
	days ^= uint16(getConstXOR(0, constXorShiftCreatedAt, constXorMaskCreatedAt))
	days ^= salt
	l.CreatedAt = decodeDays(days)

	if now := alignDays(time.Now().UTC()); l.CreatedAt.After(now) {
		return ErrInvalidLicence
	}

	return nil
}

func (l *licenseData) decodeExpiredAt(salt, days uint16) error {
	days &= mask12
	days ^= uint16(getConstXOR(l.baseConst, constXorShiftExpiredAt, constXorMaskExpiredAt))
	days ^= uint16(getConstXOR(l.seedConst, constXorShiftExpiredAt, constXorMaskExpiredAt))
	days ^= salt

	if days != maxDays {
		if days < encodeDays(l.CreatedAt) {
			return ErrInvalidLicence
		}
		l.ExpiredAt = decodeDays(days)
	}

	return nil
}

func (l *licenseData) decodeFlags(flags uint16) error {
	flags &= mask8
	flags ^= uint16(getConstXOR(l.baseConst, constXorShiftFlags, constXorMaskFlags))
	flags ^= uint16(getConstXOR(l.seedConst, constXorShiftFlags, constXorMaskFlags))

	l.parseFlags(uint8(flags))

	if l.Type == LicensePerpetual && !l.ExpiredAt.IsZero() {
		return ErrInvalidLicence
	}
	if l.Type == LicenseExpireable && l.ExpiredAt.IsZero() {
		return ErrInvalidLicence
	}

	return nil
}

func (l *licenseData) parseFlags(flags uint8) {
	flags &= mask8
	if flags&(1<<0) == 1 {
		l.Type = LicenseExpireable
	} else {
		l.Type = LicensePerpetual
	}
	for idx := range 7 {
		l.Flags[idx] = flags>>(idx+1)&1 == 1
	}
}

func extractSalt(id uint32, flags uint16) uint16 {
	p0, p1 := id>>12&mask18, uint16(id&mask8)
	flags &= mask8

	var salt uint16
	salt = uint16(p1&mask2)<<10 | uint16(p0&mask2)<<8 | flags
	salt ^= uint16(p0>>2&mask4)<<8 | p1
	salt ^= uint16(p0 >> 6 & mask12)

	return salt & mask12
}

func extractSeed(data [10]byte) ([10]byte, uint16) {
	x0 := uint16(data[4]&mask4) ^ uint16(data[4]>>4&mask4)
	x1 := uint16(data[4] & mask4)
	x2 := uint16(data[4] >> 4 & mask4)
	p0 := uint16(data[8] >> 4 & mask4)
	p1 := uint16(data[6] >> 4 & mask4)
	p2 := uint16(data[2] & mask4)

	p2 ^= x2 ^ p1
	p1 ^= x1 ^ p0
	p0 ^= x0

	data[8] = byte(p0)<<4 | data[8]&mask4
	data[6] = byte(p1)<<4 | data[6]&mask4
	data[2] = byte(p2) | data[2]&(mask4<<4)

	return data, p2<<8 | p1<<4 | p0
}

func fillChecksum(data [10]byte) [10]byte {
	license := [80]byte{}
	copy(license[0:10], data[0:10])

	license[0] &= ^(byte(3) << 6)
	license[4] = license[0] ^ license[1] ^ license[2]

	crc32Hash := crc32.ChecksumIEEE(license[0:10])
	binary.BigEndian.PutUint32(license[10:14], crc32Hash)

	license[14] = license[2]&mask4 | license[4]&(mask4<<4)
	license[15] = license[6]&(mask4<<4) | license[8]>>4&mask4

	md5Hash := md5.Sum(license[0:16])
	copy(license[16:32], md5Hash[0:16])

	sha256Hash := sha256.Sum256(license[0:32])
	copy(license[32:64], sha256Hash[0:32])

	reverseData := [16]byte{
		license[15], license[14], license[13], license[12],
		license[11], license[10], license[9], license[8],
		license[7], license[6], license[5], license[4],
		license[3], license[2], license[1], license[0],
	}

	md5Hash = md5.Sum(reverseData[0:16])
	copy(license[64:80], md5Hash[0:16])

	luhnSum := uint16(0)
	for i := range len(license) {
		weight := uint16(1)
		if i%2 == 1 {
			weight = 3
		}
		luhnSum += (uint16(license[i]) * weight)
		luhnSum &= mask12
	}
	license[4] = byte(luhnSum & mask8)
	license[0] |= byte(luhnSum>>8&mask2) << 6

	return [10]byte(license[0:10])
}

func getConstXOR(lbase uint64, shift constXorShiftType, mask constXorMaskType) uint16 {
	return uint16((constBase ^ lbase) >> shift & uint64(mask))
}

func decodeDays(d uint16) time.Time {
	return timeSince.AddDate(0, 0, int(d))
}

func encodeDays(t time.Time) uint16 {
	return max(uint16(t.Sub(timeSince).Hours()/24), 0)
}

func alignDays(t time.Time) time.Time {
	td := encodeDays(t)
	at := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if encodeDays(at) == td {
		return at
	}

	for d := range maxDays {
		if at = decodeDays(d); encodeDays(at) == td {
			return at
		}
		if at = decodeDays(-d); encodeDays(at) == td {
			return at
		}
	}

	return t
}
