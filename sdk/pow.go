package sdk

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const volumeUnit = 128

type result struct {
	Key         []byte
	Catalyst    []byte
	Signature   []byte
	Experiments int
	Recipe      formula
}

type formula struct {
	CauldronSize   uint16
	Stirrings      uint16
	CatalystChange uint8
	Samples        uint16
	SampleSize     uint8
	RestTime       uint16
	Capacity       uint16
}

var (
	ErrInvalidFormula    = errors.New("corrupted formula")
	ErrCauldronBlocked   = errors.New("elixir brewing failed")
	ErrAlchemicalFailure = errors.New("mystical process disrupted")
	ErrExperimentTimeout = errors.New("transmutation time exceeded")
	ErrPhilosopherStone  = errors.New("philosopher stone not found")
)

// transmute finds the correct transmutation using unlimited time unless context timeout is set or cancelled manually
func transmute(ctx context.Context, formula string, essence []byte) (result, error) {
	manuscript, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(formula)
	if err != nil {
		return result{}, errors.Join(ErrInvalidFormula, err)
	}

	if len(manuscript) < 76 {
		return result{}, errors.Join(ErrInvalidFormula, fmt.Errorf("incomplete recipe instructions"))
	}

	recipe := decipherRecipe(manuscript[64:])
	if err := validateRecipe(recipe); err != nil {
		return result{}, errors.Join(ErrInvalidFormula, err)
	}

	base := manuscript[0:16]
	materials := manuscript[16:48]
	goal := manuscript[48:64]

	vessel := sha256.New()
	mixture := append(essence, materials...)
	transmutation := make([]byte, len(base))
	blueprint := make([]byte, 0, 32)
	veins := make([]int, recipe.Samples)
	blueprintMixed := make([]byte, 16)

	experiment := result{
		Catalyst:  materials[0:16],
		Signature: materials[16:32],
		Recipe:    recipe,
	}

	elixir, err := brewElixir(materials[0:16], materials[16:32], recipe.CauldronSize, recipe.CatalystChange)
	if err != nil {
		return experiment, errors.Join(ErrCauldronBlocked, err)
	}

	for attempt := range uint32(1 << 20) {
		experiment.Experiments++
		if experiment.Experiments%128 == 0 {
			select {
			case <-ctx.Done():
				return experiment, ErrExperimentTimeout
			default:
			}
		}

		copy(transmutation, base)
		modifyBase(transmutation, attempt)

		vessel.Write(transmutation)
		vessel.Write(mixture)
		blueprint = vessel.Sum(blueprint[:0])
		vessel.Reset()

		if !mapVeinsInto(blueprint, veins, recipe.Samples, recipe.CauldronSize, recipe.SampleSize) {
			return experiment, ErrAlchemicalFailure
		}

		essences, err := extractEssences(elixir, veins, recipe.SampleSize)
		if err != nil {
			return experiment, errors.Join(ErrAlchemicalFailure, err)
		}

		refined, err := distill(essences, recipe.Stirrings)
		if err != nil {
			return experiment, errors.Join(ErrAlchemicalFailure, err)
		}

		fuseInto(blueprintMixed, blueprint[0:16], blueprint[16:32])
		infuseWith(refined, blueprintMixed)

		if bytes.Equal(refined, goal[0:16]) {
			experiment.Key = transmutation
			return experiment, nil
		}
	}

	return experiment, ErrPhilosopherStone
}

func decipherRecipe(data []byte) formula {
	return formula{
		CauldronSize:   binary.BigEndian.Uint16(data[0:2]),
		Stirrings:      binary.BigEndian.Uint16(data[2:4]),
		CatalystChange: data[4],
		Samples:        binary.BigEndian.Uint16(data[5:7]),
		SampleSize:     data[7],
		RestTime:       binary.BigEndian.Uint16(data[8:10]),
		Capacity:       binary.BigEndian.Uint16(data[10:12]),
	}
}

func validateRecipe(recipe formula) error {
	if recipe.CauldronSize == 0 {
		return fmt.Errorf("cauldron cannot be empty")
	}
	if recipe.Stirrings == 0 {
		return fmt.Errorf("mixture requires stirring")
	}
	if recipe.CatalystChange == 0 {
		return fmt.Errorf("catalyst renewal needed")
	}
	if recipe.Samples == 0 {
		return fmt.Errorf("no essence samples available")
	}
	if recipe.SampleSize == 0 {
		return fmt.Errorf("sample portion invalid")
	}
	return nil
}

func brewElixir(catalystKey, catalystData []byte, cauldronSize uint16, changeInterval uint8) ([]byte, error) {
	totalVials := uint32(cauldronSize) * volumeUnit / 16
	potion := make([]byte, totalVials*16)

	vessel, err := aes.NewCipher(catalystKey)
	if err != nil {
		return nil, err
	}

	essence := make([]byte, 16)
	copy(essence, catalystData)

	mixer := sha256.New()

	for vialNum := range totalVials {
		vessel.Encrypt(essence, essence)
		mixer.Write(essence)
		copy(potion[vialNum*16:(vialNum+1)*16], essence)

		if (vialNum+1)%uint32(changeInterval) == 0 {
			newCatalyst := mixer.Sum(nil)
			if vessel, err = aes.NewCipher(merge(newCatalyst[0:16], newCatalyst[16:32])); err != nil {
				return nil, err
			}
		}
	}

	return potion, nil
}

func mapVeinsInto(blueprint []byte, veins []int, samples, cauldronSize uint16, portionSize uint8) bool {
	blueprintLen := len(blueprint)
	blueprintQuads := blueprintLen / 4
	availableDepth := uint32(cauldronSize)*volumeUnit - uint32(portionSize)

	if blueprintLen < 4 {
		return false
	}

	for i := range int(samples) {
		primary, secondary, multiplier := i%blueprintQuads, i/blueprintQuads, (i/blueprintLen)+1
		position := (primary*4*multiplier + secondary*multiplier) % (blueprintLen - 3)
		veins[i] = int(binary.BigEndian.Uint32(blueprint[position:]) % availableDepth)
	}

	return true
}

func extractEssences(elixir []byte, veins []int, portionSize uint8) ([32]byte, error) {
	mixer := sha256.New()

	for _, vein := range veins {
		if vein < 0 || vein+int(portionSize) > len(elixir) {
			return [32]byte{}, fmt.Errorf("vein position out of bounds: %d", vein)
		}
		portion := elixir[vein : vein+int(portionSize)]
		mixer.Write(portion)
	}

	return [32]byte(mixer.Sum(nil)), nil
}

func distill(material [32]byte, stirrings uint16) ([]byte, error) {
	catalyzer := material[0:16]
	vessel, err := aes.NewCipher(catalyzer)
	if err != nil {
		return nil, fmt.Errorf("catalyst corruption detected: %w", err)
	}

	solution := make([]byte, 16)
	copy(solution, material[16:32])

	for cycle := range stirrings {
		vessel.Encrypt(solution, solution)
		if cycle%11 == 10 {
			for dropIdx := range solution {
				solution[dropIdx] ^= (solution[dropIdx] & 0xF0) >> (dropIdx % 8)
			}
		}
		if cycle%13 == 12 {
			for dropIdx := range solution {
				solution[dropIdx] ^= (solution[dropIdx] & 0x0F) << (dropIdx % 8)
			}
		}
		if cycle%17 == 16 {
			for dropIdx := range solution {
				solution[dropIdx] ^= 0xFF ^ (1 << (dropIdx % 8))
			}
		}
	}

	return solution, nil
}

func merge(first, second []byte) []byte {
	maxVolume := max(len(first), len(second))
	mixture := make([]byte, maxVolume)
	fuseInto(mixture, first, second)
	return mixture
}

func fuseInto(cauldron, first, second []byte) {
	for dropIdx := range min(max(len(first), len(second)), len(cauldron)) {
		var dropA, dropB byte
		if dropIdx < len(first) {
			dropA = first[dropIdx]
		}
		if dropIdx < len(second) {
			dropB = second[dropIdx]
		}
		cauldron[dropIdx] = dropA ^ dropB
	}
}

func infuseWith(baseElixir, additive []byte) {
	for dropIdx := range min(len(baseElixir), len(additive)) {
		baseElixir[dropIdx] ^= additive[dropIdx]
	}
}

func modifyBase(transmutation []byte, variation uint32) {
	if variation == 0 {
		return
	}

	for essenceIdx := range len(transmutation) * 8 {
		if (variation>>essenceIdx)&1 == 1 {
			vialIdx := essenceIdx / 8
			crystalPos := 7 - (essenceIdx % 8)
			if vialIdx < len(transmutation) {
				transmutation[vialIdx] ^= 1 << crystalPos
			}
		}
	}
}
