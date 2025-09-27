package anonymizer

import (
	"errors"
	"io"
)

const (
	chunkSize   = 8 * 1024 // 8KB - chunk size for reading from source
	overlapSize = 1024     // 1KB - overlap size for pattern matching across chunk boundaries
)

type wrapper struct {
	buffer   []byte    // buffer with processed data ready for output
	replacer Replacer  // replacer for masking sensitive data
	reader   io.Reader // source data reader
}

func newWrapper(reader io.Reader, replacer Replacer) io.Reader {
	return &wrapper{
		buffer:   make([]byte, 0, chunkSize),
		replacer: replacer,
		reader:   reader,
	}
}

func (w *wrapper) Read(p []byte) (n int, err error) {
	// if buffer has enough data for output + preserving overlap area
	if len(w.buffer) >= len(p)+overlapSize {
		n = copy(p, w.buffer)

		// shift buffer left, keeping last overlapSize bytes for next read
		// this ensures pattern matching across chunk boundaries
		copy(w.buffer, w.buffer[n:])
		w.buffer = w.buffer[:len(w.buffer)-n]

		return n, nil
	}

	// read additional data from source
	chunk := make([]byte, max(len(p)+overlapSize-len(w.buffer), chunkSize))
	for len(w.buffer) < len(p)+overlapSize {
		n, err = w.reader.Read(chunk)
		if n != 0 {
			// append new data to existing buffer
			w.buffer = append(w.buffer, chunk[:n]...)
			// apply replacer to entire buffer - necessary for pattern matching
			// at the junction of old data (from overlap) and new data
			w.buffer = w.replacer.ReplaceBytes(w.buffer)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if len(w.buffer) == 0 {
		return 0, io.EOF
	}

	// return data to user, keeping overlap area in buffer
	n = copy(p, w.buffer)
	copy(w.buffer, w.buffer[n:])
	w.buffer = w.buffer[:len(w.buffer)-n]

	return n, nil
}
