package sshconfig

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
)

func ConfigForHost(h string) (map[string][]string, error) {
	c := exec.Command("ssh", "-G", h)
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	outMap := make(map[string][]string)
	if err := NewDecoder(out).Decode(&outMap); err != nil {
		return nil, err
	}
	return outMap, c.Wait()
}

type Decoder struct {
	scanner *bufio.Scanner
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		scanner: bufio.NewScanner(r),
	}
}

func (p *Decoder) Decode(out *map[string][]string) error {
	for p.scanner.Scan() {
		line := p.scanner.Bytes()
		before, after, found := bytes.Cut(line, []byte(" "))
		if !found {
			continue
		}
		key := string(bytes.TrimSpace(before))
		value := string(bytes.TrimSpace(after))
		(*out)[key] = append((*out)[key], value)
	}
	return p.scanner.Err()
}
