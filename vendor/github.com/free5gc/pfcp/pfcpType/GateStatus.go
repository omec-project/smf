package pfcpType

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	GateOpen uint8 = iota
	GateClose
)

type GateStatus struct {
	ULGate uint8 // 0x00001100
	DLGate uint8 // 0x00000011
}

func (g *GateStatus) MarshalBinary() ([]byte, error) {
	var buf = &bytes.Buffer{}

	if g.ULGate > 1 {
		return nil, fmt.Errorf("UL Gate shall be 0 or 1")
	}

	if g.DLGate > 1 {
		return nil, fmt.Errorf("DL Gate shall be 0 or 1")
	}

	if err := buf.WriteByte(g.ULGate<<2 | g.DLGate); err != nil {
		return nil, fmt.Errorf("marshal UL & DL Gate fail: " + err.Error())
	}

	return buf.Bytes(), nil
}

func (g *GateStatus) UnmarshalBinary(data []byte) error {
	var buf = bytes.NewBuffer(data)
	var tmpByte byte

	if err := binary.Read(buf, binary.BigEndian, &tmpByte); err != nil {
		return fmt.Errorf("unmarshal UL & DL Gate fail: " + err.Error())
	}

	g.ULGate = (tmpByte >> 2) & 0x3
	g.DLGate = tmpByte & 0x3

	return nil
}
