package pfcpType

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
)

type MBR struct {
	ULMBR uint64 // 40-bit data
	DLMBR uint64 // 40-bit data
}

func (m *MBR) MarshalBinary() (data []byte, err error) {
	var buf = &bytes.Buffer{}

	if bits.Len64(m.ULMBR) > 40 {
		return nil, fmt.Errorf("UL MBR shall not be greater than 40 bits binary integer")
	}
	if bits.Len64(m.DLMBR) > 40 {
		return nil, fmt.Errorf("DL MBR shall not be greater than 40 bits binary integer")
	}

	var gbrBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(gbrBytes, m.ULMBR)

	if err := binary.Write(buf, binary.BigEndian, gbrBytes[3:]); err != nil {
		return nil, fmt.Errorf("write ULMBR fail: %s", err)
	}

	binary.BigEndian.PutUint64(gbrBytes, m.DLMBR)

	if err := binary.Write(buf, binary.BigEndian, gbrBytes[3:]); err != nil {
		return nil, fmt.Errorf("write DLMBR fail: %s", err)
	}

	return buf.Bytes(), nil
}

func (m *MBR) UnmarshalBinary(data []byte) error {
	var buf = bytes.NewBuffer(data)

	var MBRBytes = make([]byte, 5)
	var uint64Byte = make([]byte, 8)

	if err := binary.Read(buf, binary.BigEndian, MBRBytes); err != nil {
		return fmt.Errorf("read UL MBR fail: %s", err)
	}

	copy(uint64Byte[3:], MBRBytes)
	m.ULMBR = binary.BigEndian.Uint64(uint64Byte)

	if err := binary.Read(buf, binary.BigEndian, MBRBytes); err != nil {
		return fmt.Errorf("read DL MBR fail: %s", err)
	}

	copy(uint64Byte[3:], MBRBytes)
	m.DLMBR = binary.BigEndian.Uint64(uint64Byte)

	return nil
}
