package pfcpType

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type QFI struct {
	QFI uint8
}

func (q *QFI) MarshalBinary() ([]byte, error) {
	var buf = &bytes.Buffer{}

	if q.QFI > 63 {
		return nil, fmt.Errorf("QFI should be less equal than 63")
	}

	if err := binary.Write(buf, binary.BigEndian, &q.QFI); err != nil {
		return nil, fmt.Errorf("marshal QFI fail: " + err.Error())
	}

	return buf.Bytes(), nil
}

func (q *QFI) UnmarshalBinary(data []byte) error {
	var buf = bytes.NewBuffer(data)

	if err := binary.Read(buf, binary.BigEndian, &q.QFI); err != nil {
		return fmt.Errorf("unmarshal QFI fail: " + err.Error())
	}

	if q.QFI > 63 {
		return fmt.Errorf("QFI should be less equal than 63")
	}

	return nil
}
