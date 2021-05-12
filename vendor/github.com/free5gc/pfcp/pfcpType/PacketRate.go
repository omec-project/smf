package pfcpType

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// PacketRateTimeUnit represents the thime unit of packet rate
type PacketRateTimeUnit uint8

const (
	PacketRateTimeUnitMinute = iota
	PacketRateTimeUnit6Minutes
	PacketRateTimeUnitHours
	PacketRateTimeUnitDay
	PacketRateTimeUnitWeek
)

type PacketRate struct {
	ULPR       bool
	DLPR       bool
	ULTimeUnit PacketRateTimeUnit
	MaximumUL  uint16
	DLTimeUnit PacketRateTimeUnit
	MaximumDL  uint16
}

func (p *PacketRate) MarshalBinary() ([]byte, error) {
	var buf = &bytes.Buffer{}

	if err := buf.WriteByte(btou(p.ULPR)<<0 + btou(p.DLPR)<<1); err != nil {
		return nil, errors.New("marshal ULPR & DLPR fail: " + err.Error())
	}

	if p.ULPR {
		if err := buf.WriteByte(uint8(p.ULTimeUnit)); err != nil {
			return nil, errors.New("marshal UL Time Unit fail: " + err.Error())
		}
		if err := binary.Write(buf, binary.BigEndian, p.MaximumUL); err != nil {
			return nil, errors.New("marshal Maximum Uplink fail: " + err.Error())
		}
	}

	if p.DLPR {
		if err := buf.WriteByte(uint8(p.DLTimeUnit)); err != nil {
			return nil, errors.New("marshal DL Time Unit fail: " + err.Error())
		}
		if err := binary.Write(buf, binary.BigEndian, p.MaximumDL); err != nil {
			return nil, errors.New("marshal Maximum Downlink fail: " + err.Error())
		}
	}

	return buf.Bytes(), nil
}

func (p *PacketRate) UnmarshalBinary(data []byte) error {
	var buf = bytes.NewBuffer(data)
	var tmpByte byte

	// octet 1
	if err := binary.Read(buf, binary.BigEndian, &tmpByte); err != nil {
		return errors.New("Packet Rate flag read fail: " + err.Error())
	}
	p.ULPR = utob(tmpByte & (1 << 0))
	p.DLPR = utob(tmpByte & (1 << 1))

	if p.ULPR {
		if err := binary.Read(buf, binary.BigEndian, &tmpByte); err != nil {
			return errors.New("Packet Rate UL Time Unit read fail: " + err.Error())
		}

		if tmpByte > 4 {
			return errors.New("Packet Rate UL Time Unit should be 0 to 4")
		} else {
			p.ULTimeUnit = PacketRateTimeUnit(tmpByte)
		}

		if err := binary.Read(buf, binary.BigEndian, &p.MaximumUL); err != nil {
			return errors.New("Maximum Uplink Packet Rate read fail: " + err.Error())
		}
	}

	if p.DLPR {
		if err := binary.Read(buf, binary.BigEndian, &tmpByte); err != nil {
			return errors.New("Packet Rate DL Time Unit read fail: " + err.Error())
		}
		if tmpByte > 4 {
			return errors.New("Packet Rate DL Time Unit should be 0 to 4")
		} else {
			p.DLTimeUnit = PacketRateTimeUnit(tmpByte)
		}

		if err := binary.Read(buf, binary.BigEndian, &p.MaximumDL); err != nil {
			return errors.New("Maximum Downlink Packet Rate read fail: " + err.Error())
		}
	}

	return nil
}
