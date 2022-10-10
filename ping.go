package ping

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

func DoPing(IPv4String string) {
	// TODO accept hostname
	rAddr := net.ParseIP(IPv4String).To4()
	conn, err := net.DialIP("ip:icmp", localAddr, &net.IPAddr{IP: rAddr})
	if err != nil {
		log.Fatal(err)
	}
	packet := NewPingICMPPacket()

	n, err := conn.Write(packet.Marshal())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("success %d bytes write\n", n)
	buf := make([]byte, 80)
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("success %d bytes read\n", n)
	icmpPacketWithIPHeader := buf[:n+1]
	// TODO parse as IP-packet, not peel
	icmpPacketBytes := peelIPHeader(icmpPacketWithIPHeader)
	icmpPacket := parseICMPPacket(icmpPacketBytes)

	if validateChecksum(icmpPacket) {
		fmt.Printf("received. Type: %x, Code: %x: Checksum: %x, Identifier: %x, SequenceNumber: %x, Data: %x",
			icmpPacket.Type, icmpPacket.Code, icmpPacket.Checksum, icmpPacket.Identifier, icmpPacket.SequenceNumber, icmpPacket.Data)
	} else {
		fmt.Println("received but invalid icmp response.")
	}
}

// TODO: dynamic localhost ipAddr
var localAddr = &net.IPAddr{IP: net.IPv4(192, 168, 0, 150)}

type ICMPPacket struct {
	Type           []byte
	Code           []byte
	Checksum       []byte
	Identifier     []byte
	SequenceNumber []byte
	Data           []byte
}

func parseICMPPacket(b []byte) ICMPPacket {
	return ICMPPacket{
		Type:           b[0:1],
		Code:           b[1:2],
		Checksum:       b[2:4],
		Identifier:     b[4:6],
		SequenceNumber: b[6:8],
		Data:           b[8:],
	}
}

func NewPingICMPPacket() ICMPPacket {
	pp := ICMPPacket{
		Type:           []byte{0x08},
		Code:           []byte{0x00},
		Checksum:       []byte{0x00, 0x00},
		Identifier:     []byte{0x00, 0x00},
		SequenceNumber: []byte{0x00, 0x00},
		Data:           []byte{},
	}

	iPkt := ICMPPacket(pp)
	pb := iPkt.Marshal()
	pp.Checksum = checksum(pb)
	return pp
}

func (p *ICMPPacket) Marshal() []byte {
	var b []byte
	b = append(b, p.Type...)
	b = append(b, p.Code...)
	b = append(b, p.Checksum...)
	b = append(b, p.Identifier...)
	b = append(b, p.SequenceNumber...)
	b = append(b, p.Data...)
	return b
}

// マスタリングTCP/IP 第6版 p180
// 16bit(2octet)単位で1の補数の和を求めて，さらに求まった値の1の補数を計算する
func checksum(b []byte) []byte {
	var sum uint
	for i := 0; i < len(b); i++ {
		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(b[i:]))
		}
	}
	val := sum ^ 0xffff
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, uint16(val))
	return cs
}

func peelIPHeader(b []byte) []byte {
	// IP packetのheaderは固定の20byte + optionである.
	// Optionヘッダは通常使われないため，今回は20byte以降をICMP packetとみなす
	// FIXME: it can't parse with IP option header
	return b[20:]
}

func validateChecksum(packet ICMPPacket) bool {
	cs := packet.Checksum
	p := ICMPPacket{
		Type:           packet.Type,
		Code:           packet.Code,
		Checksum:       []byte{0x00, 0x00},
		Identifier:     packet.Identifier,
		SequenceNumber: packet.SequenceNumber,
	}
	cs2 := checksum(p.Marshal())
	return cs[0] == cs2[0] && cs[1] == cs2[1]
}
