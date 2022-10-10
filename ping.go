package ping

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

func DoPing() {
	conn, err := net.DialIP("ip:icmp", localAddr, &net.IPAddr{IP: net.IPv4(142, 250, 207, 4)})
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

	icmpPacket := peelIPHeader(icmpPacketWithIPHeader)
	icmpPkt := parseICMPPacket(icmpPacket)

	// TODO validate checksum
	fmt.Printf("received. Type: %x, Code: %x: Checksum: %x, Identifier: %x, SequenceNumber: %x, Data: %x", icmpPkt.Type, icmpPkt.Code, icmpPkt.Checksum, icmpPkt.Identifier, icmpPkt.SequenceNumber, icmpPkt.Data)
}

// TODO: dynamic localhost ipAddr
//var localAddr = &net.IPAddr{IP: net.IPv4(192, 168, 0, 150)}
var localAddr = &net.IPAddr{IP: net.IPv4(172, 20, 10, 4)}

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

type PingPacket ICMPPacket

func NewPingICMPPacket() PingPacket {
	pp := PingPacket{
		Type:           []byte{0x08},
		Code:           []byte{0x00},
		Checksum:       []byte{0x00, 0x00},
		Identifier:     []byte{0x00, 0x00},
		SequenceNumber: []byte{0x00, 0x00},
		Data:           []byte{},
	}

	pb := pp.Marshal()
	pp.Checksum = checksum(pb)
	return pp
}

func (p *PingPacket) Marshal() []byte {
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
