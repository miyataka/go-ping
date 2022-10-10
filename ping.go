package ping

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

func DoPing() {
	pingBytes := []byte{0xb0, 0xbe, 0x76, 0x29, 0xe5, 0x50, 0x80, 0x65, 0x7c, 0xc9, 0xb7, 0xf6, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x8c, 0x9f, 0x00, 0x00, 0x40, 0x01, 0xce, 0xcc, 0xc0, 0xa8, 0x00, 0x96, 0x8e, 0xfa, 0xcf, 0x04, 0x08, 0x00, 0xde, 0x13, 0x40, 0x70, 0x00, 0x00, 0x63, 0x42, 0xdc, 0x11, 0x00, 0x0b, 0xaf, 0x19, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	fmt.Println(pingBytes)
	conn, err := net.DialIP("ip:icmp", localAddr, &net.IPAddr{IP: net.IPv4(142, 250, 207, 4)})
	if err != nil {
		log.Fatal(err)
	}
	packet := NewPingICMPPacket()

	n, err := conn.Write(packet.Marshal())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("success %d bytes write", n)
	//buf := make([]byte, 80)
	//n, err = conn.Read(buf)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Printf("success %d bytes read", n)
	//fmt.Println(string(buf))
}

// input: remote ip
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

//
//func Ping(remoteIP string) error {
//	raddr := &net.IPAddr{IP: []byte(remoteIP)}
//	conn, err := net.DialIP("tcp", localAddr, raddr)
//	if err != nil {
//		return err
//	}
//}
//
//type IPv4Packet struct {
//	Version   []byte
//	HeaderLen []byte
//	DSCP      []byte // DSCP(6bit) and ECN(2bit)
//	TotalLen  []byte
//}
//
//func stringToHexStream(stream string) []byte {
//	splitLen := 2
//	var result []byte
//	for i := 0; i < len(stream); i += splitLen {
//		result = append(result, byte(string("0x"+stream[i:i+splitLen])))
//	}
//	return result
//}

// Internet Protocol Version 4, Src: takaAir.local (192.168.0.150), Dst: www.google.com (142.250.207.4)
//     0100 .... = Version: 4
//     .... 0101 = Header Length: 20 bytes (5)
//     Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
//         0000 00.. = Differentiated Services Codepoint: Default (0)
//         .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
//     Total Length: 84
//     Identification: 0x8c9f (35999)
//     000. .... = Flags: 0x0
//     ...0 0000 0000 0000 = Fragment Offset: 0
//     Time to Live: 64
//     Protocol: ICMP (1)
//     Header Checksum: 0xcecc [validation disabled]
//     [Header checksum status: Unverified]
//     Source Address: takaAir.local (192.168.0.150)
//     Destination Address: www.google.com (142.250.207.4)
