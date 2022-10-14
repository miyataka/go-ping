package ping

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
)

func DoPing(IPv4OrHostname string) {
	localIP := getLocalIP()
	if localIP == nil {
		log.Fatal("cannot find local ip")
	}

	ipv4 := net.ParseIP(IPv4OrHostname)
	if ipv4 == nil { // IPv4OrHostname is hostname
		addrs, err := net.LookupHost(IPv4OrHostname)
		if err != nil {
			log.Fatal(err)
		}
		if len(addrs) == 0 {
			log.Fatal(fmt.Sprintf("cannot resolve hostname: %s", IPv4OrHostname))
		}
		ipv4 = net.ParseIP(addrs[0])
	}

	conn, err := net.DialIP("ip:icmp", &net.IPAddr{IP: localIP}, &net.IPAddr{IP: ipv4.To4()})
	if err != nil {
		log.Fatal(err)
	}

	p := NewPingICMPPacket()
	b, _ := Marshal(p)
	n, err := conn.Write(b)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("success %d bytes write\n", n)

	buf := make([]byte, 80)
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	ipv4Bytes := buf[:n]
	_, body, err := parseIPv4Packet(ipv4Bytes)
	if err != nil {
		log.Fatal(err)
	}
	icmpPacket := parseICMPPacket(body)
	fmt.Printf("success %d bytes read and icmp packet size is %d\n", n, len(body))

	if validateChecksum(icmpPacket) {
		fmt.Printf("received. Type: %x, Code: %x: Checksum: %x, Identifier: %x, SequenceNumber: %x, Data: %x",
			icmpPacket.Type, icmpPacket.Code, icmpPacket.Checksum, icmpPacket.Identifier, icmpPacket.SequenceNumber, icmpPacket.Data)
	} else {
		fmt.Println("received but invalid icmp response.")
	}
}

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

var fixedPingData = []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}

func NewPingICMPPacket() ICMPPacket {
	pp := ICMPPacket{
		Type:           []byte{0x08},
		Code:           []byte{0x00},
		Checksum:       []byte{0x00, 0x00},
		Identifier:     []byte{0x00, 0x00},
		SequenceNumber: []byte{0x00, 0x00},
		Data:           fixedPingData,
	}

	iPkt := ICMPPacket(pp)
	pb, _ := Marshal(iPkt)
	pp.Checksum = checksum(pb)
	return pp
}

// Marshal signature is same "encoding/json" package Marshal
func Marshal(p any) ([]byte, error) {
	switch v := p.(type) {
	case ICMPPacket:
		var b []byte
		b = append(b, v.Type...)
		b = append(b, v.Code...)
		b = append(b, v.Checksum...)
		b = append(b, v.Identifier...)
		b = append(b, v.SequenceNumber...)
		b = append(b, v.Data...)
		return b, nil
	default:
		return nil, errors.New("its type cannot handle")
	}
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
	val := sum + (sum >> 16) ^ 0xffff
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, uint16(val))
	return cs
}

// IPv4Packet is IP version 4 header struct
type IPv4Packet struct {
	VersionAndHeaderLength []byte // version(4bit), headerLength(4bit)
	DSCPAndECN             []byte // dscp(6bit), ecn(2bit)
	TotalLength            []byte // 16bit
	Identification         []byte // 16bit
	FlagsAndFragmentOffset []byte // flags(3bit), fragmentOffset(13bit)
	TTL                    []byte // 8bit
	Protocol               []byte // 8bit
	Checksum               []byte // 16bit
	SrcAddress             []byte // 32bit
	DstAddress             []byte // 32bit
	Options                []byte // n bit, basically 0 bit
	Padding                []byte // min(32-n, 0) bit, basically 0 bit
}

func parseIPv4Packet(b []byte) (IPv4Packet, []byte, error) {
	ipp := IPv4Packet{
		VersionAndHeaderLength: b[0:1],
		DSCPAndECN:             b[1:2],
		TotalLength:            b[2:4],
		Identification:         b[4:6],
		FlagsAndFragmentOffset: b[6:8],
		TTL:                    b[8:9],
		Protocol:               b[9:10],
		Checksum:               b[10:12],
		SrcAddress:             b[12:16],
		DstAddress:             b[16:20],
	}
	hl := b[0] << 4 >> 4 // bit-shiftで右4bitだけ残す
	if hl == 5 {
		return ipp, b[20:], nil
	} else if hl > 5 {
		return IPv4Packet{}, nil, errors.New("IPv4 option-header cannot handle")
	} else {
		return IPv4Packet{}, nil, errors.New("invalid header length")
	}
}

func validateChecksum(packet ICMPPacket) bool {
	cs := packet.Checksum
	p := ICMPPacket{
		Type:           packet.Type,
		Code:           packet.Code,
		Checksum:       []byte{0x00, 0x00},
		Identifier:     packet.Identifier,
		SequenceNumber: packet.SequenceNumber,
		Data:           packet.Data,
	}
	b, _ := Marshal(p)
	cs2 := checksum(b)
	return cs[0] == cs2[0] && cs[1] == cs2[1]
}

func getLocalIP() net.IP {
	intf, err := net.InterfaceByName("en0")
	if err != nil {
		log.Fatal(err)
	}
	addrs, err := intf.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	for _, ad := range addrs {
		ipnet, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			return ipnet.IP
		}
	}
	return nil
}
