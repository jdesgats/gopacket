// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
)

// UDPLite is the layer for UDP-Lite headers (rfc 3828).
type UDPLite struct {
	BaseLayer
	SrcPort, DstPort UDPLitePort
	ChecksumCoverage uint16
	Checksum         uint16
	sPort, dPort     []byte
	tcpipchecksum
}

// LayerType returns gopacket.LayerTypeUDPLite
func (u *UDPLite) LayerType() gopacket.LayerType { return LayerTypeUDPLite }

func (u *UDPLite) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data))
	}
	u.SrcPort = UDPLitePort(binary.BigEndian.Uint16(data[0:2]))
	u.sPort = data[0:2]
	u.DstPort = UDPLitePort(binary.BigEndian.Uint16(data[2:4]))
	u.dPort = data[2:4]
	u.ChecksumCoverage = binary.BigEndian.Uint16(data[4:6])
	u.Checksum = binary.BigEndian.Uint16(data[6:8])
	u.BaseLayer = BaseLayer{Contents: data[:8]}
	switch {
	case u.ChecksumCoverage >= 8:
		hlen := int(u.ChecksumCoverage)
		if hlen > len(data) {
			df.SetTruncated()
			hlen = len(data)
		}
		u.Payload = data[8:]
	case u.ChecksumCoverage == 0: // Checksum covers the entire payload
		u.Payload = data[8:]
	default:
		return fmt.Errorf("UDPLite checksum coverage illegal: %d bytes", u.ChecksumCoverage)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (u *UDPLite) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(u.SrcPort))
	binary.BigEndian.PutUint16(bytes[2:], uint16(u.DstPort))
	binary.BigEndian.PutUint16(bytes[4:], uint16(u.ChecksumCoverage))
	if opts.ComputeChecksums {
		// zero out checksum bytes
		bytes[6] = 0
		bytes[7] = 0

		// check if the checksum takes the entire payload
		buf := b.Bytes()
		length := uint32(len(buf))

		if u.ChecksumCoverage > 0 {
			buf = buf[:u.ChecksumCoverage]
		}
		csum, err := u.computeChecksum(buf, length, IPProtocolUDPLite)
		if err != nil {
			return err
		}
		u.Checksum = csum
	}
	binary.BigEndian.PutUint16(bytes[6:], u.Checksum)
	return nil
}

func (u *UDPLite) ComputeChecksum() (uint16, error) {
	buf := append(append([]byte{}, u.Contents...), u.Payload...)
	length := uint32(len(buf))
	if u.ChecksumCoverage > 0 {
		buf = buf[:u.ChecksumCoverage]
	}

	buf[6] = 0
	buf[7] = 0

	return u.computeChecksum(buf, length, IPProtocolUDPLite)
}

// NextLayerType use the destination port to select the
// right next decoder. It tries first to decode via the
// destination port, then the source port.
func (u *UDPLite) NextLayerType() gopacket.LayerType {
	if lt := u.DstPort.LayerType(); lt != gopacket.LayerTypePayload {
		return lt
	}
	return u.SrcPort.LayerType()
}

func decodeUDPLite(data []byte, p gopacket.PacketBuilder) error {
	udp := &UDPLite{}
	err := udp.DecodeFromBytes(data, p)
	p.AddLayer(udp)
	p.SetTransportLayer(udp)
	if err != nil {
		return err
	}
	return p.NextDecoder(udp.NextLayerType())
}

func (u *UDPLite) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointUDPLitePort, u.sPort, u.dPort)
}
