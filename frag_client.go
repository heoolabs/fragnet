package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	fr11, fr12 float64 = 0.3, 1.24
	fr21, fr22 float64 = 1.25, 2.30
	w1, w2     float64 = 0.35, 0.30
	ml1, ml2   float64 = 3, 26
	splim      int     = 1500
)

type furjeparams struct {
	Nonce  uint64
	Freq1  float64
	Freq2  float64
	Amp1   float64
	Amp2   float64
	Phase  float64
	Phase2 float64
}

func main() {
	flag.Float64Var(&fr11, "fr11", fr11, "frequency1 nummber1")
	flag.Float64Var(&fr12, "fr12", fr12, "frequency1 number2")
	flag.Float64Var(&fr21, "fr21", fr21, "frequency2 number1")
	flag.Float64Var(&fr22, "fr22", fr22, "frequency2 number2")
	flag.Float64Var(&w1, "w1", w1, "weight1")
	flag.Float64Var(&w2, "w2", w2, "weight2")
	flag.Float64Var(&ml1, "ml1", ml1, "minimal fragmentation")
	flag.Float64Var(&ml2, "ml2", ml2, "maximal fragmentation")
	flag.IntVar(&splim, "splim", splim, "split limit")

	flag.Parse()
	var seedbyte [32]byte
	if _, err := rand.Read(seedbyte[:]); err != nil {
		panic(err)
	}
	fp, err := furjefrag(seedbyte)
	if err != nil {
		panic(err)
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:3952")
	if err != nil {
		panic(err)
	}
	var stepCounter atomic.Uint64
	for {
		conn, err := socksListener.Accept()
		if err != nil {
			continue
		}
		shift := mrand.Uint64N(50) + 100
		go fp.handleSocksConnection(conn, stepCounter.Add(shift))
	}
}

func furjefrag(bytes [32]byte) (*furjeparams, error) {
	rawNonce := binary.BigEndian.Uint64(bytes[:8])
	rawFreq := binary.BigEndian.Uint64(bytes[8:16])
	rawPhase := binary.BigEndian.Uint64(bytes[16:24])
	rawAmp := binary.BigEndian.Uint64(bytes[24:32])
	angleFromSeed := (float64(rawAmp&0xFFFF) / 65536.0) * 2 * math.Pi
	phase := (float64(rawPhase&0xFFFF) / 65536.0) * 2 * math.Pi
	phase2 := (float64(rawPhase>>16&0xFFFF) / 65536.0) * 2 * math.Pi
	s := math.Sin(angleFromSeed)
	fs := math.Sin(float64(rawFreq&0xFFFF)/65536.0) * 2 * math.Pi
	fc := math.Cos(float64(rawFreq>>16&0xFFFF)/65536.0) * 2 * math.Pi
	w := w1 + w2*(s*s)

	fp := &furjeparams{
		Nonce:  rawNonce&0xFFFFF | 1,
		Freq1:  fr11 + fr12*fs,
		Freq2:  fr21 + fr22*fc,
		Amp1:   w,
		Amp2:   1.0 - w,
		Phase:  phase,
		Phase2: phase2,
	}

	for attempts := 0; attempts < 5; attempts++ {
		var mask [3]uint64
		unique := 0
		for step := uint64(0); step < 20; step++ {
			idx := fp.chunkSize(step) - int(ml1)
			if mask[idx>>6]&(1<<(idx&63)) == 0 {
				mask[idx>>6] |= 1 << (idx & 63)
				unique++
			}
		}
		if unique >= 12 {
			break
		}
		fp.Nonce += 2
	}

	return fp, nil
}

func (fp *furjeparams) chunkSize(step uint64) int {
	t := float64(fp.Nonce*step) / math.Pi
	wave := fp.Amp1*math.Sin(t*fp.Freq1+fp.Phase) + fp.Amp2*math.Cos(t*fp.Freq2+fp.Phase2)
	normalized := (wave + 1.0) / 2.0
	return int(math.Round(ml1 + normalized*ml2))
}

func (fp *furjeparams) handleSocksConnection(clientConn net.Conn, step uint64) {
	defer clientConn.Close()

	var buf [257]byte

	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	numMethods := int(buf[1])
	if _, err := io.ReadFull(clientConn, buf[:numMethods]); err != nil {
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil || buf[1] != 0x01 {
		return
	}
	var addrStorage [265]byte
	addrBuf := addrStorage[:0]

	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
			return
		}
		addrBuf = strconv.AppendInt(addrBuf, int64(buf[0]), 10)
		addrBuf = append(addrBuf, '.')
		addrBuf = strconv.AppendInt(addrBuf, int64(buf[1]), 10)
		addrBuf = append(addrBuf, '.')
		addrBuf = strconv.AppendInt(addrBuf, int64(buf[2]), 10)
		addrBuf = append(addrBuf, '.')
		addrBuf = strconv.AppendInt(addrBuf, int64(buf[3]), 10)

	case 0x03:
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(clientConn, buf[:domainLen]); err != nil {
			return
		}
		addrBuf = append(addrBuf, buf[:domainLen]...)

	case 0x04:
		if _, err := io.ReadFull(clientConn, buf[:16]); err != nil {
			return
		}
		addrBuf = append(addrBuf, '[')
		addrBuf = append(addrBuf, net.IP(buf[:16]).String()...)
		addrBuf = append(addrBuf, ']')

	default:
		return
	}

	if _, err := io.ReadFull(clientConn, buf[:2]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(buf[:2])
	addrBuf = append(addrBuf, ':')
	addrBuf = strconv.AppendInt(addrBuf, int64(targetPort), 10)

	remoteConn, err := net.DialTimeout("tcp", string(addrBuf), 5*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	var tlsHeader [5]byte
	if _, err := io.ReadFull(clientConn, tlsHeader[:]); err != nil {
		return
	}

	var chPayload []byte
	if tlsHeader[0] == 0x16 {
		recordLen := int(binary.BigEndian.Uint16(tlsHeader[3:5]))
		chPayload = make([]byte, 5+recordLen)
		copy(chPayload[:5], tlsHeader[:])
		if _, err := io.ReadFull(clientConn, chPayload[5:]); err != nil {
			return
		}
	} else {
		chPayload = tlsHeader[:]
	}
	if len(chPayload) < splim {
		splim = len(chPayload)
	}
	for i := 0; i < splim; {
		chSize := fp.chunkSize(step)
		step++

		end := i + chSize
		if end > splim {
			end = splim
		}
		if _, err := remoteConn.Write(chPayload[i:end]); err != nil {
			return
		}
		i = end
		time.Sleep(time.Millisecond + mrand.N(30*time.Microsecond))
	}
	if splim < len(chPayload) {
		if _, err := remoteConn.Write(chPayload[splim:]); err != nil {
			return
		}
	}
	go io.Copy(remoteConn, clientConn)
	io.Copy(clientConn, remoteConn)
}
