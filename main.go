package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// 定义一个结构体来保存流的信息
type Flow struct {
	StartTime time.Time // 流的开始时间
	LastSeen  time.Time // 流的最后访问时间
	PacketCnt int       // 数据包数量
	ByteCnt   int       // 字节数量
}

// 定义一个 map 来保存所有的流
var flows = make(map[string]*Flow)

func main() {
	// 打开网络接口或者 PCAP 文件进行捕获
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// 设置过滤器来只捕获 TCP/IP 数据包
	filter := "tcp and ip"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		panic(err)
	}

	// 开始捕获数据包并进行处理
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 从数据包中提取五元组信息
		srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
		dstIP := packet.NetworkLayer().NetworkFlow().Dst().String()
		srcPort := packet.TransportLayer().TransportFlow().Src().String()
		dstPort := packet.TransportLayer().TransportFlow().Dst().String()
		protocol := packet.ApplicationLayer().LayerType().String()
		fmt.Println(protocol)
		// 将五元组作为键值来查找已有的流
		key := fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
		if flow, ok := flows[key]; ok {
			// 如果存在该流，更新其到达时间、数据包数量和字节数
			flow.LastSeen = time.Now()
			flow.PacketCnt += 1
			flow.ByteCnt += len(packet.Data())
		} else {
			// 如果不存在该流，则创建新的流
			flow = &Flow{
				StartTime: time.Now(),
				LastSeen:  time.Now(),
				PacketCnt: 1,
				ByteCnt:   len(packet.Data()),
			}
			flows[key] = flow
			fmt.Printf("Flow: %s\n", key)
			fmt.Printf("  Start Time: %s\n", flow.StartTime)
			fmt.Printf("  Last Seen : %s\n", flow.LastSeen)
			fmt.Printf("  Packet Cnt: %d\n", flow.PacketCnt)
			fmt.Printf("  Byte Cnt  : %d\n", flow.ByteCnt)
		}

		// 输出流的信息
	}
}
