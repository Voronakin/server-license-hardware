package hosthash

import (
	"encoding/json"
	"log/slog"
	"os"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type Hash struct {
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"`
	HostID       string `json:"hostid"`
	CpuModelName string `json:"cpu_model_name"`
	Memory       uint64 `json:"memory"`
	DiskSpace    uint64 `json:"disk_space"`
	MAC          string `json:"mac"`
}

func GenHash() string {
	hd, err := getHardwareData()
	if err != nil {
		slog.Error("Failed to determine machine identification data for hash generation", err)
		os.Exit(1)
	}
	hash, err := json.Marshal(hd)
	if err != nil {
		slog.Error("Failed to convert machine identification data to JSON for hash generation", err)
		os.Exit(1)
	}

	return string(hash)
}

func getHardwareData() (*Hash, error) {
	// memory
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// disk - start from "/" mount point for Linux
	diskStat, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	// cpu - get CPU number of cores and speed
	cpuStat, err := cpu.Info()
	if err != nil {
		return nil, err
	}

	// host or machine kernel, uptime, platform Info
	hostStat, err := host.Info()
	if err != nil {
		return nil, err
	}

	// get interfaces MAC/hardware address
	interfStat, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	mac := ""
	if len(interfStat) > 0 {
		mac = interfStat[0].HardwareAddr
	}

	return &Hash{
		Hostname:     hostStat.Hostname,
		Platform:     hostStat.Platform,
		HostID:       hostStat.HostID,
		CpuModelName: cpuStat[0].ModelName,
		Memory:       vmStat.Total,
		DiskSpace:    diskStat.Total,
		MAC:          mac,
	}, nil
}
