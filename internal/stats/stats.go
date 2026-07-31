// Package stats reads the container's real RAM and CPU usage from
// /proc and cgroup files.
//
// On Railway (and most container runtimes) the container's memory and
// CPU limits are enforced via cgroups. The /proc/meminfo file shows
// the host's memory, not the container's, so it is useless for
// displaying "how much RAM is this container using". Instead we read:
//
//   - /sys/fs/cgroup/memory.current (cgroup v2) or
//     /sys/fs/cgroup/memory/memory.usage_in_bytes (cgroup v1)
//     for the current memory usage in bytes.
//
//   - /sys/fs/cgroup/memory.max (v2) or
//     /sys/fs/cgroup/memory/memory.limit_in_bytes (v1)
//     for the memory limit (the container's RAM allocation).
//
//   - /proc/<pid>/stat for per-process CPU, aggregated across all PIDs
//     we care about (the panel itself + Xray + all Tor instances).
//
// CPU usage is computed as a percentage of one core, averaged over the
// time since the process started. This is a cumulative average, not an
// instantaneous reading, but it is good enough for a dashboard widget.
package stats

import (
        "fmt"
        "os"
        "path/filepath"
        "runtime"
        "strconv"
        "strings"
        "time"
)

// Snapshot is a point-in-time view of the container's resource usage.
type Snapshot struct {
        // MemUsedBytes is the current memory usage of the container.
        MemUsedBytes uint64 `json:"memUsedBytes"`
        // MemLimitBytes is the container's memory limit (its RAM allocation).
        // 0 means "no limit" (e.g. running outside a cgroup).
        MemLimitBytes uint64 `json:"memLimitBytes"`
        // MemPercent is MemUsedBytes / MemLimitBytes * 100, or 0 if no limit.
        MemPercent float64 `json:"memPercent"`

        // CPUPercent is the combined CPU usage of the panel + Xray + all Tor
        // instances, as a percentage of one core. 100% means one core is
        // fully saturated; 200% means two cores.
        CPUPercent float64 `json:"cpuPercent"`

        // XrayPID is the PID of the Xray process, or 0 if not running.
        XrayPID int `json:"xrayPid"`
        // XrayCPUPercent is Xray's CPU usage as a percentage of one core.
        XrayCPUPercent float64 `json:"xrayCpuPercent"`
        // XrayRSSBytes is Xray's resident set size (the RAM it actually uses).
        XrayRSSBytes uint64 `json:"xrayRssBytes"`

        // TorCount is the number of Tor instances currently running.
        TorCount int `json:"torCount"`
        // TorRSSBytes is the combined RSS of all Tor instances.
        TorRSSBytes uint64 `json:"torRssBytes"`

        // PanelRSSBytes is the panel's own RSS.
        PanelRSSBytes uint64 `json:"panelRssBytes"`

        // UptimeSeconds is how long the panel process has been running.
        UptimeSeconds uint64 `json:"uptimeSeconds"`

        // Goroutines is the number of Go goroutines currently active.
        Goroutines int `json:"goroutines"`
}

// Snapshot collects the current resource usage. It never returns an
// error: every field that cannot be read is left at its zero value, so
// the dashboard degrades gracefully on platforms where /proc or cgroups
// are not available.
func Now() Snapshot {
        s := Snapshot{
                PanelRSSBytes: ownRSS(),
                UptimeSeconds: uint64(time.Since(startTime).Seconds()),
                Goroutines:    runtime.NumGoroutine(),
        }
        s.MemUsedBytes, s.MemLimitBytes, s.MemPercent = containerMem()
        return s
}

// startTime is captured at package init so UptimeSeconds is meaningful.
var startTime = time.Now()

// containerMem reads the cgroup memory usage and limit. Tries cgroup v2
// first (modern kernels and all current container runtimes), then v1
// as a fallback.
func containerMem() (used, limit uint64, percent float64) {
        used, limit, ok := readCgroupV2Mem()
        if !ok {
                used, limit, ok = readCgroupV1Mem()
        }
        if !ok {
                return 0, 0, 0
        }
        if limit > 0 {
                percent = float64(used) / float64(limit) * 100
        }
        return used, limit, percent
}

// readCgroupV2Mem reads /sys/fs/cgroup/memory.current and memory.max.
// Returns ok=false if the files do not exist (i.e. cgroup v2 is not in use).
func readCgroupV2Mem() (used, limit uint64, ok bool) {
        usedB, err := os.ReadFile("/sys/fs/cgroup/memory.current")
        if err != nil {
                return 0, 0, false
        }
        used, _ = strconv.ParseUint(strings.TrimSpace(string(usedB)), 10, 64)

        limitB, err := os.ReadFile("/sys/fs/cgroup/memory.max")
        if err == nil {
                v := strings.TrimSpace(string(limitB))
                if v != "max" {
                        limit, _ = strconv.ParseUint(v, 10, 64)
                }
        }
        return used, limit, true
}

// readCgroupV1Mem reads /sys/fs/cgroup/memory/memory.usage_in_bytes and
// memory.limit_in_bytes (the cgroup v1 paths).
func readCgroupV1Mem() (used, limit uint64, ok bool) {
        usedB, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes")
        if err != nil {
                return 0, 0, false
        }
        used, _ = strconv.ParseUint(strings.TrimSpace(string(usedB)), 10, 64)

        limitB, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        if err == nil {
                limit, _ = strconv.ParseUint(strings.TrimSpace(string(limitB)), 10, 64)
                // A very large limit (close to 2^63) means "no limit" in cgroup v1.
                if limit > 1<<60 {
                        limit = 0
                }
        }
        return used, limit, true
}

// ownRSS reads /proc/self/status and returns the panel's own resident
// set size in bytes.
func ownRSS() uint64 {
        raw, err := os.ReadFile("/proc/self/status")
        if err != nil {
                return 0
        }
        for _, line := range strings.Split(string(raw), "\n") {
                if strings.HasPrefix(line, "VmRSS:") {
                        parts := strings.Fields(line)
                        if len(parts) >= 2 {
                                kb, _ := strconv.ParseUint(parts[1], 10, 64)
                                return kb * 1024
                        }
                }
        }
        return 0
}

// processRSS returns the RSS of the process with the given PID, in bytes.
func processRSS(pid int) uint64 {
        if pid <= 0 {
                return 0
        }
        raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
        if err != nil {
                return 0
        }
        for _, line := range strings.Split(string(raw), "\n") {
                if strings.HasPrefix(line, "VmRSS:") {
                        parts := strings.Fields(line)
                        if len(parts) >= 2 {
                                kb, _ := strconv.ParseUint(parts[1], 10, 64)
                                return kb * 1024
                        }
                }
        }
        return 0
}

// processCPU returns the CPU usage of the given PID as a percentage of
// one core, averaged over the process's lifetime.
func processCPU(pid int) float64 {
        if pid <= 0 {
                return 0
        }
        raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
        if err != nil {
                return 0
        }
        s := string(raw)
        rparen := strings.LastIndexByte(s, ')')
        if rparen < 0 {
                return 0
        }
        rest := strings.Fields(s[rparen+1:])
        if len(rest) < 20 {
                return 0
        }
        utime, _ := strconv.ParseInt(rest[11], 10, 64)
        stime, _ := strconv.ParseInt(rest[12], 10, 64)
        starttime, _ := strconv.ParseInt(rest[19], 10, 64)

        hz := float64(100)
        total := float64(utime + stime)

        uptimeBytes, err := os.ReadFile("/proc/uptime")
        if err != nil {
                return 0
        }
        uptimeParts := strings.Fields(string(uptimeBytes))
        if len(uptimeParts) < 1 {
                return 0
        }
        sysUptime, _ := strconv.ParseFloat(uptimeParts[0], 64)
        procUptime := sysUptime - float64(starttime)/hz
        if procUptime <= 0 {
                return 0
        }
        return (total / hz) / procUptime * 100
}

// FindProcesses returns the PIDs of all processes whose command line
// matches the given substring (e.g. "xray" or "tor"). Used to find the
// Xray process and all Tor instances without tracking them explicitly.
func FindProcesses(nameSubstring string) []int {
        entries, err := os.ReadDir("/proc")
        if err != nil {
                return nil
        }
        var pids []int
        for _, e := range entries {
                if !e.IsDir() {
                        continue
                }
                pid, err := strconv.Atoi(e.Name())
                if err != nil || pid <= 0 {
                        continue
                }
                cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
                if err != nil {
                        continue
                }
                // cmdline is null-separated; flatten to spaces for substring search.
                flat := strings.ReplaceAll(string(cmdline), "\x00", " ")
                if strings.Contains(flat, nameSubstring) {
                        pids = append(pids, pid)
                }
        }
        return pids
}

// DetailedSnapshot is like Snapshot but also includes per-process
// stats for Xray and Tor. The caller passes the Xray PID (from the
// xrayrun manager) so we do not have to rediscover it.
func DetailedSnapshot(xrayPID int) Snapshot {
        s := Now()

        // Xray stats.
        s.XrayPID = xrayPID
        if xrayPID > 0 {
                s.XrayCPUPercent = processCPU(xrayPID)
                s.XrayRSSBytes = processRSS(xrayPID)
        }

        // Tor stats: find all "tor" processes and sum their RSS.
        torPIDs := FindProcesses("/tor")
        // Also match the bare "tor" binary name (the cmdline is just "tor -f ...").
        if len(torPIDs) == 0 {
                torPIDs = FindProcesses("tor -f")
        }
        s.TorCount = len(torPIDs)
        var torRSS uint64
        var torCPU float64
        for _, pid := range torPIDs {
                torRSS += processRSS(pid)
                torCPU += processCPU(pid)
        }
        s.TorRSSBytes = torRSS
        // CPU percent is the sum of panel + xray + all tor.
        s.CPUPercent = processCPU(os.Getpid()) + s.XrayCPUPercent + torCPU

        return s
}

// HumanBytes formats a byte count as a human-readable string (e.g.
// "1.2 GB"). Used by the dashboard.
func HumanBytes(b uint64) string {
        const unit = 1024
        if b < unit {
                return fmt.Sprintf("%d B", b)
        }
        div, exp := uint64(unit), 0
        for n := b / unit; n >= unit; n /= unit {
                div *= unit
                exp++
        }
        return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
