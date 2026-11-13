package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/gosnmp/gosnmp"
	"github.com/oschwald/geoip2-golang"
)

var (
	errSNMPNoRxCounters = errors.New("SNMP agent does not export IF-MIB RX counters (ifInOctets/ifHCInOctets)")

	cityDB    *geoip2.Reader
	asnDB     *geoip2.Reader
	cidrRegex = regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}`)
)

type Result struct {
	IP                 string   `json:"ip"`
	Port               int      `json:"port"`
	Bandwidth          float64  `json:"bandwidth_gbps"`      // realistic single-IP dstat capacity
	TotalCapacityGbps  float64  `json:"total_capacity_gbps"` // deduped hardware total
	PrimaryPathGbps    float64  `json:"primary_path_gbps"`
	PrimaryDevice      string   `json:"primary_device"`
	HasBonding         bool     `json:"has_bonding"`
	IndependentUplinks int      `json:"independent_uplinks"`
	ISP                string   `json:"isp"`
	Country            string   `json:"country"`
	HasXDP             bool     `json:"has_xdp"`
	Category           string   `json:"category"`
	Protocol           string   `json:"protocol"`
	ProtectionStatus   string   `json:"protection_status"`
	ProtectionReason   string   `json:"protection_reason"`
	CapacityNotes      []string `json:"capacity_notes,omitempty"`
}

type Job struct {
	IP   string
	Port int
}

type protEntry struct {
	status string
	reason string
	clr    color.Attribute
}

var (
	protectedMap   map[string]protEntry
	unprotectedMap map[string]protEntry
	cloudMap       map[string]protEntry
)

func init() {
	protectedMap = buildMap(color.FgRed, "PROTECTED", []struct{ k, r string }{
		// ── DDoS scrubbing / WAF / CDN (inline mitigation) ───────────────────
		{"path network", "Path Network (DDoS Scrubbed)"},
		{"path.net", "Path Network (DDoS Scrubbed)"},
		{"path network, inc", "Path Network (DDoS Scrubbed)"},
		{"voxility", "Voxility (DDoS Scrubbed)"},
		{"voxility s.r.l", "Voxility (DDoS Scrubbed)"},
		{"cosmic global", "Cosmic Global (DDoS Protected)"},
		{"cosmic communications", "Cosmic Global (DDoS Protected)"},
		{"cosmic", "Cosmic Global (DDoS Protected)"},
		{"ddos-guard", "DDoS-Guard (DDoS Scrubbed)"},
		{"ddos guard", "DDoS-Guard (DDoS Scrubbed)"},
		{"ddos-guard ltd", "DDoS-Guard (DDoS Scrubbed)"},
		{"cloudflare", "Cloudflare (DDoS Protected)"},
		{"cloudflare, inc", "Cloudflare (DDoS Protected)"},
		{"magic transit", "Cloudflare Magic Transit (DDoS Scrubbed)"},
		{"imperva", "Imperva (DDoS Protected)"},
		{"incapsula", "Incapsula/Imperva (DDoS Scrubbed)"},
		{"fastly", "Fastly (DDoS Protected)"},
		{"akamai", "Akamai/Prolexic (DDoS Protected)"},
		{"prolexic", "Akamai Prolexic (DDoS Scrubbed)"},
		{"cloudfront", "CloudFront (Edge DDoS Protected)"},
		{"limelight", "Limelight (DDoS Protected)"},
		{"stackpath", "StackPath/Edgecast (DDoS Protected)"},
		{"edgecast", "Edgecast/Edgio (DDoS Protected)"},
		{"edgio", "Edgio (DDoS Protected)"},
		{"cachefly", "CacheFly (DDoS Protected)"},
		{"bunny.net", "BunnyCDN (DDoS Protected)"},
		{"bunnycdn", "BunnyCDN (DDoS Protected)"},
		{"keycdn", "KeyCDN (DDoS Protected)"},
		{"quantcdn", "QuantCDN (DDoS Protected)"},
		{"gcore", "G-Core Labs (DDoS Scrubbed)"},
		{"g-core", "G-Core Labs (DDoS Scrubbed)"},
		{"gcore labs", "G-Core Labs (DDoS Scrubbed)"},
		{"qrator", "Qrator Labs (DDoS Scrubbed)"},
		{"qrator labs", "Qrator Labs (DDoS Scrubbed)"},
		{"nexusguard", "Nexusguard (DDoS Scrubbed)"},
		{"dosarrest", "Dosarrest (DDoS Scrubbed)"},
		{"stormwall", "StormWall (DDoS Scrubbed)"},
		{"black lotus", "Black Lotus (DDoS Scrubbed)"},
		{"blacklotus", "Black Lotus (DDoS Scrubbed)"},
		{"yewsafe", "Yewsafe (DDoS Scrubbed)"},
		{"cdn5", "CDN5 (DDoS Scrubbed)"},
		{"wangsu", "Wangsu/CDNetworks (DDoS Protected)"},
		{"cdnetworks", "CDNetworks (DDoS Protected)"},
		{"baishan", "BaishanCloud (DDoS Protected)"},
		{"zenlayer", "Zenlayer (DDoS Protected)"},
		{"sucuri", "Sucuri (DDoS Protected)"},
		{"cloudbric", "Cloudbric (DDoS Protected)"},
		{"wallarm", "Wallarm (DDoS/WAF Protected)"},
		{"signal sciences", "Signal Sciences (DDoS/WAF Protected)"},
		{"f5 networks", "F5 Silverline (DDoS Protected)"},
		{"f5 inc", "F5 Silverline (DDoS Protected)"},
		{"arbor", "Arbor/Netscout (DDoS Protected)"},
		{"arbor networks", "Arbor/Netscout (DDoS Protected)"},
		{"netscout", "Netscout/Arbor (DDoS Protected)"},
		{"netscout systems", "Netscout/Arbor (DDoS Protected)"},
		{"radware", "Radware (DDoS Scrubbed)"},
		{"radware ltd", "Radware (DDoS Scrubbed)"},
		{"link11", "Link11 (DDoS Scrubbed)"},
		{"link11 gmbh", "Link11 (DDoS Scrubbed)"},
		{"neustar", "Neustar/UltraDNS (DDoS Scrubbed)"},
		{"neustar security", "Neustar/UltraDNS (DDoS Scrubbed)"},
		{"corero", "Corero (DDoS Protected)"},
		{"combahton", "combahton (DDoS Protected)"},
		{"tempesta", "Tempesta (DDoS Protected)"},
		{"hydra communications", "Hydra Communications (DDoS Protected)"},
		{"hydra comm", "Hydra Communications (DDoS Protected)"},
		{"layer7 networks", "Layer7 Networks (DDoS Protected)"},
		{"layer7", "Layer7 Networks (DDoS Protected)"},
		{"staminus", "Staminus (DDoS Protected)"},
		{"sharktech", "Sharktech (DDoS Protected)"},
		{"x4b", "X4B (DDoS Protected)"},
		{"nforce", "NForce (DDoS Protected)"},
		{"serverius", "Serverius (DDoS Protected)"},
		{"datapacket", "Datapacket (DDoS Protected)"},
		{"data packet", "Datapacket (DDoS Protected)"},
		{"clouvider", "Clouvider (Corero DDoS Protected)"},
		{"buyvm", "BuyVM/Frantech (DDoS Filtered)"},
		{"frantech", "BuyVM/Frantech (DDoS Filtered)"},
		{"glitch servers", "Glitch Servers (Corero DDoS Protected)"},
		{"glitchservers", "Glitch Servers (Corero DDoS Protected)"},
		{"fdcs servers", "FDCS Servers (DDoS Protected)"},
		{"fdcservers", "FDCS Servers (DDoS Protected)"},
		{"reliablesite", "ReliableSite (DDoS Protected)"},
		{"phoenixnap", "PhoenixNAP (DDoS Protected)"},
		{"internap", "INAP/Internap (DDoS Protected)"},
		{"inap holdings", "INAP (DDoS Protected)"},
		{"wowrack", "Wowrack (DDoS Protected)"},
		{"redstation", "Redstation (DDoS Protected)"},
		{"steadfast", "Steadfast (DDoS Protected)"},
		{"teraswitch", "TeraSwitch (DDoS Protected)"},
		{"servermania", "ServerMania (DDoS Protected)"},
		{"knownhost", "KnownHost (DDoS Protected)"},
		{"liquid web", "Liquid Web (DDoS Protected)"},
		{"quadranet", "QuadraNet (DDoS Protected)"},
		{"hostwinds", "Hostwinds (DDoS Protected)"},
		{"psychz", "Psychz Networks (DDoS Protected)"},
		{"gsl networks", "GSL Networks (DDoS Protected)"},
		{"singlehop", "SingleHop (DDoS Protected)"},
		{"dataclub", "Dataclub (DDoS Protected)"},
		{"netrouting", "Netrouting (DDoS Protected)"},
		{"nfoservers", "NFOservers (DDoS Protected)"},
		{"g-portal", "G-Portal (DDoS Protected)"},
		{"nodecraft", "Nodecraft (DDoS Protected)"},
		// ── Additional anti-DDoS / WAAP vendors (bigger fingerprints) ────────
		{"fortiddos", "Fortinet FortiDDoS (DDoS Protected)"},
		{"fortinet", "Fortinet (DDoS/WAAP Protected)"},
		{"f5 silverline", "F5 Silverline (DDoS Protected)"},
		{"f5 distributed cloud", "F5 Distributed Cloud (DDoS Protected)"},
		{"checkpoint", "Check Point (DDoS Protected)"},
		{"check point", "Check Point (DDoS Protected)"},
		{"a10 networks", "A10 Networks (DDoS Protected)"},
		{"threatx", "ThreatX WAAP (DDoS/WAF Protected)"},
		{"arvancloud", "ArvanCloud (DDoS/WAF Protected)"},
		{"arvan cloud", "ArvanCloud (DDoS/WAF Protected)"},
		{"reblaze", "Reblaze WAAP (DDoS/WAF Protected)"},
		{"cloud armor", "Google Cloud Armor (DDoS Protected)"},
		{"aws shield", "AWS Shield (DDoS Protected)"},
		{"azure ddos", "Azure DDoS Protection (DDoS Protected)"},
		// ── OVH group (VAC always-on scrubbing) ───────────────────────────────
		{"ovh", "OVH Cloud (DDoS Protected/VAC)"},
		{"soyoustart", "OVH/SoYouStart (DDoS Protected/VAC)"},
		{"kimsufi", "OVH/Kimsufi (DDoS Protected/VAC)"},
		{"ovhcloud", "OVHcloud (DDoS Protected/VAC)"},
	})

	unprotectedMap = buildMap(color.FgGreen, "UNPROTECTED", []struct{ k, r string }{
		// ── Raw / null-route / no inline scrub — traffic hits the box ─────────
		// High-bandwidth dedicated (popular for dstat)
		{"latitude.sh", "Latitude.sh (Unprotected/Raw Pipe)"},
		{"latitude", "Latitude.sh (Unprotected/Raw Pipe)"},
		{"maxihost", "Latitude.sh/Maxihost (Unprotected/Raw Pipe)"},
		{"hetzner", "Hetzner (Unprotected/No Inline Scrub)"},
		{"hetzner online", "Hetzner (Unprotected/No Inline Scrub)"},
		{"hetzner online gmbh", "Hetzner (Unprotected/No Inline Scrub)"},
		{"leaseweb", "Leaseweb (Unprotected/Null-Route Only)"},
		{"leaseweb netherlands", "Leaseweb (Unprotected/Null-Route Only)"},
		{"leaseweb usa", "Leaseweb (Unprotected/Null-Route Only)"},
		{"yisp", "YISP (Unprotected/Raw Pipe)"},
		{"worldstream", "Worldstream (Unprotected/No Inline Scrub)"},
		{"worldstream b.v", "Worldstream (Unprotected/No Inline Scrub)"},
		{"novoserve", "NovoServe (Unprotected/Raw Pipe)"},
		{"novoserve b.v", "NovoServe (Unprotected/Raw Pipe)"},
		{"m247", "M247 (Unprotected/Standard)"},
		{"m247 ltd", "M247 (Unprotected/Standard)"},
		{"genesis adaptive", "Genesis Adaptive (Unprotected/High Bandwidth)"},
		{"aeza", "Aeza (Unprotected/No Filtering)"},
		{"pq hosting", "PQ Hosting (Unprotected)"},
		{"pq.hosting", "PQ Hosting (Unprotected)"},
		{"fornex", "Fornex (Unprotected)"},
		{"melbicom", "Melbicom (Unprotected)"},
		{"estnoc", "EstNOC (Unprotected)"},
		{"fiberstate", "Fiberstate (Unprotected)"},
		{"fiord", "Fiord (Unprotected)"},
		{"myloc", "MyLoc (Unprotected)"},
		{"neterra", "Neterra (Unprotected)"},
		{"zare", "Zare (Unprotected)"},
		{"hostkey", "HostKey (Unprotected)"},
		{"cherry servers", "Cherry Servers (Unprotected)"},
		{"cherryservers", "Cherry Servers (Unprotected)"},
		{"servers.com", "Servers.com (Unprotected)"},
		{"servers com", "Servers.com (Unprotected)"},
		{"liteserver", "LiteServer (Unprotected)"},
		{"novogara", "Novogara (Unprotected)"},
		{"quintex", "Quintex (Unprotected)"},
		{"pehost", "PEHost (Unprotected)"},
		{"terrahost", "Terrahost (Unprotected/Standard)"},
		{"datacamp", "Datacamp Limited (Unprotected/Standard)"},
		{"data camp limited", "Datacamp Limited (Unprotected/Standard)"},
		{"cdn77", "CDN77/Datacamp (Unprotected/Standard)"},
		{"edis", "EDIS (Unprotected)"},
		{"ipvolume", "IPVolume (Unprotected)"},
		{"evolink", "Evolink (Unprotected)"},
		{"pax.net", "Pax.net (Unprotected)"},
		{"paperspace", "Paperspace (Unprotected)"},
		{"selectel", "Selectel (Unprotected/No Inline Scrub)"},
		{"scaleway", "Scaleway (Unprotected/Standard)"},
		{"online.net", "Scaleway/Online.net (Unprotected)"},
		{"dedibox", "Scaleway/Dedibox (Unprotected)"},
		{"kamatera", "Kamatera (Unprotected/No Filtering)"},
		{"contabo", "Contabo (Unprotected/Null-Route Only)"},
		{"contabo gmbh", "Contabo (Unprotected/Null-Route Only)"},
		{"interserver", "Interserver (Unprotected)"},
		{"interserver inc", "Interserver (Unprotected)"},
		{"hostinger", "Hostinger (Unprotected)"},
		{"hostinger international", "Hostinger (Unprotected)"},
		{"iweb", "iWeb (Unprotected)"},
		{"netcup", "Netcup (Unprotected/Minimal Filtering)"},
		{"netcup gmbh", "Netcup (Unprotected/Minimal Filtering)"},
		{"strato", "Strato (Unprotected)"},
		{"ionos", "IONOS/1&1 (Unprotected/Standard)"},
		{"1&1", "IONOS/1&1 (Unprotected/Standard)"},
		{"oneandone", "IONOS/1&1 (Unprotected/Standard)"},
		{"ionos se", "IONOS/1&1 (Unprotected/Standard)"},
		{"dogado", "dogado (Unprotected)"},
		{"manitu", "manitu (Unprotected)"},
		{"all-inkl", "All-Inkl (Unprotected)"},
		{"webgo", "webgo (Unprotected)"},
		{"mittwald", "Mittwald (Unprotected)"},
		{"keyweb", "Keyweb (Unprotected)"},
		{"alfahosting", "Alfahosting (Unprotected)"},
		{"domainfactory", "domainfactory (Unprotected)"},
		{"fasthosts", "Fasthosts (Unprotected)"},
		{"heart internet", "Heart Internet (Unprotected)"},
		{"eurovps", "EuroVPS (Unprotected)"},
		{"vautron", "Vautron (Unprotected)"},
		{"hosteurope", "HostEurope (Unprotected/Standard)"},
		{"serverloft", "Serverloft (Unprotected)"},
		{"server4you", "server4you (Unprotected)"},
		{"timeweb", "Timeweb (Unprotected)"},
		{"reg.ru", "REG.RU (Unprotected)"},
		{"reg ru", "REG.RU (Unprotected)"},
		{"beget", "Beget (Unprotected)"},
		{"firstvds", "FirstVDS (Unprotected)"},
		{"vdsina", "VDSina (Unprotected)"},
		{"zomro", "Zomro (Unprotected)"},
		{"adminvps", "AdminVPS (Unprotected)"},
		{"delta.bg", "Delta.bg (Unprotected)"},
		{"hosting.bg", "Hosting.bg (Unprotected)"},
		{"superhosting", "SuperHosting (Unprotected)"},
		{"racknerd", "RackNerd (Unprotected/No Scrub)"},
		{"hosthatch", "HostHatch (Unprotected)"},
		{"virmach", "VirMach (Unprotected)"},
		{"nocix", "Nocix (Unprotected)"},
		{"dedipath", "DediPath (Unprotected)"},
		{"limestone networks", "Limestone Networks (Unprotected/Raw Pipe)"},
		{"joes datacenter", "Joe's Datacenter (Unprotected)"},
		{"joesdatacenter", "Joe's Datacenter (Unprotected)"},
		{"dacentec", "Dacentec (Unprotected)"},
		{"webnx", "WebNX (Unprotected)"},
		{"oneprovider", "OneProvider (Unprotected)"},
		{"hostzealot", "HostZealot (Unprotected)"},
		{"glesys", "GleSYS (Unprotected)"},
		{"gle sys", "GleSYS (Unprotected)"},
		{"servinga", "Servinga (Unprotected)"},
		{"dedistart", "Dedistart (Unprotected)"},
		{"blueservers", "BlueServers (Unprotected)"},
		{"blue servers", "BlueServers (Unprotected)"},
		{"edgeuno", "EdgeUno (Unprotected/Raw Transit)"},
		{"mevspace", "Mevspace (Unprotected)"},
		{"time4vps", "Time4VPS (Unprotected)"},
		{"hostbrr", "HostBRR (Unprotected)"},
		{"wholesaleinternet", "Wholesale Internet (Unprotected)"},
		{"wholesale internet", "Wholesale Internet (Unprotected)"},
		{"datashack", "Datashack (Unprotected)"},
		{"serverhub", "ServerHub (Unprotected)"},
		{"servercheap", "ServerCheap (Unprotected)"},
		{"serverroom", "ServerRoom (Unprotected)"},
		{"ssdnodes", "SSD Nodes (Unprotected)"},
		{"colocrossing", "ColoCrossing (Unprotected/Standard)"},
		{"alexhost", "AlexHost (Unprotected)"},
		{"flokinet", "FlokiNET (Unprotected/Minimal Scrub)"},
		{"prq", "PRQ (Unprotected/Minimal Scrub)"},
		{"1984 hosting", "1984 Hosting (Unprotected)"},
		{"orange website", "OrangeWebsite (Unprotected)"},
		{"liberty-net", "LibertyNet (Unprotected)"},
		{"offshorededicated", "OffshoreDedicated (Unprotected)"},
		{"rack911", "Rack911 (Unprotected)"},
		{"pulse servers", "Pulse Servers (Unprotected)"},
		{"serverpronto", "ServerPronto (Unprotected)"},
		{"steadyhost", "SteadyHost (Unprotected)"},
		{"hudson valley", "Hudson Valley Host (Unprotected)"},
		{"hawkhost", "HawkHost (Unprotected)"},
		{"mochahost", "MochaHost (Unprotected)"},
		{"glowhost", "GlowHost (Unprotected)"},
		{"justhosting", "JustHosting (Unprotected)"},
		{"dreamhost", "DreamHost (Unprotected/Standard)"},
		{"hostgator", "HostGator (Unprotected/Standard)"},
		{"bluehost", "Bluehost (Unprotected/Standard)"},
		{"godaddy", "GoDaddy (Unprotected/Standard)"},
		{"namecheap", "Namecheap (Unprotected/Standard)"},
		{"porkbun", "Porkbun (Unprotected/Standard)"},
		{"inmotion", "InMotion (Unprotected/Standard)"},
		{"a2 hosting", "A2 Hosting (Unprotected on Basic)"},
		{"siteground", "SiteGround (Unprotected on Basic VPS)"},
		{"greengeeks", "GreenGeeks (Unprotected/Standard)"},
		{"hostpapa", "HostPapa (Unprotected/Standard)"},
		{"transip", "TransIP (Unprotected/Standard)"},
		{"aruba", "Aruba.it (Unprotected/Standard)"},
		{"aruba s.p.a", "Aruba.it (Unprotected/Standard)"},
		{"sim-networks", "SIM-Networks (Unprotected)"},
		{"datalix", "Datalix (Unprotected)"},
		{"giga-hosting", "Giga-Hosting (Unprotected)"},
		{"hosting.de", "Hosting.de (Unprotected)"},
		{"netsons", "Netsons (Unprotected)"},
		{"seflow", "SeFlow (Unprotected)"},
		{"servergigabit", "ServerGigabit (Unprotected)"},
		{"serverdiscounter", "ServerDiscounter (Unprotected)"},
		{"serverbid", "ServerBid (Unprotected)"},
		{"servercircle", "ServerCircle (Unprotected)"},
		{"servercore", "ServerCore (Unprotected on Basic)"},
		{"serverel", "Serverel (Unprotected)"},
		{"serverfarm", "Serverfarm (Unprotected on Basic)"},
		{"serverforge", "ServerForge (Unprotected)"},
		{"servermind", "ServerMind (Unprotected)"},
		{"servernet", "ServerNet (Unprotected)"},
		{"serverpars", "ServerPars (Unprotected)"},
		{"serverplan", "ServerPlan (Unprotected)"},
		{"serverprofi", "ServerProfi (Unprotected)"},
		{"servers24", "Servers24 (Unprotected)"},
		{"servertown", "ServerTown (Unprotected)"},
		{"servervault", "ServerVault (Unprotected)"},
		{"serverwerk", "ServerWerk (Unprotected)"},
		{"serverworld", "ServerWorld (Unprotected)"},
		{"serverzone", "ServerZone (Unprotected)"},
		{"servetheworld", "ServeTheWorld (Unprotected)"},
		{"seedvps", "SeedVPS (Unprotected)"},
		{"sparknode", "SparkNode (Unprotected)"},
		{"nexusbytes", "NexusBytes (Unprotected)"},
		{"underhost", "UnderHost (Unprotected)"},
		{"ultahost", "UltaHost (Unprotected)"},
		{"ukservers", "UKServers (Unprotected)"},
		{"veesp", "Veesp (Unprotected)"},
		{"velia", "Velia (Unprotected)"},
		{"viacloud", "ViaCloud (Unprotected)"},
		{"virtualine", "Virtualine (Unprotected)"},
		{"vpsdime", "VPSDime (Unprotected)"},
		{"webtropia", "Webtropia (Unprotected)"},
		{"westhost", "WestHost (Unprotected)"},
		{"xeonbd", "XeonBD (Unprotected)"},
		{"zappiehost", "Zappie Host (Unprotected)"},
		{"znetlive", "ZNetLive (Unprotected)"},
		{"radore", "Radore (Unprotected)"},
		{"sadecehosting", "SadeceHosting (Unprotected)"},
		{"sakura internet", "Sakura Internet (Unprotected on Basic)"},
		{"xserver", "Xserver (Unprotected)"},
		{"conoha", "ConoHa (Unprotected on Basic)"},
		{"gmo internet", "GMO Internet (Unprotected on Basic)"},
		{"ru-center", "RU-CENTER (Unprotected)"},
		{"masterhost", "Masterhost (Unprotected)"},
		{"mchost", "McHost (Unprotected)"},
		{"hostland", "Hostland (Unprotected)"},
		{"hostpro", "HostPro (Unprotected)"},
		{"isbaremetal", "IsBareMetal (Unprotected/Raw Pipe)"},
		{"alphavps", "AlphaVPS (Unprotected/Optional Scrub)"},
		{"ariseserver", "AriseServer (Unprotected/Raw Pipe)"},
		{"hivelocity", "Hivelocity (Unprotected on Standard)"},
		// ── Transit/carrier signatures often seen as direct raw paths ──────────
		{"cogent communications", "Cogent (Unprotected/Transit Path)"},
		{"cogentco", "Cogent (Unprotected/Transit Path)"},
		{"lumen technologies", "Lumen/Level3 (Unprotected/Transit Path)"},
		{"level 3", "Lumen/Level3 (Unprotected/Transit Path)"},
		{"telia", "Telia Carrier (Unprotected/Transit Path)"},
		{"arelion", "Arelion/Telia Carrier (Unprotected/Transit Path)"},
		{"gtt communications", "GTT (Unprotected/Transit Path)"},
		{"zayo", "Zayo (Unprotected/Transit Path)"},
		{"ntt communications", "NTT (Unprotected/Transit Path)"},
		{"tata communications", "Tata (Unprotected/Transit Path)"},
		{"hurricane electric", "Hurricane Electric (Unprotected/Transit Path)"},
		{"he.net", "Hurricane Electric (Unprotected/Transit Path)"},
	})

	cloudMap = buildMap(color.FgYellow, "PARTIAL", []struct{ k, r string }{
		// ── Hyperscaler / cloud — standard firewall, optional or variable DDoS ─
		{"google cloud", "Google Cloud (Standard Firewall/Armor)"},
		{"google llc", "Google Cloud (Standard Firewall/Armor)"},
		{"google inc", "Google Cloud (Standard Firewall/Armor)"},
		{"google", "Google Cloud (Standard Firewall/Armor)"},
		{"amazon web services", "AWS (Standard Shield)"},
		{"amazon technologies", "AWS (Standard Shield)"},
		{"amazon.com", "AWS (Standard Shield)"},
		{"amazon", "AWS (Standard Shield)"},
		{"aws", "AWS (Standard Shield)"},
		{"microsoft azure", "Azure (Standard Firewall/DDOS)"},
		{"microsoft corporation", "Azure (Standard Firewall/DDOS)"},
		{"microsoft", "Azure (Standard Firewall/DDOS)"},
		{"azure", "Azure (Standard Firewall/DDOS)"},
		{"digitalocean", "DigitalOcean (Standard Firewall)"},
		{"digital ocean", "DigitalOcean (Standard Firewall)"},
		{"vultr", "Vultr (Standard DDoS Shield Available)"},
		{"choopa", "Vultr/Choopa (Standard DDoS Shield)"},
		{"constant company", "Vultr/Constant (Standard DDoS Shield)"},
		{"linode", "Linode/Akamai Connected Cloud (Standard Firewall)"},
		{"akamai connected", "Akamai Connected Cloud (Standard Firewall)"},
		{"alibaba cloud", "Alibaba Cloud (Standard Anti-DDoS)"},
		{"alicloud", "Alibaba Cloud (Standard Anti-DDoS)"},
		{"alibaba", "Alibaba Cloud (Standard Anti-DDoS)"},
		{"tencent cloud", "Tencent Cloud (Standard Anti-DDoS)"},
		{"tencent", "Tencent Cloud (Standard Anti-DDoS)"},
		{"oracle cloud", "Oracle Cloud (Standard Firewall)"},
		{"oracle corporation", "Oracle Cloud (Standard Firewall)"},
		{"oracle", "Oracle Cloud (Standard Firewall)"},
		{"ibm cloud", "IBM Cloud (Standard Firewall)"},
		{"softlayer", "IBM/SoftLayer (Standard Firewall)"},
		{"rackspace", "Rackspace (Standard Firewall)"},
		{"rackspace hosting", "Rackspace (Standard Firewall)"},
		{"equinix", "Equinix Metal (Standard/Optional DDoS)"},
		{"equinix metal", "Equinix Metal (Standard/Optional DDoS)"},
		{"packet.net", "Equinix Metal/Packet (Standard/Optional DDoS)"},
		{"upcloud", "UpCloud (Standard Firewall)"},
		{"upcloud ltd", "UpCloud (Standard Firewall)"},
		{"exoscale", "Exoscale (Standard Firewall)"},
		{"cloudsigma", "CloudSigma (Standard Firewall)"},
		{"brightbox", "Brightbox (Standard Firewall)"},
		{"clever cloud", "Clever Cloud (Standard Firewall)"},
		{"scalingo", "Scalingo (Standard Firewall)"},
		{"platform.sh", "Platform.sh (Standard Firewall)"},
		{"fly.io", "Fly.io (Standard Edge Firewall)"},
		{"railway", "Railway (Standard Firewall)"},
		{"render.com", "Render (Standard Firewall)"},
		{"vercel", "Vercel (Edge DDoS/Standard)"},
		{"netlify", "Netlify (Edge DDoS/Standard)"},
		{"heroku", "Heroku/Salesforce (Standard Firewall)"},
		{"salesforce", "Salesforce/Heroku (Standard Firewall)"},
		{"huawei cloud", "Huawei Cloud (Standard Anti-DDoS)"},
		{"huawei", "Huawei Cloud (Standard Anti-DDoS)"},
		{"baidu cloud", "Baidu Cloud (Standard Anti-DDoS)"},
		{"baidu", "Baidu Cloud (Standard Anti-DDoS)"},
		{"yandex cloud", "Yandex Cloud (Standard Anti-DDoS)"},
		{"yandex", "Yandex Cloud (Standard Anti-DDoS)"},
		{"ucloud", "UCloud (Standard Anti-DDoS)"},
		{"kingsoft cloud", "Kingsoft Cloud (Standard Anti-DDoS)"},
		{"jd cloud", "JD Cloud (Standard Anti-DDoS)"},
		{"jd.com", "JD Cloud (Standard Anti-DDoS)"},
		{"mail.ru cloud", "VK/Mail.ru Cloud (Standard Anti-DDoS)"},
		{"vk cloud", "VK Cloud (Standard Anti-DDoS)"},
		{"openstack", "OpenStack (Provider-Dependent Protection)"},
		{"ovh public cloud", "OVH Public Cloud (VAC Protected)"},
		{"wasabi", "Wasabi (Object Storage/Standard)"},
		{"backblaze", "Backblaze (Object Storage/Standard)"},
		{"cloudways", "Cloudways (Managed Cloud/Variable)"},
		{"kinsta", "Kinsta/GCP (Managed/Variable Protection)"},
		{"wpengine", "WP Engine (Managed/Variable Protection)"},
		{"pantheon", "Pantheon (Managed/Variable Protection)"},
		{"shopify", "Shopify (Platform/Variable Protection)"},
		{"bigcommerce", "BigCommerce (Platform/Variable Protection)"},
		{"magento cloud", "Adobe/Magento Cloud (Standard Shield)"},
		{"adobe cloud", "Adobe Cloud (Standard Shield)"},
		{"lightsail", "AWS Lightsail (Standard Shield)"},
		{"ec2", "AWS EC2 (Standard Shield)"},
		{"compute engine", "Google Compute Engine (Standard Armor)"},
	})
}

func buildMap(clr color.Attribute, status string, entries []struct{ k, r string }) map[string]protEntry {
	m := make(map[string]protEntry, len(entries))
	for _, e := range entries {
		m[e.k] = protEntry{status: status, reason: e.r, clr: clr}
	}
	return m
}

var cloudISPKeywords = []string{
	"microsoft", "msft", "azure",
	"google", "gcp", "google cloud",
	"amazon", "aws", "amazon web services",
	"alibaba", "alicloud", "alibaba cloud",
	"tencent", "tencent cloud",
	"huawei", "huawei cloud",
	"baidu", "baidu cloud",
	"oracle", "oracle cloud",
	"ibm", "softlayer", "ibm cloud",
	"digitalocean", "digital ocean",
	"vultr", "choopa", "constant company",
	"linode", "akamai connected",
	"rackspace", "equinix", "packet.net",
	"upcloud", "exoscale", "cloudsigma",
	"yandex", "yandex cloud",
	"ucloud", "kingsoft",
	"jd cloud", "jd.com",
	"mail.ru", "vk cloud",
	"openstack", "clever cloud",
	"fly.io", "railway", "render.com",
	"vercel", "netlify", "heroku",
}

var virtualPrefixes = []string{
	"lo", "veth", "cali", "docker", "br-", "tun", "vxlan",
	"flannel", "tailscale", "macvlan", "bond", "vlan", "gre",
	"geneve", "virbr", "lxc", "lxd", "cni", "cilium", "kube", "vtun",
}

var physicalPrefixes = []string{"eth", "ens", "eno", "enp", "em"}

var garbageKeywords = []string{
	"stat pid", "stat uptime", "stat cmd_get", "ssh-",
	"http/1.1", "unsolicited", "athinfod", "bad request",
}

var scannerNoiseKeywords = []string{
	"[warn] monitor:",
	"monitor: dropped",
	"packets in the last second",
	"total dropped (pcap",
	" zmap: completed",
	"hitrate:",
	"senders finished",
}

const (
	portMetrics  = 9100
	portNetdata  = 19999
	portSNMP     = 161
	portTelegraf = 9273
	portGlances  = 61208
	portCAdvisor = 8080
)

const (
	oidIfDescr         = "1.3.6.1.2.1.2.2.1.2"
	oidIfSpeed         = "1.3.6.1.2.1.2.2.1.5"
	oidIfPhysAddr      = "1.3.6.1.2.1.2.2.1.6"
	oidIfHighSpeed     = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfHCInOctets    = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCInUcastPkts = "1.3.6.1.2.1.31.1.1.1.7"
	oidIfInOctets      = "1.3.6.1.2.1.2.2.1.10"
	oidIfInUcastPkts   = "1.3.6.1.2.1.2.2.1.11"
)

var (
	netdataSpeedNameRe   = regexp.MustCompile(`^netdata_net_(?:interface_)?(?:nic_)?speed(?:_max|_kilobits_persec_average)?\{`)
	netdataLegacySpeedRe = regexp.MustCompile(`^netdata_net_([a-zA-Z0-9_.:-]+)_nic_speed_max\{`)
	netdataOperNameRe    = regexp.MustCompile(`^netdata_net_(?:interface_)?operstate\{`)
	netdataLegacyOperRe  = regexp.MustCompile(`^netdata_net_([a-zA-Z0-9_.:-]+)_operstate\{`)
	snmpCommunities      = []string{"private", "public"}
	ipInLineRegex        = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
)

type scanSources struct {
	Metrics  bool
	Netdata  bool
	SNMP     bool
	Telegraf bool
	Glances  bool
	CAdvisor bool
}

func allScanSources() scanSources {
	return scanSources{
		Metrics: true, Netdata: true, Telegraf: true, SNMP: true, Glances: true,
		CAdvisor: true,
	}
}

func (s scanSources) any() bool {
	return s.Metrics || s.Netdata || s.SNMP || s.Telegraf || s.Glances || s.CAdvisor
}

func (s scanSources) ports() []int {
	var p []int
	if s.Metrics {
		p = append(p, portMetrics)
	}
	if s.Netdata {
		p = append(p, portNetdata)
	}
	if s.Telegraf {
		p = append(p, portTelegraf)
	}
	if s.SNMP {
		p = append(p, portSNMP)
	}
	if s.Glances {
		p = append(p, portGlances)
	}
	if s.CAdvisor {
		p = append(p, portCAdvisor)
	}
	return p
}

func (s scanSources) label() string {
	var parts []string
	if s.Metrics {
		parts = append(parts, "metrics")
	}
	if s.Netdata {
		parts = append(parts, "netdata")
	}
	if s.Telegraf {
		parts = append(parts, "telegraf")
	}
	if s.SNMP {
		parts = append(parts, "snmp")
	}
	if s.Glances {
		parts = append(parts, "glances")
	}
	if s.CAdvisor {
		parts = append(parts, "cadvisor")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " · ")
}

func parseScanSources(raw string) scanSources {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || raw == "all" {
		return allScanSources()
	}
	if raw == "all7" {
		return scanSources{}
	}
	var src scanSources
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '+' || r == '|' || r == ' ' || r == ';'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch part {
		case "metrics", "metric", "node", "node_exporter", "prometheus", "9100":
			src.Metrics = true
		case "netdata", "19999":
			src.Netdata = true
		case "telegraf", "9273":
			src.Telegraf = true
		case "snmp", "161", "udp", "udp161", "udp:161", "pu:161", "u:161":
			src.SNMP = true
		case "glances", "61208":
			src.Glances = true
		case "cadvisor", "8080":
			src.CAdvisor = true
		case "all":
			return allScanSources()
		}
	}
	return src
}

func hasL4AllArg(args []string) bool {
	for _, a := range args {
		for _, part := range strings.FieldsFunc(strings.ToLower(strings.TrimSpace(a)), func(r rune) bool {
			return r == ',' || r == '+' || r == '|' || r == ';' || r == ' '
		}) {
			if part == "all" {
				return true
			}
		}
	}
	return false
}

type scanConfig struct {
	minBandwidth float64
	mode         string
	sources      scanSources
}

func isHelpArg(arg string) bool {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "-h", "--help", "help", "?":
		return true
	}
	return false
}

const appTitle = "Zyre Dstat Scanner"

// programBin returns the command users should type (derived from how this binary was invoked).
func programBin() string {
	if exe, err := os.Executable(); err == nil {
		exe = filepath.Clean(exe)
		base := filepath.Base(exe)
		if base != "" && !strings.Contains(exe, "/go-build") && !strings.HasPrefix(base, "go-build") {
			if strings.HasSuffix(base, ".go") {
				return "go run " + base
			}
			// Prefer ./binary when it lives in cwd (avoids apt 'dstat' package name clash).
			if wd, err := os.Getwd(); err == nil {
				if exe == filepath.Join(wd, base) {
					return "./" + base
				}
			}
			return base
		}
	}
	arg0 := filepath.Base(os.Args[0])
	if strings.HasSuffix(arg0, ".go") {
		return "go run " + arg0
	}
	if name := detectMainGoFile(); name != "" {
		return "go run " + name
	}
	return "go run dstat.go"
}

func detectMainGoFile() string {
	for _, name := range []string{"dstat.go", "scanner.go", "main.go"} {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	matches, _ := filepath.Glob("*.go")
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "func main()") {
			return filepath.Base(m)
		}
	}
	return ""
}

// ── Terminal UI ───────────────────────────────────────────────────────────────

const uiWidth = 78

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type termUI struct{}

func newTermUI() *termUI { return &termUI{} }

func (ui *termUI) col(clr color.Attribute, bold bool) *color.Color {
	if bold {
		return color.New(clr, color.Bold)
	}
	return color.New(clr)
}

func (ui *termUI) isTTY() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) == 0
}

func (ui *termUI) stripANSI(s string) string {
	return ansiStripRe.ReplaceAllString(s, "")
}

func (ui *termUI) padRight(s string, w int) string {
	n := len(ui.stripANSI(s))
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

func (ui *termUI) width() int {
	w := uiWidth
	if raw := strings.TrimSpace(os.Getenv("COLUMNS")); raw != "" {
		if cols, err := strconv.Atoi(raw); err == nil && cols > 0 {
			// Two leading spaces are printed before each frame line.
			w = cols - 2
		}
	}
	if w < 44 {
		w = 44
	}
	if w > uiWidth {
		w = uiWidth
	}
	return w
}

func (ui *termUI) hr(ch rune) string {
	return strings.Repeat(string(ch), ui.width()-2)
}

func (ui *termUI) boxTop(title string) {
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	titleFn := ui.col(color.FgHiWhite, true).SprintFunc()
	w := ui.width()
	title = truncateText(strings.TrimSpace(title), w-8)
	fmt.Println()
	fmt.Println("  " + accent("╭"+ui.hr('─')+"╮"))
	line := " " + titleFn(title)
	pad := w - 4 - len(ui.stripANSI(line))
	if pad < 0 {
		pad = 0
	}
	fmt.Println("  " + accent("│") + line + strings.Repeat(" ", pad) + accent("│"))
	fmt.Println("  " + accent("├"+ui.hr('─')+"┤"))
}

func (ui *termUI) boxRow(label, value string) {
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	lbl := ui.col(color.Faint, false).SprintFunc()
	val := ui.col(color.FgHiWhite, false).SprintFunc()
	w := ui.width()
	label = strings.TrimSpace(label)
	value = strings.TrimSpace(value)
	left := lbl(strings.ToUpper(label) + ":")
	avail := w - 4 - len(ui.stripANSI(left)) - 2
	if avail < 6 {
		avail = 6
	}
	right := val(truncateText(value, avail))
	line := left + " " + right
	pad := w - 4 - len(ui.stripANSI(line))
	if pad < 0 {
		pad = 0
	}
	fmt.Println("  " + accent("│ ") + line + strings.Repeat(" ", pad) + accent("│"))
}

func (ui *termUI) boxBottom() {
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	fmt.Println("  " + accent("╰"+ui.hr('─')+"╯"))
	fmt.Println()
}

func (ui *termUI) section(title string) {
	w := ui.width()
	fmt.Println()
	fmt.Println("  " + ui.col(color.FgHiCyan, true).Sprint("◆ "+title))
	fmt.Println("  " + ui.col(color.Faint, false).Sprint(strings.Repeat("─", w-2)))
}

func (ui *termUI) playBootAnimation() {
	if !ui.isTTY() {
		return
	}
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	glow := ui.col(color.FgHiMagenta, true).SprintFunc()
	dim := ui.col(color.Faint, false).SprintFunc()
	frames := []string{"▛▀▀▀▀▀▀▀", "▜▀▀▀▀▀▀▀", "▙▄▄▄▄▄▄▄", "▟▟▟▟▟▟▟"}
	for _, f := range frames {
		fmt.Print("\r  " + accent(f) + glow(" ⚡ ") + dim("Zyre Dstat Scanner"))
		time.Sleep(70 * time.Millisecond)
	}
	fmt.Print("\r\033[K")
}

func (ui *termUI) pulseBar(frame int, width int) string {
	if width < 8 {
		width = 8
	}
	pos := frame % (width * 2)
	if pos >= width {
		pos = width*2 - pos
	}
	var b strings.Builder
	for i := 0; i < width; i++ {
		dist := pos - i
		if dist < 0 {
			dist = -dist
		}
		switch {
		case dist == 0:
			b.WriteString(ui.col(color.FgHiCyan, true).Sprint("█"))
		case dist == 1:
			b.WriteString(ui.col(color.FgCyan, false).Sprint("▓"))
		case dist == 2:
			b.WriteString(ui.col(color.FgBlue, false).Sprint("▒"))
		default:
			b.WriteString(ui.col(color.Faint, false).Sprint("░"))
		}
	}
	return b.String()
}

func (ui *termUI) printProgress(frame int64, scanned, found int64, rate float64) {
	spin := spinnerFrames[frame%int64(len(spinnerFrames))]
	accent := ui.col(color.FgHiCyan, true).SprintFunc()
	dim := ui.col(color.Faint, false).SprintFunc()
	foundClr := ui.col(color.FgHiGreen, true).SprintFunc()
	rateClr := ui.col(color.FgHiYellow, true).SprintFunc()
	countClr := ui.col(color.FgHiWhite, true).SprintFunc()
	displayMu.Lock()
	defer displayMu.Unlock()
	// End with newline so zmap stderr cannot append to the same line.
	fmt.Printf("\r\033[2K  %s %s %s  %s %s  %s %s\n",
		accent(spin),
		dim("scanned"), countClr(fmt.Sprintf("%d", scanned)),
		dim("hits"), foundClr(fmt.Sprintf("%d", found)),
		dim("rate"), rateClr(fmt.Sprintf("%.0f/s", rate)))
}

func (ui *termUI) clearProgressLine() {
	displayMu.Lock()
	fmt.Print("\r\033[2K")
	displayMu.Unlock()
}

var ansiStripRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func truncateText(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return string(r[:1])
	}
	return string(r[:max-1]) + "…"
}

var globalUI = newTermUI()
var displayMu sync.Mutex

func printZmapStderrTip() {
	dim := globalUI.col(color.Faint, false).SprintFunc()
	fmt.Println("  " + dim("Tip: hide zmap drop-packet spam →  zmap -p PORT -q 2>/dev/null | "+programBin()+" zmap …"))
}

func printScannerHelp() {
	ui := globalUI
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	title := ui.col(color.FgHiCyan, true).SprintFunc()
	hi := ui.col(color.FgHiWhite, true).SprintFunc()
	dim := ui.col(color.Faint, false).SprintFunc()
	green := ui.col(color.FgHiGreen, false).SprintFunc()
	yellow := ui.col(color.FgHiYellow, false).SprintFunc()
	magenta := ui.col(color.FgHiMagenta, false).SprintFunc()

	bin := programBin()

	ui.playBootAnimation()
	fmt.Println()
	w := ui.width()
	fmt.Println("  " + accent("╭"+ui.hr('─')+"╮"))
	head := " ⚡ " + appTitle
	sub := "find dstats · check protection"
	line := title(head) + "  " + dim(sub)
	if len(ui.stripANSI(line)) > w-2 {
		line = title(truncateText(head+"  "+sub, w-2))
	}
	pad := w - 2 - len(ui.stripANSI(line))
	if pad < 0 {
		pad = 0
	}
	fmt.Println("  " + accent("│") + line + strings.Repeat(" ", pad) + accent("│"))
	fmt.Println("  " + accent("╰"+ui.hr('─')+"╯"))

	cmdRow := func(cmd, desc string) {
		fmt.Println("  " + magenta("▸") + " " + yellow(cmd))
		if strings.TrimSpace(desc) != "" {
			fmt.Println("    " + dim(desc))
		}
	}
	sourceRow := func(name, port, desc string) {
		left := ui.padRight(green(name), 10)
		mid := ui.padRight(dim(port), 9)
		fmt.Println("  " + left + " " + mid + " " + dim(desc))
	}
	capRow := func(name, bw, pps, nic, note string) {
		line := "  " + ui.padRight(dim(name), 10) +
			dim(" BW ") + ui.padRight(hi(bw), 5) +
			dim(" · PPS ") + ui.padRight(hi(pps), 5) +
			dim(" · NIC ") + ui.padRight(hi(nic), 5)
		if note != "" {
			line += dim(" · " + note)
		}
		fmt.Println(line)
	}
	apiRow := func(name, path, note string) {
		left := ui.padRight(dim(name), 21)
		mid := ui.padRight(hi(path), 27)
		fmt.Println("  " + left + " " + mid + " " + dim(note))
	}

	ui.section("SYNOPSIS")
	cmdRow(bin+" [min_gbps] [zmap|masscan] [sources] < ips", "Layer 4 capacity discovery scan")
	cmdRow(bin+" monitor <ip> [port|metrics|netdata|telegraf|snmp|glances|cadvisor]", "Live monitor (Gb/s + PPS)")
	cmdRow(bin+" [zmap|masscan] [nginx|apache|haproxy|envoy|traefik|caddy|all7] [http|https] [port[,port...]] < ips", "Layer 7 RPS scanner")
	cmdRow(bin+" scrape <AS#####|#####> <output.txt>", "Export ASN IPv4 ranges for scanning")
	cmdRow(bin+" help", "Show this help")

	ui.section("SOURCES")
	sourceRow("metrics", ":9100", "node_exporter /metrics")
	sourceRow("netdata", ":19999", "Netdata Prometheus API")
	sourceRow("telegraf", ":9273", "Telegraf prometheus_client /metrics")
	sourceRow("snmp", "UDP:161", "SNMP v2c IF-MIB (UDP:161, 10/100/400G links)")
	sourceRow("glances", ":61208", "Glances REST API (NIC speed + RX rate, no PPS)")
	sourceRow("cadvisor", ":8080", "cAdvisor machine API + /metrics counters")
	sourceRow("all", "-", "L4 bundle: metrics + netdata + telegraf + snmp + glances + cadvisor")
	sourceRow("all7", "-", "L7 bundle: nginx + apache + haproxy + envoy + traefik + caddy")

	ui.section("BEST COMMANDS (BIG SERVERS)")
	cmdRow(bin+" scrape AS##### ranges.txt", "Prepare a clean IPv4 range list first")
	cmdRow("{ zmap -p 9100 -q -w ranges.txt; zmap -p 19999 -q -w ranges.txt; zmap -p 9273 -q -w ranges.txt; zmap -p 61208 -q -w ranges.txt; zmap -p 8080 -q -w ranges.txt; } | "+bin+" zmap all", "Best general zmap coverage for high-capacity hosts")
	cmdRow("masscan 0.0.0.0/0 -pU:161 --rate 50000 -oL - | "+bin+" masscan snmp", "Masscan UDP:161 discovery (100/200/400G routers)")
	cmdRow(bin+" snmp <ip|cidr>", "Direct SNMP UDP:161 scan on single host or entire CIDR")
	cmdRow("zmap -p 9100 -q 2>/dev/null | "+bin+" zmap metrics", "Best single zmap command (usually most hits)")

	ui.section("SCAN ALL AT ONCE")
	cmdRow("{ zmap -p 9100 -q; zmap -p 19999 -q; zmap -p 9273 -q; zmap -p 61208 -q; zmap -p 8080 -q; } | "+bin+" zmap all", "Scan all supported L4 TCP sources")
	cmdRow("masscan 0.0.0.0/0 -p8080,9100,9273,19999,61208 --rate 50000 --output-format list | "+bin+" masscan all", "Masscan variant for broad discovery")
	cmdRow("{ zmap -p 80 -q 2>/dev/null; zmap -p 443 -q 2>/dev/null; zmap -p 8080 -q 2>/dev/null; zmap -p 8404 -q 2>/dev/null; zmap -p 9901 -q 2>/dev/null; zmap -p 2019 -q 2>/dev/null; } | "+bin+" zmap all7", "Scan all supported L7 APIs")

	ui.section("SOURCE CAPABILITIES")
	capRow("metrics", "yes", "yes", "yes", "")
	capRow("netdata", "yes", "yes", "yes", "")
	capRow("telegraf", "yes", "yes", "yes", "")
	capRow("snmp", "yes*", "yes*", "yes", "")
	capRow("glances", "yes", "no", "yes", "")
	capRow("cadvisor", "yes", "yes", "yes", "")
	fmt.Println("  " + dim("  * SNMP depends on IF-MIB counters being exposed by target"))

	ui.section("LAYER7 APIS (BESIDES NGINX)")
	apiRow("Apache mod_status", "/server-status?auto", "requests/sec if enabled")
	apiRow("HAProxy stats", "/stats;csv", "sessions/rate, often auth-protected")
	apiRow("Envoy admin stats", "/stats?format=prometheus", "rq counters, often internal-only")
	apiRow("Traefik metrics", "/metrics", "Prometheus request counters")
	apiRow("Caddy metrics", "/metrics", "Prometheus request counters")
	fmt.Println("  " + dim("  Note: these expose current request rate, not true max RPS capacity."))

	ui.section("EXAMPLES")
	examples := []struct{ cmd, desc string }{
		{"cat ips.txt | " + bin + " 10 metrics", "min 10 Gbps · metrics only"},
		{"cat ips.txt | " + bin + " 50 metrics,netdata", "min 50 Gbps · metrics + netdata"},
		{"zmap -p 9100 -q 2>/dev/null | " + bin + " zmap metrics", "zmap node_exporter hits"},
		{"zmap -p 19999 -q 2>/dev/null | " + bin + " zmap netdata", "zmap Netdata hits"},
		{"zmap -p 9273 -q 2>/dev/null | " + bin + " zmap telegraf", "zmap Telegraf hits"},
		{"zmap -p 61208 -q 2>/dev/null | " + bin + " zmap glances", "zmap Glances hits (NIC speed)"},
		{"zmap -p 8080 -q 2>/dev/null | " + bin + " zmap cadvisor", "zmap cAdvisor hits (machine NIC speed)"},
		{bin + " monitor 1.2.3.4 glances", "live monitor · Glances :61208"},
		{bin + " monitor 1.2.3.4 cadvisor", "live monitor · cAdvisor :8080"},
		{"zmap -p 80 -q 2>/dev/null | " + bin + " zmap nginx", "layer7 nginx_status scanner"},
		{"zmap -p 80 -q 2>/dev/null | " + bin + " zmap apache", "layer7 Apache mod_status scanner"},
		{"zmap -p 8404 -q 2>/dev/null | " + bin + " zmap haproxy", "layer7 HAProxy stats scanner"},
		{"zmap -p 9901 -q 2>/dev/null | " + bin + " zmap envoy", "layer7 Envoy stats scanner"},
		{"zmap -p 8080 -q 2>/dev/null | " + bin + " zmap traefik", "layer7 Traefik metrics scanner"},
		{"zmap -p 2019 -q 2>/dev/null | " + bin + " zmap caddy", "layer7 Caddy metrics scanner"},
		{"{ zmap -p 80 -q 2>/dev/null; zmap -p 443 -q 2>/dev/null; zmap -p 8080 -q 2>/dev/null; zmap -p 8404 -q 2>/dev/null; zmap -p 9901 -q 2>/dev/null; zmap -p 2019 -q 2>/dev/null; } | " + bin + " zmap all7", "scan all layer7 APIs at once"},
		{"zmap -p 443 -q 2>/dev/null | " + bin + " zmap nginx https", "layer7 scanner forcing HTTPS"},
		{bin + " scrape AS202422 gcore.txt", "export IPv4 BGP prefixes for an ASN (IPv6 auto-removed for zmap)"},
		{"{ zmap -p 9100 -q -w gcore.txt; zmap -p 9273 -q -w gcore.txt; zmap -p 19999 -q -w gcore.txt; zmap -p 61208 -q -w gcore.txt; zmap -p 8080 -q -w gcore.txt; } | " + bin + " zmap all", "scan ASN prefix file · all supported TCP ports"},
		{"{ zmap -p 9100 -q; zmap -p 9273 -q; zmap -p 19999 -q; zmap -p 61208 -q; zmap -p 8080 -q; } | " + bin + " zmap all", "scan every supported TCP source at once"},
		{"{ zmap -p 9100 -q; zmap -p 19999 -q; zmap -p 161 -q; } | " + bin + " zmap all", "zmap incl. UDP 161 · all protocols"},
		{"masscan 0.0.0.0/0 -p8080,9100,9273,19999,61208 --rate 50000 --output-format list | " + bin + " masscan all", "masscan multi-port"},
		{"masscan 0.0.0.0/0 -p9100 --rate 50000 --output-format list | " + bin + " masscan metrics", "masscan TCP 9100"},
		{"masscan 0.0.0.0/0 -pU:161 --rate 50000 --output-format list | " + bin + " masscan snmp", "masscan UDP 161"},
		{bin + " monitor 1.2.3.4", "live traffic monitor · :9100"},
		{bin + " monitor 1.2.3.4 netdata", "live monitor · Netdata :19999"},
		{bin + " monitor 1.2.3.4 telegraf", "live monitor · Telegraf :9273"},
		{bin + " monitor 1.2.3.4 snmp", "live monitor · SNMP :161"},
	}
	for _, ex := range examples {
		cmdRow(ex.cmd, ex.desc)
	}

	ui.section("TIPS")
	cmdRow(bin+" scrape AS##### ranges.txt", "Scrape ASN prefixes before scanning")
	cmdRow("zmap -p 9100 -q -w ranges.txt", "Use zmap whitelist files for controlled scans")
	cmdRow("{ zmap -p 9100 -q; zmap -p 61208 -q; zmap -p 8080 -q; }", "zmap supports one port per run")
	cmdRow("-p8080,9100,9273,19999,61208", "masscan supports comma-separated multi-port scans")
	cmdRow("ulimit -n 100000", "Raise file descriptor limits before heavy scans")
	cmdRow("zmap … -q 2>/dev/null | "+bin+" …", "Suppress zmap [WARN] monitor: Dropped packets spam")
	fmt.Println()
}

func envIntInRange(key string, fallback, minVal, maxVal int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func recommendedWorkerCount(perCPU, minVal, maxVal int) int {
	w := runtime.NumCPU() * perCPU
	if w < minVal {
		return minVal
	}
	if w > maxVal {
		return maxVal
	}
	return w
}

func printScannerBanner(cfg scanConfig) {
	ui := globalUI
	bin := programBin()
	ui.playBootAnimation()

	ports := cfg.sources.ports()
	portStr := make([]string, len(ports))
	for i, p := range ports {
		portStr[i] = strconv.Itoa(p)
	}

	filter := "any bandwidth"
	if cfg.minBandwidth > 0 {
		filter = fmt.Sprintf("at least %.0f Gbps", cfg.minBandwidth)
	}

	ui.boxTop("⚡ " + appTitle + " · L4 Scanner")
	ui.boxRow("checking", cfg.sources.label())
	ui.boxRow("ports", strings.Join(portStr, " · "))
	ui.boxRow("input", cfg.mode)
	ui.boxRow("min size", filter)
	ui.boxRow("waiting", "IPs on stdin… "+bin+" help for usage")
	ui.boxBottom()
}

// ── Async buffered file writer ────────────────────────────────────────────────

type asyncWriter struct {
	ch   chan string
	done chan struct{}
}

func newAsyncWriter(f *os.File) *asyncWriter {
	aw := &asyncWriter{
		ch:   make(chan string, 8192), // bigger buffer = less backpressure
		done: make(chan struct{}),
	}
	go func() {
		defer close(aw.done)
		bw := bufio.NewWriterSize(f, 128*1024) // 128KB write buffer
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case s, ok := <-aw.ch:
				if !ok {
					bw.Flush()
					return
				}
				bw.WriteString(s)
			case <-ticker.C:
				bw.Flush()
			}
		}
	}()
	return aw
}

func (aw *asyncWriter) Write(s string) { aw.ch <- s }
func (aw *asyncWriter) Close() {
	close(aw.ch)
	<-aw.done
}

// ── ISP/country cache ─────────────────────────────────────────────────────────
// Cache by /24 prefix — IPs in the same /24 almost always share the same ASN.
// Uses sync.Map for lock-free concurrent reads (hot path).

type ispCacheEntry struct {
	isp     string
	country string
}

var ispCache sync.Map // key: string (/24 prefix), value: ispCacheEntry

func ipTo24Prefix(ipStr string) string {
	// Fast: find the last dot and truncate
	lastDot := strings.LastIndexByte(ipStr, '.')
	if lastDot == -1 {
		return ipStr
	}
	return ipStr[:lastDot]
}

// ── Scanner buffer pool ───────────────────────────────────────────────────────
// Reuse bufio.Scanner buffers across getNodeSpeed calls to avoid 128KB
// allocation per HTTP response.

var scanBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// ── ASN prefix scrape ─────────────────────────────────────────────────────────

func normalizeASNInput(s string) (string, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "AS")
	if s == "" {
		return "", fmt.Errorf("empty ASN")
	}
	if _, err := strconv.ParseUint(s, 10, 32); err != nil {
		return "", fmt.Errorf("invalid ASN %q (use AS202422 or 202422)", s)
	}
	return s, nil
}

type ripeAnnouncedPrefixesResp struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

type bgpViewPrefixesResp struct {
	Data struct {
		IPv4Prefixes []bgpPrefixEntry `json:"ipv4_prefixes"`
		IPv6Prefixes []bgpPrefixEntry `json:"ipv6_prefixes"`
	} `json:"data"`
}

type bgpPrefixEntry struct {
	Prefix string `json:"prefix"`
}

type ripeASOverviewResp struct {
	Data struct {
		Holder string `json:"holder"`
	} `json:"data"`
}

func fetchASNHolder(asn string) string {
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%s", asn)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out ripeASOverviewResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ""
	}
	return strings.TrimSpace(out.Data.Holder)
}

func fetchASNPrefixes(asn string) ([]string, int, error) {
	var raw []string
	var err error
	if prefixes, e := fetchASNPrefixesRIPE(asn); e == nil && len(prefixes) > 0 {
		raw = prefixes
	} else {
		raw, err = fetchASNPrefixesBGPView(asn)
		if err != nil {
			return nil, 0, err
		}
	}
	v4, dropped := filterIPv4Only(raw)
	if len(v4) == 0 {
		return nil, dropped, fmt.Errorf("no IPv4 prefixes for AS%s", asn)
	}
	sortPrefixes(v4)
	return v4, dropped, nil
}

func fetchASNPrefixesRIPE(asn string) ([]string, error) {
	client := &http.Client{Timeout: 45 * time.Second}
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE Stat HTTP %d", resp.StatusCode)
	}

	var payload ripeAnnouncedPrefixesResp
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if !strings.EqualFold(payload.Status, "ok") {
		return nil, fmt.Errorf("RIPE Stat status %q", payload.Status)
	}

	seen := make(map[string]struct{})
	var prefixes []string
	for _, p := range payload.Data.Prefixes {
		prefix := strings.TrimSpace(p.Prefix)
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no prefixes returned for AS%s", asn)
	}
	sortPrefixes(prefixes)
	return prefixes, nil
}

func fetchASNPrefixesBGPView(asn string) ([]string, error) {
	client := &http.Client{Timeout: 45 * time.Second}
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("BGPView HTTP %d", resp.StatusCode)
	}

	var payload bgpViewPrefixesResp
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var prefixes []string
	for _, p := range payload.Data.IPv4Prefixes {
		prefix := strings.TrimSpace(p.Prefix)
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no prefixes returned for AS%s", asn)
	}
	sortPrefixes(prefixes)
	return prefixes, nil
}

func isIPv4CIDR(prefix string) bool {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(prefix))
	if err != nil {
		return false
	}
	return ip.To4() != nil
}

func filterIPv4Only(prefixes []string) (v4 []string, dropped int) {
	for _, p := range prefixes {
		if isIPv4CIDR(p) {
			v4 = append(v4, strings.TrimSpace(p))
		} else {
			dropped++
		}
	}
	return v4, dropped
}

func sortPrefixes(prefixes []string) {
	sort.Slice(prefixes, func(i, j int) bool {
		return comparePrefix(prefixes[i], prefixes[j]) < 0
	})
}

func comparePrefix(a, b string) int {
	ipA, netA, errA := net.ParseCIDR(a)
	ipB, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	if c := bytesCompare(ipA, ipB); c != 0 {
		return c
	}
	onesA, _ := netA.Mask.Size()
	onesB, _ := netB.Mask.Size()
	if onesA < onesB {
		return -1
	}
	if onesA > onesB {
		return 1
	}
	return 0
}

func bytesCompare(a, b net.IP) int {
	aa := a.To16()
	bb := b.To16()
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func runASNScrape(args []string) {
	bin := programBin()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s scrape <AS#####|#####> <output.txt>\n", bin)
		fmt.Fprintf(os.Stderr, "Example: %s scrape AS202422 gcore.txt\n", bin)
		os.Exit(1)
	}

	asn, err := normalizeASNInput(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
		os.Exit(1)
	}
	outPath := args[1]

	ui := globalUI
	accent := ui.col(color.FgHiCyan, false).SprintFunc()
	title := ui.col(color.FgHiCyan, true).SprintFunc()
	dim := ui.col(color.Faint, false).SprintFunc()
	green := ui.col(color.FgHiGreen, false).SprintFunc()

	fmt.Println()
	fmt.Println("  " + accent("╔"+ui.hr('═')+"╗"))
	fmt.Println("  " + accent("║") + title("  ⚡  "+appTitle+" · ASN Scrape") + accent(strings.Repeat(" ", 24)) + accent("║"))
	fmt.Println("  " + accent("╚"+ui.hr('═')+"╝"))
	fmt.Println()
	fmt.Printf("  %s  %s\n", dim("ASN"), green("AS"+asn))
	fmt.Printf("  %s  %s\n", dim("Output"), green(outPath))
	fmt.Println("  " + dim("Fetching announced prefixes…"))
	fmt.Println()

	holder := fetchASNHolder(asn)
	prefixes, droppedV6, err := fetchASNPrefixes(asn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ cannot write %s: %v\n", outPath, err)
		os.Exit(1)
	}
	defer f.Close()

	bw := bufio.NewWriterSize(f, 128*1024)
	for _, prefix := range prefixes {
		bw.WriteString(prefix)
		bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  %s  %s\n", dim("Saved"), green(fmt.Sprintf("%d IPv4 prefixes → %s", len(prefixes), outPath)))
	if holder != "" {
		fmt.Printf("  %s  %s\n", dim("Holder"), holder)
	}
	if droppedV6 > 0 {
		fmt.Printf("  %s  %s\n", dim("Filtered"), dim(fmt.Sprintf("%d IPv6 prefixes removed (zmap whitelist is IPv4-only)", droppedV6)))
	}
	fmt.Println()
	fmt.Println("  " + dim("Scan this file with zmap:"))
	fmt.Println("  " + green(fmt.Sprintf("{ zmap -p 9100 -q -w %s; zmap -p 9273 -q -w %s; zmap -p 19999 -q -w %s; } | %s zmap all", outPath, outPath, outPath, bin)))
	fmt.Println()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	log.SetOutput(io.Discard)

	if len(os.Args) >= 2 {
		if strings.EqualFold(os.Args[1], "monitor") {
			runTrafficMonitor(os.Args[2:])
			return
		}
		if strings.EqualFold(os.Args[1], "scrape") {
			runASNScrape(os.Args[2:])
			return
		}
		// Layer-7 scanner trigger (nginx/apache/haproxy/envoy/traefik/caddy/all7).
		if hasL7Selector(os.Args[1:]) {
			runNginxScan(os.Args[1:])
			return
		}
		if isHelpArg(os.Args[1]) {
			printScannerHelp()
			return
		}
	}

	// ── Linux performance tuning ───────────────────────────────────────────
	runtime.GOMAXPROCS(runtime.NumCPU())
	// Reduce GC frequency — we allocate a lot of short-lived objects.
	// Default is 100 (GC when heap doubles). 300 = less frequent GC = more throughput.
	debug.SetGCPercent(300)

	minBandwidth := 0.0
	mode := "zmap"
	sources := allScanSources()
	var directTargets []string

	// ./scanner [min_bandwidth] [zmap|masscan] [metrics|netdata|snmp|udp|all|...] [IP|CIDR...]
	for _, arg := range os.Args[1:] {
		if val, err := strconv.ParseFloat(arg, 64); err == nil {
			minBandwidth = val
			if minBandwidth <= 0 {
				minBandwidth = 0
			}
			continue
		}
		m := strings.ToLower(arg)
		switch m {
		case "masscan", "massscan":
			mode = "masscan"
		case "zmap":
			mode = "zmap"
		default:
			if parsed := parseScanSources(arg); parsed.any() {
				sources = parsed
			} else if net.ParseIP(arg) != nil || cidrRegex.MatchString(arg) {
				directTargets = append(directTargets, arg)
			}
		}
	}
	if hasL4AllArg(os.Args[1:]) {
		sources = allScanSources()
	}

	cfg := scanConfig{minBandwidth: minBandwidth, mode: mode, sources: sources}

	if !sources.any() {
		printScannerHelp()
		fmt.Fprintf(os.Stderr, "\n  %s\n\n", color.New(color.FgHiRed).Sprint("⚠ No scan sources selected. Use metrics, netdata, telegraf, snmp, glances, cadvisor, or all."))
		os.Exit(1)
	}

	printScannerBanner(cfg)
	printZmapStderrTip()

	dim := color.New(color.Faint).SprintFunc()
	label := color.New(color.Faint, color.Bold).SprintFunc()
	fmt.Println("  " + label(" CAT ") + " " + label(" PROTO ") + " " + label(" PROTECTION  ") + "  " +
		dim("TARGET                  BANDWIDTH (MAX / LIST AS)   LOCATION"))
	fmt.Println("  " + dim(strings.Repeat("─", 68)))

	ports := sources.ports()

	var err error
	cityDB, err = geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", globalUI.col(color.FgHiYellow, false).Sprint("⚠ GeoLite2-City.mmdb not found — using online fallback"))
		cityDB = nil
	} else {
		defer cityDB.Close()
	}

	asnDB, err = geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", globalUI.col(color.FgHiYellow, false).Sprint("⚠ GeoLite2-ASN.mmdb not found — using online fallback"))
		asnDB = nil
	} else {
		defer asnDB.Close()
	}

	// ── Output files ───────────────────────────────────────────────────────
	bigFile, _ := os.OpenFile("big.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	dstatsFile, _ := os.OpenFile("dstats.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer bigFile.Close()
	defer dstatsFile.Close()

	bigWriter := newAsyncWriter(bigFile)
	dstatsWriter := newAsyncWriter(dstatsFile)
	defer bigWriter.Close()
	defer dstatsWriter.Close()
	writeTxtHeaderIfEmpty(bigFile, bigWriter)
	writeTxtHeaderIfEmpty(dstatsFile, dstatsWriter)

	// ── Read and Parse Input Targets (STREAMING) ─────────────────────────────
	// Read stdin line-by-line and feed IPs directly into the job channel
	// so scanning starts immediately while the upstream scanner is still running.
	var r io.Reader = os.Stdin

	var attempted int64
	var foundCount int64
	results := make([]Result, 0, 512)
	var mu sync.Mutex

	jobs := make(chan Job, 200_000) // bigger buffer = scanner never blocks waiting for workers
	var total int64

	go func() {
		defer close(jobs)

		for _, tgt := range directTargets {
			if match := cidrRegex.FindString(tgt); match != "" {
				if ip, ipnet, err := net.ParseCIDR(match); err == nil {
					count := cidrIPCount(ipnet)
					ui := globalUI
					accent := ui.col(color.FgHiCyan, false).SprintFunc()
					dim := ui.col(color.Faint, false).SprintFunc()
					hi := ui.col(color.FgHiYellow, true).SprintFunc()
					green := ui.col(color.FgHiGreen, true).SprintFunc()
					fmt.Printf("\r\033[K  %s %s %s %s %s\n",
						accent("◆"), dim("CIDR"), hi(match), dim("→"), green(fmt.Sprintf("%d IPs queued", count)))
					for ip2 := ip.Mask(ipnet.Mask); ipnet.Contains(ip2); incIP(ip2) {
						s := ip2.String()
						for _, p := range ports {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: s, Port: p}
						}
					}
					continue
				}
			}

			ipOnly, overridePort := parseIPAndOptionalPort(tgt)
			if net.ParseIP(ipOnly) == nil {
				ipOnly = extractIPFromInputLine(tgt)
			}
			if net.ParseIP(ipOnly) != nil {
				pList := ports
				if overridePort != 0 {
					pList = []int{overridePort}
				}
				for _, p := range pList {
					atomic.AddInt64(&total, 1)
					jobs <- Job{IP: ipOnly, Port: p}
				}
			}
		}

		if len(directTargets) > 0 && !isStdinPiped() {
			return
		}

		lineScanner := bufio.NewScanner(r)
		lineScanner.Buffer(make([]byte, 1*1024*1024), 1*1024*1024)
		for lineScanner.Scan() {
			raw := strings.TrimSpace(lineScanner.Text())
			if raw == "" || strings.HasPrefix(raw, "#") || isScannerNoise(raw) {
				continue
			}

			// Support masscan -oL format: "open tcp 9100 1.2.3.4 timestamp"
			if mode == "masscan" && strings.HasPrefix(raw, "open ") {
				parts := strings.Fields(raw)
				if len(parts) >= 4 {
					ipStr := parts[3]
					if net.ParseIP(ipStr) != nil {
						overridePort, _ := strconv.Atoi(parts[2])
						pList := ports
						if overridePort != 0 {
							pList = []int{overridePort}
						}
						for _, p := range pList {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: ipStr, Port: p}
						}
						continue
					}
				}
			}

			if match := cidrRegex.FindString(raw); match != "" {
				ip, ipnet, err := net.ParseCIDR(match)
				if err == nil {
					count := cidrIPCount(ipnet)
					ui := globalUI
					accent := ui.col(color.FgHiCyan, false).SprintFunc()
					dim := ui.col(color.Faint, false).SprintFunc()
					hi := ui.col(color.FgHiYellow, true).SprintFunc()
					green := ui.col(color.FgHiGreen, true).SprintFunc()
					fmt.Printf("\r\033[K  %s %s %s %s %s\n",
						accent("◆"), dim("CIDR"), hi(match), dim("→"), green(fmt.Sprintf("%d IPs queued", count)))
					for ip2 := ip.Mask(ipnet.Mask); ipnet.Contains(ip2); incIP(ip2) {
						s := ip2.String()
						for _, p := range ports {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: s, Port: p}
						}
					}
					continue
				}
			}

			ipOnly, overridePort := parseIPAndOptionalPort(raw)
			if net.ParseIP(ipOnly) == nil {
				ipOnly = extractIPFromInputLine(raw)
			}
			if net.ParseIP(ipOnly) == nil {
				continue
			}

			pList := ports
			if overridePort != 0 {
				pList = []int{overridePort}
			}
			for _, p := range pList {
				atomic.AddInt64(&total, 1)
				jobs <- Job{IP: ipOnly, Port: p}
			}
		}
		if err := lineScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Error reading input: %v\n", err)
		}
	}()

	startTime := time.Now()
	var wg sync.WaitGroup

	// ── Progress ticker ────────────────────────────────────────────────────
	stopProgress := make(chan struct{})
	var spinFrame int64
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		ui := globalUI
		for {
			select {
			case <-stopProgress:
				return
			case <-tick.C:
				a := atomic.LoadInt64(&attempted)
				f := atomic.LoadInt64(&foundCount)
				if a == 0 {
					continue
				}
				elapsed := time.Since(startTime).Seconds()
				if elapsed == 0 {
					continue
				}
				frame := atomic.AddInt64(&spinFrame, 1)
				ui.printProgress(frame, a, f, float64(a)/elapsed)
			}
		}
	}()

	// ── Hit pipeline ───────────────────────────────────────────────────────
	// Scan workers only do the fast HTTP check and push raw hits here.
	// Post-processors handle slow ops (ISP lookup, DNS, classify, print).
	type hit struct {
		ip     string
		port   int
		cap    *CapacityReport
		hasXDP bool
	}
	hitCh := make(chan hit, 32768) // bigger buffer so workers almost never block

	// ── Post-processor pool ──────────────────────────────────────────────────
	ppWorkers := envIntInRange("DSTAT_L4_POST_WORKERS", recommendedWorkerCount(16, 96, 512), 32, 1024)
	rdnsEnabled := envBool("DSTAT_SCAN_RDNS", false)
	rdnsTimeoutMs := envIntInRange("DSTAT_SCAN_RDNS_TIMEOUT_MS", 60, 20, 500)
	var ppWg sync.WaitGroup
	for i := 0; i < ppWorkers; i++ {
		ppWg.Add(1)
		go func() {
			defer ppWg.Done()
			for h := range hitCh {
				isp, country := getIPInfoCached(h.ip)
				ispLower := strings.ToLower(isp)

				totalBw, labelBw := dstatBandwidthPair(h.cap)
				effectiveGbps := math.Max(totalBw, labelBw)
				category := classifyCategory(effectiveGbps)
				pStatus, classified := classifyProtectionFromISP(ispLower)
				if !classified {
					if rdnsEnabled {
						hostnames := reverseDNSWithTimeout(h.ip, time.Duration(rdnsTimeoutMs)*time.Millisecond)
						pStatus = classifyProtection(ispLower, hostnames)
					} else {
						pStatus = classifyProtection(ispLower, nil)
					}
				}

				res := Result{
					IP:                 h.ip,
					Port:               h.port,
					Bandwidth:          h.cap.RealisticDstatGbps,
					TotalCapacityGbps:  h.cap.TotalHardwareGbps,
					PrimaryPathGbps:    h.cap.PrimaryPathGbps,
					PrimaryDevice:      h.cap.PrimaryDevice,
					HasBonding:         h.cap.HasBonding,
					IndependentUplinks: h.cap.IndependentUplinks,
					ISP:                isp,
					Country:            country,
					HasXDP:             h.hasXDP,
					Category:           category,
					Protocol:           protocolName(h.port),
					ProtectionStatus:   pStatus.status,
					ProtectionReason:   pStatus.reason,
					CapacityNotes:      h.cap.Notes,
				}

				entry := formatLogEntry(res)

				displayMu.Lock()
				fmt.Print("\r\033[2K")
				printResult(h.ip, h.port, h.cap, isp, country, h.hasXDP, category, pStatus)
				displayMu.Unlock()

				mu.Lock()
				results = append(results, res)
				atomic.AddInt64(&foundCount, 1)
				mu.Unlock()

				if totalBw >= 300 || labelBw >= 300 || h.cap.TotalHardwareGbps >= 300 || h.cap.RealisticDstatGbps >= 300 || h.cap.PrimaryPathGbps >= 300 {
					bigWriter.Write(entry)
				} else {
					dstatsWriter.Write(entry)
				}
			}
		}()
	}

	// ── Scan workers ────────────────────────────────────────────────────────
	// Each worker has its own dedicated HTTP client — zero shared state,
	// zero pool contention, zero semaphore overhead.
	// Worker count IS the concurrency limit. No semaphore needed.
	//
	// Dynamic default to avoid FD/socket pressure bursts that can look like "stuck".
	// Override with DSTAT_L4_WORKERS when needed.
	workerCount := envIntInRange("DSTAT_L4_WORKERS", recommendedWorkerCount(256, 1024, 6144), 256, 8192)
	l4Retries := envIntInRange("DSTAT_L4_RETRIES", 1, 0, 3)
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each worker gets its own HTTP client and transport.
			// No shared transport mutex = maximum parallelism.
			client := &http.Client{
				Timeout: 1300 * time.Millisecond,
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout:   700 * time.Millisecond,
						KeepAlive: -1,
					}).DialContext,
					DisableKeepAlives:     true,
					MaxIdleConns:          0,
					ResponseHeaderTimeout: 700 * time.Millisecond,
					IdleConnTimeout:       1 * time.Millisecond,
				},
			}
			for j := range jobs {
				atomic.AddInt64(&attempted, 1)
				var cap *CapacityReport
				hasXDP := false
				for attempt := 0; attempt <= l4Retries; attempt++ {
					cap, hasXDP = getHostCapacity(client, j.IP, j.Port)
					if cap != nil && len(cap.Interfaces) > 0 && (cap.RealisticDstatGbps >= 1.0 || cap.TotalHardwareGbps >= 1.0) && cap.RealisticDstatGbps >= minBandwidth {
						break
					}
					if attempt < l4Retries {
						time.Sleep(25 * time.Millisecond)
					}
				}
				if cap == nil || len(cap.Interfaces) == 0 || (cap.RealisticDstatGbps < 1.0 && cap.TotalHardwareGbps < 1.0) || cap.RealisticDstatGbps < minBandwidth {
					continue
				}
				hitCh <- hit{ip: j.IP, port: j.Port, cap: cap, hasXDP: hasXDP}
			}
		}()
	}

	wg.Wait()
	close(hitCh)
	ppWg.Wait()
	close(stopProgress)

	jsonFile, _ := os.Create("results.json")
	enc := json.NewEncoder(jsonFile)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
	jsonFile.Close()

	elapsed := time.Since(startTime)
	globalUI.clearProgressLine()
	ui := globalUI
	ui.boxTop("Done")
	ui.boxRow("found", fmt.Sprintf("%d dstats", len(results)))
	ui.boxRow("queued", fmt.Sprintf("%d targets", atomic.LoadInt64(&total)))
	ui.boxRow("checked", fmt.Sprintf("%d IPs", atomic.LoadInt64(&attempted)))
	ui.boxRow("took", elapsed.Round(time.Second).String())
	if len(results) > 0 {
		ui.boxRow("saved to", "results.json · dstats.txt · big.txt")
	}
	ui.boxBottom()
}

func getHostCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	switch port {
	case portNetdata:
		return getNetdataCapacity(client, ip, port)
	case portSNMP:
		return getSNMPCapacity(ip)
	case portTelegraf:
		return getTelegrafCapacity(client, ip, port)
	case portGlances:
		return getGlancesCapacity(client, ip, port)
	case portCAdvisor:
		return getCAdvisorCapacity(client, ip, port)
	default:
		return getNodeExporterCapacity(client, ip, port)
	}
}

// getNodeExporterCapacity fetches /metrics and returns passive capacity analysis.
func getNodeExporterCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	var sb strings.Builder
	sb.Grow(32 + len(ip))
	sb.WriteString("http://")
	sb.WriteString(ip)
	sb.WriteByte(':')
	sb.WriteString(strconv.Itoa(port))
	sb.WriteString("/metrics")

	req, err := http.NewRequest("GET", sb.String(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, false
	}

	report, err := parseHostCapacity(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil || report == nil || len(report.Interfaces) == 0 || (report.RealisticDstatGbps < 1.0 && report.TotalHardwareGbps < 1.0) {
		return nil, false
	}
	return report, report.HasXDP
}

func getTelegrafCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	var sb strings.Builder
	sb.Grow(32 + len(ip))
	sb.WriteString("http://")
	sb.WriteString(ip)
	sb.WriteByte(':')
	sb.WriteString(strconv.Itoa(port))
	sb.WriteString("/metrics")

	req, err := http.NewRequest("GET", sb.String(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, false
	}

	report, err := parseTelegrafCapacity(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil || report == nil || report.RealisticDstatGbps == 0 {
		return nil, false
	}
	return report, false
}

type glancesIface struct {
	Name     string  `json:"interface_name"`
	Speed    float64 `json:"speed"`
	RecvRate float64 `json:"bytes_recv_rate_per_sec"`
	Rx       float64 `json:"rx"`
	IsUp     *bool   `json:"is_up"`
}

func fetchGlancesNet(client *http.Client, ip string, port int) ([]glancesIface, error) {
	var lastErr error
	for _, p := range []string{"/api/4/network", "/api/3/network"} {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, p)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "zyre-dstat-scanner/1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var out []glancesIface
		err = json.NewDecoder(io.LimitReader(resp.Body, 1*1024*1024)).Decode(&out)
		resp.Body.Close()
		if err == nil && len(out) > 0 {
			return out, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("glances API unreachable on %s:%d", ip, port)
	}
	return nil, lastErr
}

func glancesRecvBytesPs(it glancesIface) float64 {
	if it.RecvRate > 0 {
		return it.RecvRate
	}
	if it.Rx > 0 {
		return it.Rx / 8.0
	}
	return 0
}

func getGlancesCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	ifaces, err := fetchGlancesNet(client, ip, port)
	if err != nil {
		return nil, false
	}
	speeds := map[string]float64{}
	oper := map[string]string{}
	for _, it := range ifaces {
		if it.Name == "" || isVirtualIface(it.Name) {
			continue
		}
		if it.Speed > 0 {
			speeds[it.Name] = it.Speed / 8.0
		}
		if it.IsUp == nil || *it.IsUp {
			oper[it.Name] = "up"
		}
	}
	if len(speeds) == 0 {
		return nil, false
	}
	report := analyze(speeds, map[string]string{}, oper, map[string]int{}, map[string]int{}, false)
	if report == nil || report.RealisticDstatGbps == 0 {
		return nil, false
	}
	report.Notes = append([]string{"Glances REST API (RX rate, no PPS)"}, report.Notes...)
	return report, false
}

func fetchGlancesLiveRates(client *http.Client, ip string, port int) ([]IfRate, map[string]string, error) {
	ifaces, err := fetchGlancesNet(client, ip, port)
	if err != nil {
		return nil, nil, err
	}
	var rates []IfRate
	for _, it := range ifaces {
		if it.Name == "" || isVirtualIface(it.Name) {
			continue
		}
		rates = append(rates, IfRate{Device: it.Name, BytesPs: glancesRecvBytesPs(it), PacketsPs: 0})
	}
	return rates, map[string]string{}, nil
}

type cAdvisorMachine struct {
	NetworkDevices []struct {
		Name       string `json:"name"`
		MacAddress string `json:"mac_address"`
		Speed      int64  `json:"speed"` // Mbit/s
	} `json:"network_devices"`
}

func fetchCAdvisorMachine(client *http.Client, ip string, port int) (*cAdvisorMachine, error) {
	var lastErr error
	for _, p := range []string{"/api/v2.0/machine", "/api/v1.3/machine"} {
		url := fmt.Sprintf("http://%s:%d%s", ip, port, p)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "zyre-dstat-scanner/1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var out cAdvisorMachine
		err = json.NewDecoder(io.LimitReader(resp.Body, 1*1024*1024)).Decode(&out)
		resp.Body.Close()
		if err == nil && len(out.NetworkDevices) > 0 {
			return &out, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("cAdvisor machine API unreachable on %s:%d", ip, port)
	}
	return nil, lastErr
}

func fetchCAdvisorSnapshot(client *http.Client, ip string, port int) (*MetricsSnapshot, error) {
	url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	s := &MetricsSnapshot{
		Time:      float64(time.Now().UnixNano()) / 1e9,
		RxBytes:   map[string]float64{},
		RxPackets: map[string]float64{},
		MACs:      map[string]string{},
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		switch {
		case strings.HasPrefix(line, "container_network_receive_bytes_total{"):
			dev := extractLabelString(line, "interface")
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if id := extractLabelString(line, "id"); id != "/" {
				continue
			}
			if val, ok := metricValue(line); ok {
				s.RxBytes[dev] = val
			}
		case strings.HasPrefix(line, "container_network_receive_packets_total{"):
			dev := extractLabelString(line, "interface")
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if id := extractLabelString(line, "id"); id != "/" {
				continue
			}
			if val, ok := metricValue(line); ok {
				s.RxPackets[dev] = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(s.RxBytes) == 0 {
		return nil, fmt.Errorf("not cAdvisor network metrics")
	}
	return s, nil
}

func getCAdvisorCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	m, err := fetchCAdvisorMachine(client, ip, port)
	if err != nil {
		return nil, false
	}
	speeds := map[string]float64{}
	macs := map[string]string{}
	oper := map[string]string{}
	for _, n := range m.NetworkDevices {
		if n.Name == "" || isVirtualIface(n.Name) {
			continue
		}
		if n.Speed > 0 {
			speeds[n.Name] = float64(n.Speed) * 1e6 / 8 // Mbit/s -> B/s
		}
		if n.MacAddress != "" {
			macs[n.Name] = strings.ToLower(n.MacAddress)
		}
		oper[n.Name] = "up"
	}
	if len(speeds) == 0 {
		return nil, false
	}
	report := analyze(speeds, macs, oper, map[string]int{}, map[string]int{}, false)
	if report == nil || report.RealisticDstatGbps == 0 {
		return nil, false
	}
	report.Notes = append([]string{"cAdvisor machine API + container_network counters"}, report.Notes...)
	return report, false
}

var monitorPrev sync.Map

func telegrafIfaceFromLine(line string) string {
	for _, key := range []string{"interface", "device", "iface"} {
		if dev := extractLabelString(line, key); dev != "" {
			return dev
		}
	}
	return ""
}

// telegrafSpeedToBytes converts Telegraf speed fields to bytes/s.
// net_speed / ethtool_speed are Mbit/s; *_bytes variants are already bytes/s.
func telegrafSpeedToBytes(metricPrefix string, val float64) float64 {
	if val <= 0 {
		return 0
	}
	switch {
	case strings.HasSuffix(metricPrefix, "_bytes"):
		return val
	case strings.Contains(metricPrefix, "nspeed_bits"), strings.HasSuffix(metricPrefix, "_bits"):
		return val / 8
	default:
		// net_speed, ethtool_speed, etc. — Mbit/s
		return val * 1e6 / 8
	}
}

func parseTelegrafCapacity(body io.Reader) (*CapacityReport, error) {
	speeds := map[string]float64{}
	oper := map[string]string{}
	hasNetCounters := false
	speedEstimated := false

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		metricName := line
		if idx := strings.Index(line, "{"); idx > 0 {
			metricName = line[:idx]
		}

		switch {
		case metricName == "ethtool_speed_bytes" || metricName == "ethtool_max_speed_bytes",
			metricName == "net_speed_bytes", metricName == "net_nspeed_bits":
			dev := telegrafIfaceFromLine(line)
			if val, ok := metricValue(line); ok {
				if bps := telegrafSpeedToBytes(metricName, val); dev != "" && bps > 0 && bps < SpeedUnknownBytes/2 {
					speeds[dev] = bps
				}
			}
		case metricName == "net_speed" || metricName == "ethtool_speed" || metricName == "ethtool_link_speed":
			dev := telegrafIfaceFromLine(line)
			if val, ok := metricValue(line); ok && val > 0 {
				if bps := telegrafSpeedToBytes(metricName, val); dev != "" && bps > 0 && bps < SpeedUnknownBytes/2 {
					speeds[dev] = bps
				}
			}
		case metricName == "net_bytes_recv":
			dev := telegrafIfaceFromLine(line)
			if dev != "" && !isVirtualIface(dev) {
				hasNetCounters = true
				if _, ok := oper[dev]; !ok {
					oper[dev] = "up"
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !hasNetCounters {
		return nil, nil
	}

	// Counter-only Telegraf (net input without speed field): show hit with per-NIC 10G estimate.
	if len(speeds) == 0 {
		speedEstimated = true
		for dev := range oper {
			speeds[dev] = 1.25e9 // 10 Gbit/s in bytes/s
		}
	}
	if len(speeds) == 0 {
		return nil, nil
	}

	report := analyze(speeds, map[string]string{}, oper, map[string]int{}, map[string]int{}, false)
	if report != nil {
		note := "Telegraf prometheus_client (net RX counters"
		if speedEstimated {
			note += ", link speed estimated — add net/ethtool speed for exact capacity"
		} else {
			note += " + link speed"
		}
		report.Notes = append([]string{note + ")"}, report.Notes...)
	}
	return report, nil
}

func getNetdataCapacity(client *http.Client, ip string, port int) (*CapacityReport, bool) {
	_ = client
	ndClient := &http.Client{Timeout: 5 * time.Second}

	var sb strings.Builder
	sb.Grow(64 + len(ip))
	sb.WriteString("http://")
	sb.WriteString(ip)
	sb.WriteByte(':')
	sb.WriteString(strconv.Itoa(port))
	sb.WriteString("/api/v1/allmetrics?format=prometheus")

	req, err := http.NewRequest("GET", sb.String(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")

	resp, err := ndClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, false
	}

	report, err := parseNetdataCapacity(io.LimitReader(resp.Body, 4<<20))
	if err != nil || report == nil || report.RealisticDstatGbps == 0 {
		return nil, false
	}
	return report, report.HasXDP
}

func parseNetdataCapacity(body io.Reader) (*CapacityReport, error) {
	speeds := map[string]float64{}
	oper := map[string]string{}

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		switch {
		case strings.Contains(line, "netdata_net_speed_kilobits_persec") && strings.Contains(line, `dimension="speed"`):
			dev := netdataDeviceFromLine(line)
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if val, ok := metricValue(line); ok && val > 0 && !isBogusSpeed(val) {
				speeds[dev] = val * 1000 / 8 // kilobits/s → bytes/s
			}
		case netdataSpeedNameRe.MatchString(line) || strings.Contains(line, "nic_speed_max"):
			dev := netdataDeviceFromLine(line)
			if dev == "" {
				if m := netdataLegacySpeedRe.FindStringSubmatch(line); len(m) == 2 {
					dev = m[1]
				}
			}
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if val, ok := metricValue(line); ok && val > 0 && !isBogusSpeed(val) {
				speeds[dev] = netdataSpeedToBytes(val)
			}
		case netdataOperNameRe.MatchString(line) || strings.Contains(line, "_operstate{"):
			dev := netdataDeviceFromLine(line)
			if dev == "" {
				if m := netdataLegacyOperRe.FindStringSubmatch(line); len(m) == 2 {
					dev = m[1]
				}
			}
			if dev == "" {
				continue
			}
			if val, ok := metricValue(line); ok {
				if val >= 1 {
					oper[dev] = "up"
				} else {
					oper[dev] = "down"
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(speeds) == 0 {
		return nil, nil
	}

	return analyze(speeds, map[string]string{}, oper, map[string]int{}, map[string]int{}, false), nil
}

func netdataDeviceFromLine(line string) string {
	for _, key := range []string{"device", "family", "dimension", "interface"} {
		if v := extractLabelString(line, key); v != "" && v != "speed" && v != "received" && v != "sent" {
			return v
		}
	}
	return ""
}

func netdataSpeedToBytes(val float64) float64 {
	if val <= 0 || isBogusSpeed(val) {
		return 0
	}
	// If val >= 50000, it is exported in kilobits/s. Otherwise in Megabits/s.
	if val >= 50000 {
		return val * 1000 / 8
	}
	return val * 1e6 / 8
}

func getSNMPCapacity(ip string) (*CapacityReport, bool) {
	for _, community := range snmpCommunities {
		report, ok := snmpProbe(ip, community)
		if ok {
			return report, false
		}
	}
	return nil, false
}

func snmpProbe(ip, community string) (*CapacityReport, bool) {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      uint16(portSNMP),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   2000 * time.Millisecond,
		Retries:   1,
		MaxOids:   60,
	}
	if err := snmp.Connect(); err != nil {
		return nil, false
	}
	defer snmp.Conn.Close()

	descrs, err := snmpBulkWalk(snmp, oidIfDescr)
	if err != nil || len(descrs) == 0 {
		return nil, false
	}
	speedsRaw, _ := snmpBulkWalk(snmp, oidIfSpeed)
	highSpeeds, _ := snmpBulkWalk(snmp, oidIfHighSpeed)
	macsRaw, _ := snmpBulkWalk(snmp, oidIfPhysAddr)

	speeds := map[string]float64{}
	macs := map[string]string{}
	oper := map[string]string{}

	for oid, pdu := range descrs {
		dev := snmpString(pdu)
		if dev == "" || isVirtualIface(dev) {
			continue
		}
		idx := snmpIndex(oid, oidIfDescr)
		if idx == "" {
			continue
		}

		speedBytes := snmpIfSpeedBytes(speedsRaw[oidIfSpeed+"."+idx], highSpeeds[oidIfHighSpeed+"."+idx])
		if speedBytes <= 0 || speedBytes >= SpeedUnknownBytes/2 {
			continue
		}
		if speedBytesToGbpsDecimal(speedBytes) < 0.9 {
			continue
		}
		speeds[dev] = speedBytes

		if macPDU, ok := macsRaw[oidIfPhysAddr+"."+idx]; ok {
			if mac := snmpMAC(macPDU); mac != "" {
				macs[dev] = mac
			}
		}
		oper[dev] = "up"
	}

	if len(speeds) == 0 {
		return nil, false
	}

	if !snmpCountersAvailable(snmp, descrs) {
		return nil, false
	}

	report := analyze(speeds, macs, oper, map[string]int{}, map[string]int{}, false)
	if report == nil || len(report.Interfaces) == 0 || (report.RealisticDstatGbps < 1.0 && report.TotalHardwareGbps < 1.0) {
		return nil, false
	}
	report.Notes = append([]string{"SNMP v2c (IF-MIB counters)"}, report.Notes...)
	return report, true
}

// snmpCountersAvailable returns true when IF-MIB exports RX byte counters
// (ifHCInOctets or ifInOctets) — required for bandwidth/pps like metrics/netdata.
func snmpCountersAvailable(snmp *gosnmp.GoSNMP, descrs map[string]gosnmp.SnmpPDU) bool {
	for oid, pdu := range descrs {
		dev := snmpString(pdu)
		if dev == "" || isVirtualIface(dev) {
			continue
		}
		idx := snmpIndex(oid, oidIfDescr)
		if idx == "" {
			continue
		}
		for _, base := range []string{oidIfHCInOctets, oidIfInOctets} {
			pkt, err := snmp.Get([]string{base + "." + idx})
			if err != nil {
				continue
			}
			for _, v := range pkt.Variables {
				if v.Type != gosnmp.NoSuchObject && v.Type != gosnmp.NoSuchInstance && v.Type != gosnmp.EndOfMibView {
					return true
				}
			}
		}
	}
	return false
}

func snmpBulkWalk(snmp *gosnmp.GoSNMP, baseOID string) (map[string]gosnmp.SnmpPDU, error) {
	out := map[string]gosnmp.SnmpPDU{}
	prefix := baseOID + "."
	next := baseOID

	for i := 0; i < 512; i++ {
		pkt, err := snmp.GetBulk([]string{next}, 0, 25)
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		if len(pkt.Variables) == 0 {
			break
		}
		advanced := false
		for _, v := range pkt.Variables {
			if v.Type == gosnmp.EndOfMibView || v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
				return out, nil
			}
			name := v.Name
			if strings.HasPrefix(name, ".") {
				name = name[1:]
			}
			if !strings.HasPrefix(name, prefix) {
				return out, nil
			}
			out[name] = v
			next = name
			advanced = true
		}
		if !advanced {
			break
		}
	}
	return out, nil
}

func snmpIndex(oid, base string) string {
	prefix := base + "."
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	if !strings.HasPrefix(oid, prefix) {
		return ""
	}
	return oid[len(prefix):]
}

func snmpString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimSpace(string(v))
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func snmpIfSpeedBytes(ifSpeedPDU, ifHighSpeedPDU gosnmp.SnmpPDU) float64 {
	if hs := snmpUint(ifHighSpeedPDU); hs > 0 {
		if hs == 4294967295 || hs == 65535 || hs > 800000 {
			return 0
		}
		return float64(hs) * 1e6 / 8
	}
	bps := snmpUint(ifSpeedPDU)
	if bps == 0 || bps == 4294967295 || bps == 65535 || bps > 800_000_000_000 {
		return 0
	}
	return float64(bps) / 8
}

func snmpUint(pdu gosnmp.SnmpPDU) uint64 {
	switch v := pdu.Value.(type) {
	case uint:
		return uint64(v)
	case uint32:
		return uint64(v)
	case uint64:
		return v
	case int:
		if v > 0 {
			return uint64(v)
		}
	case int64:
		if v > 0 {
			return uint64(v)
		}
	case []byte:
		n := gosnmp.ToBigInt(v)
		if n != nil && n.Sign() > 0 {
			return n.Uint64()
		}
	}
	return 0
}

func snmpMapLookup(m map[string]gosnmp.SnmpPDU, baseOID, idx string) (gosnmp.SnmpPDU, bool) {
	for _, key := range []string{baseOID + "." + idx, "." + baseOID + "." + idx} {
		if pdu, ok := m[key]; ok {
			return pdu, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

func snmpHasRxCounters(ip string) bool {
	for _, community := range snmpCommunities {
		snmp := &gosnmp.GoSNMP{
			Target:    ip,
			Port:      uint16(portSNMP),
			Community: community,
			Version:   gosnmp.Version2c,
			Timeout:   2500 * time.Millisecond,
			Retries:   1,
			MaxOids:   60,
		}
		if err := snmp.Connect(); err != nil {
			continue
		}
		descrs, err := snmpBulkWalk(snmp, oidIfDescr)
		ok := err == nil && len(descrs) > 0 && snmpCountersAvailable(snmp, descrs)
		snmp.Conn.Close()
		if ok {
			return true
		}
	}
	return false
}

func snmpCheckRxCounters(ip, community string) bool {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      uint16(portSNMP),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   2500 * time.Millisecond,
		Retries:   0,
		MaxOids:   60,
	}
	if err := snmp.Connect(); err != nil {
		return false
	}
	defer snmp.Conn.Close()

	descrs, err := snmpBulkWalk(snmp, oidIfDescr)
	if err != nil || len(descrs) == 0 {
		return false
	}
	return snmpCountersAvailable(snmp, descrs)
}

func snmpMAC(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		if len(v) != 6 {
			return ""
		}
		parts := make([]string, 6)
		for i, b := range v {
			parts[i] = fmt.Sprintf("%02x", b)
		}
		mac := strings.Join(parts, ":")
		if mac == "00:00:00:00:00:00" {
			return ""
		}
		return mac
	default:
		return ""
	}
}

// ── Protection classification ─────────────────────────────────────────────────

func classifyProtectionFromISP(ispLower string) (protEntry, bool) {
	check := func(m map[string]protEntry) (protEntry, bool) {
		return bestProtectionMatch(ispLower, "", m)
	}
	if e, ok := check(protectedMap); ok {
		return e, true
	}
	if e, ok := check(unprotectedMap); ok {
		return e, true
	}
	if e, ok := check(cloudMap); ok {
		return e, true
	}
	return protEntry{}, false
}

func classifyProtection(ispLower string, hostnames []string) protEntry {
	// Build hostname string without repeated allocation
	var sb strings.Builder
	for _, h := range hostnames {
		sb.WriteString(strings.ToLower(h))
		sb.WriteByte(' ')
	}
	hostStr := sb.String()

	check := func(m map[string]protEntry) (protEntry, bool) {
		return bestProtectionMatch(ispLower, hostStr, m)
	}

	if e, ok := check(protectedMap); ok {
		return e
	}
	if e, ok := check(unprotectedMap); ok {
		return e
	}
	if e, ok := check(cloudMap); ok {
		return e
	}
	return protEntry{status: "UNKNOWN", reason: "Unknown Status", clr: color.FgCyan}
}

func bestProtectionMatch(ispLower, hostLower string, m map[string]protEntry) (protEntry, bool) {
	bestLen := 0
	best := protEntry{}
	for k, v := range m {
		if strings.Contains(ispLower, k) || (hostLower != "" && strings.Contains(hostLower, k)) {
			if len(k) > bestLen {
				bestLen = len(k)
				best = v
			}
		}
	}
	if bestLen == 0 {
		return protEntry{}, false
	}
	return best, true
}

func isCloudISP(ispLower, countryLower string) bool {
	if countryLower == "china" {
		return true
	}
	for _, kw := range cloudISPKeywords {
		if strings.Contains(ispLower, kw) {
			return true
		}
	}
	return false
}

// ── IP info ───────────────────────────────────────────────────────────────────

var onlineClient = &http.Client{Timeout: 900 * time.Millisecond}

// Online lookup rate limiter: max 5 concurrent online API calls.
// Prevents flooding ip-api.com and getting rate-limited/banned.
var onlineSem = make(chan struct{}, 5)

// getIPInfoCached returns ISP and country for an IP, using /24 prefix cache.
func getIPInfoCached(ipStr string) (string, string) {
	prefix := ipTo24Prefix(ipStr)

	// Fast path: check cache first (lock-free read)
	if cached, ok := ispCache.Load(prefix); ok {
		e := cached.(ispCacheEntry)
		return e.isp, e.country
	}

	// Slow path: do the actual lookup
	isp, country := getIPInfo(ipStr)

	// Cache the result for the whole /24
	ispCache.Store(prefix, ispCacheEntry{isp: isp, country: country})
	return isp, country
}

func getIPInfo(ipStr string) (string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown", "Unknown"
	}

	var isp, country string

	if asnDB != nil {
		if rec, err := asnDB.ASN(ip); err == nil {
			isp = rec.AutonomousSystemOrganization
		}
	}
	if cityDB != nil {
		if rec, err := cityDB.City(ip); err == nil {
			country = rec.Country.Names["en"]
		}
	}

	allowOnline := envBool("DSTAT_ONLINE_IPINFO", false)

	// Optional online fallback. Disabled by default for high-speed scans.
	if allowOnline && (isp == "" || country == "") {
		select {
		case onlineSem <- struct{}{}:
			oISP, oCountry, ok := getIPInfoOnline(ipStr)
			<-onlineSem
			if ok {
				if isp == "" {
					isp = oISP
				}
				if country == "" {
					country = oCountry
				}
			}
		default:
			// Semaphore full — skip online lookup to avoid blocking
		}
	}

	if isp == "" {
		isp = "Unknown"
	}
	if country == "" {
		country = "Unknown"
	}
	return isp, country
}

func getIPInfoOnline(ipStr string) (string, string, bool) {
	if isp, c, err := queryIPAPI(ipStr); err == nil && isp != "" && c != "" {
		return isp, c, true
	}
	if isp, c, err := queryIPAPICo(ipStr); err == nil && isp != "" && c != "" {
		return isp, c, true
	}
	return "", "", false
}

func queryIPAPI(ipStr string) (string, string, error) {
	resp, err := onlineClient.Get("http://ip-api.com/json/" + ipStr)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var d struct {
		Status  string `json:"status"`
		ISP     string `json:"isp"`
		AS      string `json:"as"`
		Country string `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", "", err
	}
	if d.Status != "success" {
		return "", "", fmt.Errorf("ip-api: %s", d.Status)
	}
	isp := d.ISP
	if isp == "" {
		isp = d.AS
	}
	return isp, d.Country, nil
}

func queryIPAPICo(ipStr string) (string, string, error) {
	req, _ := http.NewRequest("GET", "https://ipapi.co/"+ipStr+"/json/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := onlineClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var d struct {
		Org         string `json:"org"`
		ASN         string `json:"asn"`
		CountryName string `json:"country_name"`
		Error       bool   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", "", err
	}
	if d.Error {
		return "", "", fmt.Errorf("ipapi.co error")
	}
	isp := d.Org
	if isp == "" {
		isp = d.ASN
	}
	return isp, d.CountryName, nil
}

// ── Reverse DNS ───────────────────────────────────────────────────────────────

func reverseDNSWithTimeout(ip string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
	return names
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isGarbage(line string) bool {
	low := strings.ToLower(line)
	for _, b := range garbageKeywords {
		if strings.Contains(low, b) {
			return true
		}
	}
	return false
}

func isScannerNoise(line string) bool {
	if isGarbage(line) {
		return true
	}
	low := strings.ToLower(strings.TrimSpace(line))
	for _, b := range scannerNoiseKeywords {
		if strings.Contains(low, b) {
			return true
		}
	}
	// zmap monitor / status noise (often via 2>&1|pipe or stderr on same TTY)
	if strings.Contains(low, "[warn]") && strings.Contains(low, "monitor:") {
		return true
	}
	if strings.Contains(low, "[error]") && strings.Contains(low, "blacklist:") {
		return true
	}
	return false
}

func classifyCategory(gbps float64) string {
	if gbps >= 100 {
		return "HIGH"
	}
	return "LOW"
}

// fmtBW formats bandwidth with NO trailing .00
// 400 → "400Gb"  |  1.5 → "1.5Gb"  |  1000 → "1Tb"  |  1200 → "1.2Tb"
func fmtBW(bw float64) string {
	if bw >= 1000 {
		tb := bw / 1000
		if tb == math.Trunc(tb) {
			return fmt.Sprintf("%dTb", int(tb))
		}
		return fmt.Sprintf("%.1fTb", tb)
	}
	if bw == math.Trunc(bw) {
		return fmt.Sprintf("%dGb", int(bw))
	}
	return fmt.Sprintf("%.1fGb", bw)
}

// dstatBandwidthPair returns (total chassis Gbps, servers.json label Gbps).
func dstatBandwidthPair(r *CapacityReport) (total, label float64) {
	if r == nil {
		return 0, 0
	}
	label = r.RealisticDstatGbps
	total = r.TotalHardwareGbps
	if total <= 0 {
		total = r.PrimaryPathGbps
	}
	if label <= 0 {
		label = total
	}
	if total <= 0 {
		total = label
	}
	return total, label
}

func fmtDstatBwSlash(r *CapacityReport) string {
	total, label := dstatBandwidthPair(r)
	if total > label*1.05 {
		return fmtBW(total) + " / " + fmtBW(label)
	}
	return fmtBW(label)
}

func bwBadgeDstat(r *CapacityReport) string {
	total, label := dstatBandwidthPair(r)
	sep := color.New(color.Faint).SprintFunc()
	if total > label*1.05 {
		return bwBadge(total) + sep(" / ") + bwBadge(label)
	}
	return bwBadge(label)
}

// bwBadgeDstatScan — scanner table: max bandwidth / list-as, both tier-colored.
func bwBadgeDstatScan(r *CapacityReport) string {
	total, label := dstatBandwidthPair(r)
	sep := color.New(color.Faint).SprintFunc()
	return bwBadge(total) + sep(" / ") + bwBadge(label)
}

func parseIPAndOptionalPort(raw string) (string, int) {
	if strings.Contains(raw, ":") {
		parts := strings.Split(raw, ":")
		ip := parts[0]
		portStr := parts[len(parts)-1]
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			return ip, p
		}
	}
	return raw, 0
}

// extractIPFromInputLine pulls an IPv4 from zmap csv/json or plain text lines.
func extractIPFromInputLine(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	for _, field := range strings.Split(raw, ",") {
		field = strings.Trim(field, " \"'")
		if ip := net.ParseIP(field); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	if strings.HasPrefix(raw, "{") {
		var rec struct {
			Saddr string `json:"saddr"`
			IP    string `json:"ip"`
		}
		if json.Unmarshal([]byte(raw), &rec) == nil {
			for _, s := range []string{rec.Saddr, rec.IP} {
				if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
					return ip.To4().String()
				}
			}
		}
	}
	if m := ipInLineRegex.FindString(raw); m != "" {
		if ip := net.ParseIP(m); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}

// ── Pretty print ──────────────────────────────────────────────────────────────

const ansiReset = "\033[0m"

// termBadge renders a fixed-width pill: dark 256-color bg + bright fg.
func termBadge(text string, bg256, fg256, width int) string {
	if width < len(text)+2 {
		width = len(text) + 2
	}
	pad := width - len(text)
	left := pad / 2
	right := pad - left
	inner := strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
	return fmt.Sprintf("\033[48;5;%dm\033[38;5;%dm\033[1m%s\033[0m", bg256, fg256, inner)
}

func protocolName(port int) string {
	switch port {
	case portNetdata:
		return "NETDATA"
	case portSNMP:
		return "SNMP"
	case portTelegraf:
		return "TELEGRAF"
	case portGlances:
		return "GLANCES"
	case portCAdvisor:
		return "CADVISOR"
	case portMetrics:
		return "METRICS"
	default:
		return "UNKNOWN"
	}
}

func protocolBadge(port int) string {
	switch port {
	case portNetdata:
		// violet — streaming / dashboard
		return termBadge("NETDATA", 53, 183, 9)
	case portSNMP:
		// amber — network management
		return termBadge("SNMP", 130, 223, 9)
	case portTelegraf:
		// rose — distinct from metrics teal
		return termBadge("TELEGRAF", 168, 218, 9)
	case portGlances:
		return termBadge("GLANCES", 61, 189, 9)
	case portCAdvisor:
		return termBadge("CADVISOR", 95, 220, 9)
	case portMetrics:
		// teal — prometheus / node_exporter
		return termBadge("METRICS", 24, 87, 9)
	default:
		return termBadge("???", 238, 245, 9)
	}
}

func categoryBadge(cat string) string {
	if cat == "HIGH" {
		return termBadge("HIGH", 52, 196, 5)
	}
	return termBadge("LOW", 236, 245, 5)
}

// formatLogEntry writes a plain-text line matching console fields for dstats.txt / big.txt.
func formatLogEntry(r Result) string {
	var b strings.Builder
	b.Grow(320)
	b.WriteString("[")
	b.WriteString(r.Category)
	b.WriteString("] [")
	b.WriteString(r.Protocol)
	b.WriteString("] [")
	b.WriteString(r.ProtectionStatus)
	b.WriteString("] ")
	b.WriteString(r.IP)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(r.Port))
	b.WriteString(" → ")
	b.WriteString(fmtDstatBwSlash(&CapacityReport{
		RealisticDstatGbps: r.Bandwidth,
		TotalHardwareGbps:  r.TotalCapacityGbps,
	}))
	if r.HasBonding {
		b.WriteString(" bond:")
		b.WriteString(r.PrimaryDevice)
	} else if r.PrimaryDevice != "" {
		b.WriteString(" dev:")
		b.WriteString(r.PrimaryDevice)
	}
	b.WriteString(" | ")
	b.WriteString(r.ISP)
	b.WriteString(" · ")
	b.WriteString(r.Country)
	if r.ProtectionReason != "" && r.ProtectionReason != "Unknown Status" {
		b.WriteString(" | ")
		b.WriteString(r.ProtectionReason)
	}
	if r.HasXDP {
		b.WriteString(" | XDP")
	}
	if r.IndependentUplinks > 0 {
		b.WriteString(" | uplinks:")
		b.WriteString(strconv.Itoa(r.IndependentUplinks))
	}
	b.WriteByte('\n')
	return b.String()
}

func writeTxtHeaderIfEmpty(f *os.File, w *asyncWriter) {
	if fi, err := f.Stat(); err == nil && fi.Size() == 0 {
		w.Write("# [CATEGORY] [PROTOCOL] [PROTECTION] ip:port → bw hw:bw bond:dev | ISP · Country | reason | XDP | uplinks:N\n")
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func printResult(ip string, port int, cap *CapacityReport, isp, country string, xdp bool, cat string, p protEntry) {
	dim := color.New(color.Faint).SprintFunc()
	ipClr := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	sep := color.New(color.Faint).Sprint("·")

	ipPort := ipClr(fmt.Sprintf("%s:%d", ip, port))
	bw := bwBadgeDstatScan(cap)
	loc := dim(truncateText(isp, 28) + " " + sep + " " + country)

	extra := ""
	if cap.HasBonding {
		extra += dim(fmt.Sprintf("  [%s]", cap.PrimaryDevice))
	}
	if xdp {
		extra += " " + termBadge("XDP", 94, 214, 6)
	}

	fmt.Printf("  %s %s %s  %s  %s%s  %s\n",
		categoryBadge(cat),
		protocolBadge(port),
		protBadge(p.status),
		ipPort,
		bw,
		extra,
		loc)
}

// bwBadge: muted gradient by bandwidth tier.
func bwBadge(bw float64) string {
	label := fmtBW(bw)
	switch {
	case bw >= 100:
		return termBadge(label, 52, 196, 7)
	case bw >= 50:
		return termBadge(label, 52, 203, 7)
	case bw >= 30:
		return termBadge(label, 94, 208, 7)
	case bw >= 10:
		return termBadge(label, 58, 221, 7)
	default:
		return termBadge(label, 22, 114, 7)
	}
}

// protBadge: protection status pill.
func protBadge(status string) string {
	switch status {
	case "PROTECTED":
		return termBadge("PROTECTED", 52, 203, 13)
	case "UNPROTECTED":
		return termBadge("UNPROTECTED", 22, 119, 13)
	case "PARTIAL":
		return termBadge("PARTIAL", 58, 179, 13)
	default:
		return termBadge("UNKNOWN", 237, 244, 13)
	}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cidrIPCount(ipnet *net.IPNet) int64 {
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return 0
	}
	exponent := bits - ones
	if exponent >= 62 {
		return math.MaxInt64
	}
	return 1 << exponent
}

// ── Capacity analysis (passive, no attack) ─────────────────────────────────

const (
	SpeedUnknownBytes = 536_870_911_875_000.0
	// 800G NICs exist in production; single port above 800G is an overflow/wraparound.
	MaxSaneGbps       = 800.0
)

func isBogusSpeed(val float64) bool {
	if val <= 0 {
		return true
	}
	// Check known 32-bit / 16-bit wraparound error markers (SPEED_UNKNOWN = -1 = 4294967295)
	if (val >= 4294967000 && val <= 4294968000) || val == 65535 || val == 18446744073709551615 {
		return true
	}
	// Anything > 800 Gbps (100 GB/s) in raw bytes/s is a misread
	if val > 100_000_000_000 {
		return true
	}
	return false
}

type BondInfo struct {
	Master     string
	Slaves     int
	Active     int
	SpeedGbps  float64
	MemberGbps float64 // max member link speed (single-flow ceiling per bond)
	SlaveDevs  []string
}

type InterfaceInfo struct {
	Device     string
	MAC        string
	SpeedGbps  float64
	SpeedBytes float64
	IsBond     bool
	IsSlave    bool
	IsVirtual  bool
	OperState  string
}

// CapacityReport is the passive capacity analysis for a dstat host.
type CapacityReport struct {
	// RealisticDstatGbps — recommended label for single-IP / typical single-flow attacks.
	RealisticDstatGbps float64
	// TotalHardwareGbps — deduped sum of all independent uplinks (no double-counting bond slaves).
	TotalHardwareGbps float64
	// PrimaryPathGbps — rated speed of the main ingress path (usually largest bond or NIC).
	PrimaryPathGbps float64
	// MaxSingleNicGbps — legacy scanner behavior (max one interface speed).
	MaxSingleNicGbps float64
	// SingleFlowBondGbps — if bonded, max throughput for one LACP/Balance-xor flow.
	SingleFlowBondGbps float64

	HasBonding         bool
	BondCount          int
	IndependentUplinks int
	Bondings           []BondInfo
	Interfaces         []InterfaceInfo
	PrimaryDevice      string
	Notes              []string
	HasXDP             bool
}

// parseHostCapacity reads Prometheus text exposition and returns capacity analysis.
func parseHostCapacity(body io.Reader) (*CapacityReport, error) {
	speeds := map[string]float64{}
	macs := map[string]string{}
	oper := map[string]string{}
	bondSlaves := map[string]int{}
	bondActive := map[string]int{}
	hasXDP := false

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if !hasXDP && (strings.Contains(line, "ebpf_") || strings.Contains(line, "xdp_")) {
			hasXDP = true
		}

		switch {
		case strings.HasPrefix(line, "node_network_speed_bytes{"):
			dev, val := extractLabelAndValue(line, "device")
			if dev != "" && val > 0 && val < SpeedUnknownBytes/2 && (val*8)/1e9 >= 0.9 {
				speeds[dev] = val
			}
		case strings.HasPrefix(line, "node_network_info{"):
			dev := extractLabelString(line, "device")
			addr := extractLabelString(line, "address")
			op := extractLabelString(line, "operstate")
			if dev != "" {
				if addr != "" && addr != "00:00:00:00:00:00" {
					macs[dev] = strings.ToLower(addr)
				}
				if op != "" {
					oper[dev] = op
				}
			}
		case strings.HasPrefix(line, "node_bonding_slaves{"):
			master := extractLabelString(line, "master")
			if master != "" {
				if v, ok := metricValue(line); ok {
					bondSlaves[master] = int(v)
				}
			}
		case strings.HasPrefix(line, "node_bonding_active{"):
			master := extractLabelString(line, "master")
			if master != "" {
				if v, ok := metricValue(line); ok {
					bondActive[master] = int(v)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(speeds) == 0 {
		return nil, nil
	}

	return analyze(speeds, macs, oper, bondSlaves, bondActive, hasXDP), nil
}

func analyze(
	speeds map[string]float64,
	macs map[string]string,
	oper map[string]string,
	bondSlaves map[string]int,
	bondActive map[string]int,
	hasXDP bool,
) *CapacityReport {
	r := &CapacityReport{HasXDP: hasXDP}

	// Bond master MACs → mark slaves (same MAC, not bond name).
	bondMasterMACs := map[string]bool{}
	for dev := range speeds {
		if isBondMaster(dev) {
			if mac, ok := macs[dev]; ok {
				bondMasterMACs[mac] = true
			}
		}
	}

	slaveSet := map[string]bool{}
	for dev, mac := range macs {
		if isBondMaster(dev) {
			continue
		}
		if bondMasterMACs[mac] {
			slaveSet[dev] = true
		}
	}

	// Collect interface metadata.
	type uplink struct {
		dev       string
		gbps      float64
		isBond    bool
		isSlave   bool
		isVirtual bool
		mac       string
	}
	var uplinks []uplink
	maxSingle := 0.0

	for dev, speedBytes := range speeds {
		virtual := isVirtualIface(dev)
		slave := slaveSet[dev]
		if isBogusSpeed(speedBytes) {
			if !virtual && !slave {
				low := strings.ToLower(dev)
				if strings.HasPrefix(low, "eth") || strings.HasPrefix(low, "ens") || strings.HasPrefix(low, "enp") || strings.HasPrefix(low, "eno") {
					speedBytes = 1e9 / 8 // Default to realistic 1Gbps for standard physical NICs
				} else {
					continue
				}
			} else {
				continue
			}
		}

		gbps := speedBytesToGbpsDecimal(speedBytes)
		if gbps > MaxSaneGbps {
			low := strings.ToLower(dev)
			if strings.HasPrefix(low, "eth") || strings.HasPrefix(low, "ens") || strings.HasPrefix(low, "enp") || strings.HasPrefix(low, "eno") {
				gbps = 1.0
				speedBytes = 1e9 / 8
			} else {
				continue
			}
		}

		if !virtual && !slave && !isBondMaster(dev) && gbps > maxSingle {
			maxSingle = gbps
		}

		uplinks = append(uplinks, uplink{
			dev: dev, gbps: gbps, isBond: isBondMaster(dev), isSlave: slave,
			isVirtual: virtual, mac: macs[dev],
		})

		r.Interfaces = append(r.Interfaces, InterfaceInfo{
			Device: dev, MAC: macs[dev], SpeedGbps: gbps, SpeedBytes: speedBytes,
			IsBond: isBondMaster(dev), IsSlave: slave, IsVirtual: virtual, OperState: oper[dev],
		})
	}
	r.MaxSingleNicGbps = maxSingle

	// Bond details + per-bond member speeds.
	bondMembers := map[string][]float64{}
	for _, u := range uplinks {
		if u.isSlave && u.gbps > 0 {
			for master := range bondSlaves {
				if mac, ok := macs[master]; ok && mac == u.mac {
					bondMembers[master] = append(bondMembers[master], u.gbps)
				}
			}
		}
	}

	seenMAC := map[string]bool{}
	rawSum := 0.0
	bondSum := 0.0
	var indepSpeeds []float64
	independent := 0
	var primaryBond *BondInfo
	primaryBondGbps := 0.0
	singleFlowBondMax := 0.0

	for dev, speedBytes := range speeds {
		if isVirtualIface(dev) || slaveSet[dev] {
			continue
		}
		if isBogusSpeed(speedBytes) {
			low := strings.ToLower(dev)
			if strings.HasPrefix(low, "eth") || strings.HasPrefix(low, "ens") || strings.HasPrefix(low, "enp") || strings.HasPrefix(low, "eno") {
				speedBytes = 1e9 / 8
			} else {
				continue
			}
		}
		gbps := speedBytesToGbpsDecimal(speedBytes)
		if gbps <= 0 || gbps > MaxSaneGbps {
			low := strings.ToLower(dev)
			if strings.HasPrefix(low, "eth") || strings.HasPrefix(low, "ens") || strings.HasPrefix(low, "enp") || strings.HasPrefix(low, "eno") {
				gbps = 1.0
			} else {
				continue
			}
		}
		if mac := macs[dev]; mac != "" {
			if seenMAC[mac] {
				continue
			}
			seenMAC[mac] = true
		}

		rawSum += gbps

		if isBondMaster(dev) {
			bondSum += gbps
			r.HasBonding = true
			r.BondCount++
			members := bondMembers[dev]
			memberMax := 0.0
			for _, m := range members {
				if m > memberMax {
					memberMax = m
				}
			}
			if memberMax == 0 {
				// Fallback: bond rated / slave count
				slaves := bondSlaves[dev]
				if slaves > 0 {
					memberMax = gbps / float64(slaves)
				} else {
					memberMax = gbps
				}
			}
			if memberMax > singleFlowBondMax {
				singleFlowBondMax = memberMax
			}

			bi := BondInfo{
				Master: dev, Slaves: bondSlaves[dev], Active: bondActive[dev],
				SpeedGbps: gbps, MemberGbps: memberMax,
			}
			r.Bondings = append(r.Bondings, bi)
			if gbps > primaryBondGbps {
				primaryBondGbps = gbps
				b := bi
				primaryBond = &b
				r.PrimaryDevice = dev
			}
		} else if isPhysicalIface(dev) {
			independent++
			indepSpeeds = append(indepSpeeds, gbps)
		}
	}
	r.TotalHardwareGbps = computeTotalHardwareGbps(bondSum, rawSum, indepSpeeds, independent)
	r.IndependentUplinks = independent
	r.SingleFlowBondGbps = singleFlowBondMax
	sort.Slice(r.Bondings, func(i, j int) bool { return r.Bondings[i].SpeedGbps > r.Bondings[j].SpeedGbps })

	// Primary path = largest bond or largest independent NIC.
	primaryPath := 0.0
	if primaryBond != nil {
		primaryPath = primaryBond.SpeedGbps
		r.Notes = append(r.Notes, sprintfBondNote(*primaryBond))
	} else {
		for _, u := range uplinks {
			if !u.isVirtual && !u.isSlave && !u.isBond && u.gbps > primaryPath {
				primaryPath = u.gbps
				r.PrimaryDevice = u.dev
			}
		}
	}
	r.PrimaryPathGbps = primaryPath

	// Realistic single-IP dstat capacity:
	// - Bonded: one flow ≈ one member link speed (LACP hashes per-flow).
	// - If only independent NICs: max single NIC (traffic to one IP uses one route).
	// - Never exceed primary path rated speed.
	realistic := primaryPath
	if r.HasBonding && singleFlowBondMax > 0 {
		realistic = singleFlowBondMax
		r.Notes = append(r.Notes, "LACP/bond: typical single-flow attack uses ~1 member link (~"+formatGbps(singleFlowBondMax)+")")
	} else if !r.HasBonding && maxSingle > 0 {
		realistic = maxSingle
	}
	if independent > 0 && r.TotalHardwareGbps > primaryPath*1.5 {
		r.Notes = append(r.Notes, sprintf("This host has %d extra NICs (~%s total) — you need multiple IPs to use all of it", independent, formatGbps(r.TotalHardwareGbps)))
	}
	if rawSum > r.TotalHardwareGbps*2 && independent > 3 {
		r.Notes = append(r.Notes, sprintf("NIC speeds add up to ~%s but this host can really use about ~%s", formatGbps(rawSum), formatGbps(r.TotalHardwareGbps)))
	}
	r.RealisticDstatGbps = realistic

	return r
}

// AggregateRates combines per-interface RX rates (bytes/sec) without double-counting bond slaves.
// Matches the Node.js dstat dashboard logic (binary Gbps).
type IfRate struct {
	Device    string
	BytesPs   float64
	PacketsPs float64
}

type AggregateResult struct {
	BytesPs        float64
	PacketsPs      float64
	GbpsBinary     float64
	Mpps           float64
	Mode           string
	Interfaces     []IfRate
	Countable      []IfRate
	ExcludedSlaves []string
}

func aggregateRates(rates []IfRate, macs map[string]string, configuredGbps float64, totalHardwareGbps float64) AggregateResult {
	slaves := buildBondSlaveSet(macs)
	var preDedup []IfRate
	var excluded []string

	for _, r := range rates {
		if isVirtualIface(r.Device) {
			continue
		}
		if slaves[r.Device] {
			excluded = append(excluded, r.Device)
			continue
		}
		preDedup = append(preDedup, r)
	}

	// Same MAC = same physical port (alias / macvlan / passthrough, e.g. "bootnet"
	// mirroring "enp157s0f0np0"). Keep the highest-rate one per MAC so summing
	// independent uplinks never double-counts a single port.
	countable := dedupeRatesByMac(preDedup, macs, &excluded)

	maxBw, maxPkt := 0.0, 0.0
	sumBw, sumPkt := 0.0, 0.0
	active := 0
	for _, r := range countable {
		if r.BytesPs > maxBw {
			maxBw = r.BytesPs
		}
		if r.PacketsPs > maxPkt {
			maxPkt = r.PacketsPs
		}
		sumBw += r.BytesPs
		sumPkt += r.PacketsPs
	}
	for _, r := range countable {
		if r.BytesPs > maxBw*0.15 && r.BytesPs > 0 {
			active++
		}
	}

	effectiveCap := totalHardwareGbps
	if configuredGbps > effectiveCap {
		effectiveCap = configuredGbps
	}
	highCap := effectiveCap > 100
	spread := active >= 2 && sumBw > maxBw*1.12
	useSum := highCap || spread
	if !highCap && active <= 1 {
		useSum = false
	}

	bw := maxBw
	pkt := maxPkt
	mode := "max"
	if useSum {
		bw = sumBw
		pkt = sumPkt
		if highCap {
			mode = "sum-capacity"
		} else {
			mode = "sum-spread"
		}
	}
	if useSum && effectiveCap > 0 && bytesPsToGbpsBinary(bw) > effectiveCap*1.35 {
		bw = maxBw
		pkt = maxPkt
		mode = "max-fallback"
	}

	return AggregateResult{
		BytesPs: bw, PacketsPs: pkt,
		GbpsBinary:     bytesPsToGbpsBinary(bw),
		Mpps:           pkt / 1e6,
		Mode:           mode,
		Interfaces:     rates,
		Countable:      countable,
		ExcludedSlaves: excluded,
	}
}

// Snapshot holds counter values for delta rate calculation.
type MetricsSnapshot struct {
	Time      float64
	RxBytes   map[string]float64
	RxPackets map[string]float64
	MACs      map[string]string
}

// FetchSnapshot pulls current counters + topology from node_exporter metrics body.
func parseMetricsSnapshot(body io.Reader) (*MetricsSnapshot, error) {
	s := &MetricsSnapshot{
		RxBytes:   map[string]float64{},
		RxPackets: map[string]float64{},
		MACs:      map[string]string{},
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "node_network_receive_bytes_total{"):
			dev, val := extractLabelAndValue(line, "device")
			if dev != "" {
				s.RxBytes[dev] = val
			}
		case strings.HasPrefix(line, "node_network_receive_packets_total{"):
			dev, val := extractLabelAndValue(line, "device")
			if dev != "" {
				s.RxPackets[dev] = val
			}
		case strings.HasPrefix(line, "node_network_info{"):
			dev := extractLabelString(line, "device")
			addr := extractLabelString(line, "address")
			if dev != "" && addr != "" && addr != "00:00:00:00:00:00" {
				s.MACs[dev] = strings.ToLower(addr)
			}
		}
	}
	return s, sc.Err()
}

func parseTelegrafSnapshot(body io.Reader) (*MetricsSnapshot, error) {
	s := &MetricsSnapshot{
		RxBytes:   map[string]float64{},
		RxPackets: map[string]float64{},
		MACs:      map[string]string{},
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		metricName := line
		if idx := strings.Index(line, "{"); idx > 0 {
			metricName = line[:idx]
		}
		switch metricName {
		case "net_bytes_recv":
			dev := telegrafIfaceFromLine(line)
			if dev != "" {
				if val, ok := metricValue(line); ok {
					s.RxBytes[dev] = val
				}
			}
		case "net_packets_recv":
			dev := telegrafIfaceFromLine(line)
			if dev != "" {
				if val, ok := metricValue(line); ok {
					s.RxPackets[dev] = val
				}
			}
		}
	}
	return s, sc.Err()
}

func isValidTelegrafSnapshot(snap *MetricsSnapshot) bool {
	if snap == nil {
		return false
	}
	return len(snap.RxBytes) > 0
}

// RatesFromDelta computes per-interface bytes/s and packets/s from two snapshots.
func ratesFromDelta(prev, cur *MetricsSnapshot) []IfRate {
	dt := cur.Time - prev.Time
	if dt <= 0 || dt > 60 {
		return nil
	}
	devices := map[string]bool{}
	for d := range cur.RxBytes {
		devices[d] = true
	}
	var rates []IfRate
	for dev := range devices {
		if isVirtualIface(dev) {
			continue
		}
		pb, pok := prev.RxBytes[dev]
		cb := cur.RxBytes[dev]
		pp := prev.RxPackets[dev]
		cp := cur.RxPackets[dev]
		if !pok {
			continue
		}
		bps := (cb - pb) / dt
		pps := (cp - pp) / dt
		if bps < 0 {
			bps = 0
		}
		if pps < 0 {
			pps = 0
		}
		if bps > 0 || pps > 0 {
			if bps > 1e7 && pps == 0 {
				pps = bps / (1200 * 8)
			}
			rates = append(rates, IfRate{Device: dev, BytesPs: bps, PacketsPs: pps})
		}
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].BytesPs > rates[j].BytesPs })
	return rates
}

// dedupeRatesByMac keeps only the highest-rate interface per MAC. Interfaces with no
// known MAC are always kept. Dropped duplicates are appended to *excluded for display.
func dedupeRatesByMac(rates []IfRate, macs map[string]string, excluded *[]string) []IfRate {
	sorted := make([]IfRate, len(rates))
	copy(sorted, rates)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].BytesPs > sorted[j].BytesPs })

	seen := map[string]bool{}
	var out []IfRate
	for _, r := range sorted {
		mac := macs[r.Device]
		if mac != "" {
			if seen[mac] {
				if excluded != nil {
					*excluded = append(*excluded, r.Device)
				}
				continue
			}
			seen[mac] = true
		}
		out = append(out, r)
	}
	return out
}

func buildBondSlaveSet(macs map[string]string) map[string]bool {
	bondMACs := map[string]bool{}
	for dev, mac := range macs {
		if isBondMaster(dev) {
			bondMACs[mac] = true
		}
	}
	slaves := map[string]bool{}
	for dev, mac := range macs {
		if isBondMaster(dev) {
			continue
		}
		if bondMACs[mac] {
			slaves[dev] = true
		}
	}
	return slaves
}

// computeTotalHardwareGbps estimates real chassis capacity.
func computeTotalHardwareGbps(bondSum, rawSum float64, indepSpeeds []float64, independentCount int) float64 {
	if rawSum <= 0 {
		return 0
	}
	if bondSum > 0 {
		indepSum := 0.0
		for _, s := range indepSpeeds {
			indepSum += s
		}
		return bondSum + indepSum
	}
	return rawSum
}

func isBondMaster(dev string) bool {
	return strings.HasPrefix(dev, "bond") || strings.HasPrefix(dev, "team")
}

func isVirtualIface(dev string) bool {
	low := strings.ToLower(strings.TrimSpace(dev))
	if low == "" || low == "lo" || strings.Contains(low, "loopback") || strings.Contains(low, "vlan") || strings.Contains(low, ".") {
		return true
	}
	prefixes := []string{
		"veth", "docker", "br-", "vbr", "vxlan", "cali", "dummy", "lxc",
		"flannel", "cni", "tun", "tap", "wg", "kube", "tailscale", "cni0",
		"wlan", "wifi", "ath", "ra", "wl", "ppp", "nas", "cellular", "modem",
		"bridge", "gre", "sit", "ip6tnl", "dummy", "virbr", "vmnet",
		"ovs-", "ovs_", "vmbr", "macvlan", "macvtap", "erspan", "geneve",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	if strings.Contains(low, "wireless") || strings.HasPrefix(low, "wlan ") || strings.HasPrefix(low, "lan interface") {
		return true
	}
	return false
}

func isPhysicalIface(dev string) bool {
	return !isVirtualIface(dev) && !isBondMaster(dev)
}

func speedBytesToGbpsDecimal(b float64) float64 {
	return (b * 8) / 1e9
}

func bytesPsToGbpsBinary(b float64) float64 {
	return (b * 8) / (1024 * 1024 * 1024)
}

func extractLabelString(line, label string) string {
	marker := label + `="`
	idx := strings.Index(line, marker)
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	end := strings.IndexByte(line[start:], '"')
	if end == -1 {
		return ""
	}
	return line[start : start+end]
}

func extractLabelAndValue(line, label string) (string, float64) {
	dev := extractLabelString(line, label)
	v, ok := metricValue(line)
	if !ok {
		return dev, 0
	}
	return dev, v
}

func metricValue(line string) (float64, bool) {
	// Prometheus text: name{labels} value [timestamp]
	brace := strings.LastIndexByte(line, '}')
	if brace != -1 {
		fields := strings.Fields(strings.TrimSpace(line[brace+1:]))
		if len(fields) > 0 {
			v, err := strconv.ParseFloat(fields[0], 64)
			return v, err == nil
		}
	}
	idx := strings.LastIndexByte(line, ' ')
	if idx == -1 || idx >= len(line)-1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+1:]), 64)
	return v, err == nil
}

func sprintfBondNote(b BondInfo) string {
	return sprintf("bond %s: %s rated, %d slave(s), %d active — single-flow ~%s",
		b.Master, formatGbps(b.SpeedGbps), b.Slaves, b.Active, formatGbps(b.MemberGbps))
}

func formatGbps(g float64) string {
	if g == math.Trunc(g) {
		return sprintf("%.0fG", g)
	}
	return sprintf("%.1fG", g)
}

func sprintf(format string, args ...interface{}) string {
	return strings.TrimSpace(fmtSprintf(format, args...))
}

func fmtSprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

const monitorPollInterval = time.Second
const monitorLiveLines = 8

// runTrafficMonitor: <bin> monitor <ip> [port|metrics|netdata|telegraf|snmp|glances|cadvisor]
func runTrafficMonitor(args []string) {
	bin := programBin()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s monitor <ip> [port|metrics|netdata|telegraf|snmp|glances|cadvisor]\n", bin)
		os.Exit(1)
	}
	ip := args[0]
	port := portMetrics
	autoDetected := ""
	if len(args) >= 2 {
		port = parseMonitorPortArg(args[1])
		if port == 0 {
			fmt.Fprintf(os.Stderr, "Invalid port/source: %q\n", args[1])
			os.Exit(1)
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	ui := newMonitorUI()

	if len(args) < 2 {
		if p, desc := detectMonitorProtocol(client, ip); p != 0 {
			port = p
			autoDetected = desc
		}
	}

	if port == portSNMP && !snmpHasRxCounters(ip) {
		ui.printErr("SNMP on %s:%d exposes link speeds only — no IF-MIB RX counters for live traffic", ip, portSNMP)
		ui.printErr("This host cannot be live-monitored via SNMP (common on Alibaba Cloud / minimal agents)")
		if p, desc := detectMonitorProtocol(client, ip); p != 0 && p != portSNMP {
			ui.printErr("Try instead: %s monitor %s %s", bin, ip, monitorProtocolArg(p))
			_ = desc
		} else {
			ui.printErr("Install node_exporter (:9100) or Netdata (:19999) on the target for live monitor")
		}
		os.Exit(1)
	}

	capReport, _ := getHostCapacity(client, ip, port)
	if capReport == nil || len(capReport.Interfaces) == 0 || (capReport.RealisticDstatGbps <= 0 && capReport.TotalHardwareGbps <= 0) {
		ui.printErr("Cannot monitor %s:%d — no usable network interfaces found", ip, port)
		os.Exit(1)
	}

	ui.printBanner(ip, port)
	if autoDetected != "" {
		fmt.Println("  " + ui.muted("Found: "+autoDetected))
	}
	ui.printCapacity(capReport)

	ui.printMonitorFooter()

	ratesDirect := port == portNetdata || port == portGlances
	useDelta := !ratesDirect
	var prev *MetricsSnapshot
	if useDelta {
		var err error
		prev, err = fetchMonitorSnapshot(client, ip, port)
		if err != nil {
			ui.printErr("Cannot reach target: %v", err)
			os.Exit(1)
		}
	} else if port == portGlances {
		if _, _, err := fetchGlancesLiveRates(client, ip, port); err != nil {
			ui.printErr("Cannot reach Glances: %v", err)
			os.Exit(1)
		}
	} else if port == portCAdvisor {
		if _, err := fetchCAdvisorSnapshot(client, ip, port); err != nil {
			ui.printErr("Cannot reach cAdvisor: %v", err)
			os.Exit(1)
		}
	} else if _, _, err := fetchNetdataLiveRates(client, ip, port); err != nil {
		ui.printErr("Cannot reach Netdata: %v", err)
		os.Exit(1)
	}
	time.Sleep(monitorPollInterval)

	state := &monitorState{
		peakGbps:    0,
		peakMpps:    0,
		ceilingGbps: 100.0,
	}
	if capReport != nil {
		state.ceilingGbps = capReport.RealisticDstatGbps
		if state.ceilingGbps <= 0 {
			state.ceilingGbps = capReport.PrimaryPathGbps
		}
	}

	ui.drawLivePanel(state, nil, "Waiting for traffic…")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.Tick(monitorPollInterval)

	for {
		select {
		case <-sig:
			ui.clearLiveArea()
			ui.printPeakSummary(state)
			return
		case <-tick:
			var rates []IfRate
			var macs map[string]string
			var err error

			if port == portNetdata {
				rates, macs, err = fetchNetdataLiveRates(client, ip, port)
			} else if port == portGlances {
				rates, macs, err = fetchGlancesLiveRates(client, ip, port)
			} else if port == portCAdvisor {
				cur, fetchErr := fetchCAdvisorSnapshot(client, ip, port)
				if fetchErr != nil {
					err = fetchErr
				} else {
					key := fmt.Sprintf("cadvisor:%s:%d", ip, port)
					prevRaw, _ := monitorPrev.Load(key)
					var prev *MetricsSnapshot
					if prevRaw != nil {
						prev, _ = prevRaw.(*MetricsSnapshot)
					}
					monitorPrev.Store(key, cur)
					if prev != nil {
						rates = ratesFromDelta(prev, cur)
						macs = cur.MACs
					}
				}
			} else {
				cur, fetchErr := fetchMonitorSnapshot(client, ip, port)
				if fetchErr != nil {
					err = fetchErr
				} else {
					rates = ratesFromDelta(prev, cur)
					macs = cur.MACs
					prev = cur
				}
			}
			if err != nil {
				ui.drawLivePanel(state, nil, fmt.Sprintf("Fetch error: %v", err))
				continue
			}

			totalHW := 0.0
			if capReport != nil {
				totalHW = capReport.TotalHardwareGbps
			}
			agg := aggregateRates(rates, macs, 0, totalHW)

			if agg.GbpsBinary > state.peakGbps {
				state.peakGbps = agg.GbpsBinary
				state.peakMpps = agg.Mpps
				state.peakMode = agg.Mode
				state.peakDetail = formatTopIfaces(agg.Countable, 6)
			}
			state.lastAgg = &agg
			state.lastTime = time.Now()

			ui.drawLivePanel(state, &agg, "")
		}
	}
}

func monitorProtocolArg(port int) string {
	switch port {
	case portNetdata:
		return "netdata"
	case portTelegraf:
		return "telegraf"
	case portSNMP:
		return "snmp"
	case portGlances:
		return "glances"
	case portCAdvisor:
		return "cadvisor"
	default:
		return "metrics"
	}
}

func detectMonitorProtocol(client *http.Client, ip string) (int, string) {
	url := fmt.Sprintf("http://%s:%d/metrics", ip, portMetrics)
	if snap, err := fetchMetricsSnapshot(client, url); err == nil && isValidNodeExporterSnapshot(snap) {
		return portMetrics, "node_exporter /metrics on :9100"
	}
	tgURL := fmt.Sprintf("http://%s:%d/metrics", ip, portTelegraf)
	if snap, err := fetchTelegrafSnapshot(client, tgURL); err == nil && isValidTelegrafSnapshot(snap) {
		return portTelegraf, "Telegraf prometheus_client on :9273"
	}
	if _, _, err := fetchNetdataLiveRates(client, ip, portNetdata); err == nil {
		return portNetdata, "Netdata Prometheus API on :19999"
	}
	if snmpHasRxCounters(ip) {
		return portSNMP, "SNMP v2c IF-MIB counters on :161"
	}
	if _, _, err := fetchGlancesLiveRates(client, ip, portGlances); err == nil {
		return portGlances, "Glances REST API on :61208"
	}
	if snap, err := fetchCAdvisorSnapshot(client, ip, portCAdvisor); err == nil && len(snap.RxBytes) > 0 {
		return portCAdvisor, "cAdvisor /metrics + /api/v2.0/machine on :8080"
	}
	return 0, ""
}

func isValidNodeExporterSnapshot(snap *MetricsSnapshot) bool {
	if snap == nil {
		return false
	}
	return len(snap.RxBytes) > 0 || len(snap.MACs) > 0
}

func parseMonitorPortArg(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "metrics", "node", "9100":
		return portMetrics
	case "netdata", "19999":
		return portNetdata
	case "telegraf", "9273":
		return portTelegraf
	case "snmp", "161", "udp", "udp161", "udp:161", "pu:161":
		return portSNMP
	case "glances", "61208":
		return portGlances
	case "cadvisor", "8080":
		return portCAdvisor
	default:
		p, err := strconv.Atoi(s)
		if err != nil || p <= 0 || p > 65535 {
			return 0
		}
		if p == 9103 || p == 10050 {
			return 0
		}
		return p
	}
}

func monitorSourceLabel(port int) string {
	switch port {
	case portNetdata:
		return "Netdata Prometheus API (RX only, binary Gb/s)"
	case portTelegraf:
		return "Telegraf prometheus_client /metrics (RX only, binary Gb/s)"
	case portSNMP:
		return "SNMP v2c IF-MIB counters (RX only, binary Gb/s)"
	case portGlances:
		return "Glances REST API (RX rate, binary Gb/s, no PPS)"
	case portCAdvisor:
		return "cAdvisor /metrics (RX + PPS via container_network_*, speed via machine API)"
	default:
		return "node_exporter /metrics (RX only, binary Gb/s)"
	}
}

type monitorState struct {
	peakGbps    float64
	peakMpps    float64
	peakMode    string
	peakDetail  string
	ceilingGbps float64
	lastAgg     *AggregateResult
	lastTime    time.Time
}

type monitorUI struct {
	title     func(a ...interface{}) string
	accent    func(a ...interface{}) string
	label     func(a ...interface{}) string
	value     func(a ...interface{}) string
	good      func(a ...interface{}) string
	warn      func(a ...interface{}) string
	muted     func(a ...interface{}) string
	err       func(a ...interface{}) string
	liveHdr   func(a ...interface{}) string
	info      func(a ...interface{}) string
	liveDrawn bool
}

func newMonitorUI() *monitorUI {
	return &monitorUI{
		title:   color.New(color.FgHiCyan, color.Bold).SprintFunc(),
		accent:  color.New(color.FgCyan).SprintFunc(),
		label:   color.New(color.Faint).SprintFunc(),
		value:   color.New(color.FgHiWhite, color.Bold).SprintFunc(),
		good:    color.New(color.FgHiGreen, color.Bold).SprintFunc(),
		warn:    color.New(color.FgHiYellow, color.Bold).SprintFunc(),
		err:     color.New(color.FgHiRed, color.Bold).SprintFunc(),
		muted:   color.New(color.Faint).SprintFunc(),
		liveHdr: color.New(color.FgHiMagenta, color.Bold).SprintFunc(),
		info:    color.New(color.FgHiCyan).SprintFunc(),
	}
}

func (ui *monitorUI) printErr(format string, args ...interface{}) {
	fmt.Println(ui.err("  ✗ " + fmt.Sprintf(format, args...)))
}

func (ui *monitorUI) printBanner(ip string, port int) {
	fmt.Println()
	fmt.Println("  " + ui.accent("╭────────────────────────────────────────────────────────────╮"))
	fmt.Println("  " + ui.accent("│ ") + ui.title("⚡ Zyre Live Monitor") + ui.accent("                                       │"))
	fmt.Println("  " + ui.accent("╰────────────────────────────────────────────────────────────╯"))
	fmt.Println()
	fmt.Printf("  %s %s\n", ui.label("Target:"), ui.value(fmt.Sprintf("%s:%d", ip, port)))
	fmt.Printf("  %s %s\n", ui.label("Source:"), ui.info(monitorSourceLabel(port)))
	fmt.Println()
}

func (ui *monitorUI) printCapacity(r *CapacityReport) {
	w := 56
	total, label := dstatBandwidthPair(r)
	_ = w
	ui.boxTop("How much bandwidth can this host take?", w)
	ui.boxRowBadge("Max bandwidth (all links)", total)
	ui.boxRowBadge("List bandwidth on dstat as", label)
	ui.boxBottom(w)
	sep := color.New(color.Faint).SprintFunc()
	if total > label*1.05 {
		fmt.Println("  " + ui.muted("Host max ") + bwBadge(total) + sep(" · list as ") + bwBadge(label) + ui.muted(" on dstat.bond"))
	} else {
		fmt.Println("  " + ui.muted("List as ") + bwBadge(label) + ui.muted(" on dstat.bond"))
	}
	fmt.Println()
}

func (ui *monitorUI) printMonitorFooter() {
	fmt.Println("  " + ui.muted("────────────────────────────────────────────────────────────"))
	fmt.Println("  " + ui.warn("Live updates every second") + ui.muted(" · ") + ui.muted("Ctrl+C") + ui.muted(" to stop and print peak"))
	fmt.Println()
	fmt.Println("  " + ui.liveHdr("◆ LIVE TRAFFIC"))
	fmt.Println()
}

func (ui *monitorUI) boxTop(title string, w int) {
	fmt.Println("  " + ui.accent("╭─ "+truncateText(title, intMax(0, w-6))+" "+strings.Repeat("─", intMax(0, w-len(title)-4))+"╮"))
}

func (ui *monitorUI) boxBottom(w int) {
	fmt.Println("  " + ui.accent("╰"+strings.Repeat("─", w-2)+"╯"))
}

func (ui *monitorUI) boxRow(label, val string, w int, highlight bool) {
	valStr := ui.value(val)
	if highlight {
		valStr = ui.good(val)
	}
	fmt.Printf("  %s %-28s %s %s\n", ui.accent("│"), ui.label(strings.ToUpper(label)+":"), valStr, ui.accent("│"))
}

func (ui *monitorUI) boxRowBadge(rowLabel string, gbps float64) {
	fmt.Printf("  %s %-28s %s %s\n", ui.accent("│"), ui.label(strings.ToUpper(rowLabel)+":"), bwBadge(gbps), ui.accent("│"))
}

func (ui *monitorUI) drawLivePanel(st *monitorState, agg *AggregateResult, errMsg string) {
	lines := ui.buildLiveLines(st, agg, errMsg)
	if ui.liveDrawn {
		ui.clearLiveArea()
	}
	for _, ln := range lines {
		fmt.Println(ln)
	}
	ui.liveDrawn = true
}

func (ui *monitorUI) buildLiveLines(st *monitorState, agg *AggregateResult, errMsg string) []string {
	var out []string

	if errMsg != "" {
		out = append(out, "  "+ui.err("  "+errMsg))
		out = append(out, "  "+ui.muted("  Peak bandwidth: "+formatMonitorBw(st.peakGbps)+" · PPS: "+formatMonitorPps(st.peakMpps)))
		for len(out) < monitorLiveLines {
			out = append(out, "")
		}
		return out
	}

	curBw, curPps := 0.0, 0.0
	var ifaces []IfRate
	if agg != nil {
		curBw = agg.GbpsBinary
		curPps = agg.Mpps
		ifaces = agg.Countable
	}

	out = append(out, fmt.Sprintf("  %s %s",
		ui.label("Time:"), ui.muted(time.Now().Format("15:04:05"))))
	out = append(out, fmt.Sprintf("  %s %s   %s %s",
		ui.label("Bandwidth:"),
		ui.formatBwColored(curBw),
		ui.label("PPS:"),
		ui.formatPpsColored(curPps)))
	out = append(out, fmt.Sprintf("  %s %s",
		ui.label("Peak bandwidth:"),
		ui.good(formatMonitorBw(st.peakGbps))))

	bar := trafficBar(curBw, st.ceilingGbps, 28)
	out = append(out, fmt.Sprintf("  %s %s  %s",
		ui.label("Usage:"),
		bar,
		ui.muted(fmt.Sprintf("%.0f%% of ~%.0fG max", pctOf(curBw, st.ceilingGbps), st.ceilingGbps))))

	out = append(out, "  "+ui.label("Interfaces:"))
	if len(ifaces) == 0 || curBw < 0.01 {
		out = append(out, "  "+ui.muted("  (no traffic)"))
	} else {
		for _, r := range ifaces {
			if r.BytesPs < 1e6 {
				continue
			}
			g := bytesPsToGbpsBinary(r.BytesPs)
			out = append(out, fmt.Sprintf("  %s  %-14s %s",
				ui.muted("  │"), r.Device, ui.formatBwColored(g)))
		}
	}

	for len(out) < monitorLiveLines {
		out = append(out, "")
	}
	if len(out) > monitorLiveLines {
		out = out[:monitorLiveLines]
	}
	return out
}

func (ui *monitorUI) clearLiveArea() {
	if !monitorSupportsANSI() {
		return
	}
	for i := 0; i < monitorLiveLines; i++ {
		fmt.Print("\033[A\033[2K")
	}
}

func (ui *monitorUI) printPeakSummary(st *monitorState) {
	fmt.Println()
	w := 56
	ui.boxTop("Your peak this session", w)
	ui.boxRow("Peak bandwidth", formatMonitorBw(st.peakGbps), w, true)
	ui.boxRow("Packets per second (PPS)", formatMonitorPps(st.peakMpps), w, true)
	if st.peakDetail != "" {
		ui.boxRow("Interfaces", st.peakDetail, w, false)
	}
	ui.boxBottom(w)
	fmt.Println()
}

func (ui *monitorUI) formatBwColored(gbps float64) string {
	if gbps >= 50 {
		return ui.good(formatMonitorBw(gbps))
	}
	if gbps >= 1 {
		return ui.warn(formatMonitorBw(gbps))
	}
	if gbps >= 0.01 {
		return ui.value(formatMonitorBw(gbps))
	}
	return ui.muted("0.00 Gb/s")
}

func (ui *monitorUI) formatPpsColored(mpps float64) string {
	if mpps >= 1 {
		return ui.good(formatMonitorPps(mpps))
	}
	if mpps > 0 {
		return ui.value(formatMonitorPps(mpps))
	}
	return ui.muted("0 PPS")
}

func formatMonitorBw(gbps float64) string {
	if gbps >= 1000 {
		return fmt.Sprintf("%.2f Tb/s", gbps/1000)
	}
	return fmt.Sprintf("%.2f Gb/s", gbps)
}

func formatMonitorPps(mpps float64) string {
	if mpps >= 1000 {
		return fmt.Sprintf("%.2f Bpps", mpps/1000)
	}
	if mpps >= 1 {
		return fmt.Sprintf("%.2f Mpps", mpps)
	}
	if mpps >= 0.001 {
		return fmt.Sprintf("%.2f Kpps", mpps*1000)
	}
	return fmt.Sprintf("%.0f pps", mpps*1e6)
}

func trafficBar(current, ceiling float64, width int) string {
	if ceiling <= 0 {
		ceiling = 100
	}
	pct := current / ceiling
	if pct > 1 {
		pct = 1
	}
	if pct < 0 {
		pct = 0
	}
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if pct >= 0.95 {
		return color.New(color.FgHiRed, color.Bold).Sprint(bar)
	}
	if pct >= 0.5 {
		return color.New(color.FgHiYellow, color.Bold).Sprint(bar)
	}
	return color.New(color.FgHiGreen).Sprint(bar)
}

func pctOf(current, ceiling float64) float64 {
	if ceiling <= 0 {
		return 0
	}
	return (current / ceiling) * 100
}

func monitorSupportsANSI() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return true
}

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fetchMonitorSnapshot(client *http.Client, ip string, port int) (*MetricsSnapshot, error) {
	switch port {
	case portSNMP:
		return fetchSNMPMonitorSnapshot(ip)
	case portTelegraf:
		url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
		return fetchTelegrafSnapshot(client, url)
	case portCAdvisor:
		return fetchCAdvisorSnapshot(client, ip, port)
	default:
		url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
		return fetchMetricsSnapshot(client, url)
	}
}

func fetchSNMPMonitorSnapshot(ip string) (*MetricsSnapshot, error) {
	var lastErr error
	var hadAgent bool
	for _, community := range snmpCommunities {
		snap, err := snmpMonitorSnapshot(ip, community)
		if err != nil {
			lastErr = err
			continue
		}
		hadAgent = true
		if len(snap.RxBytes) > 0 {
			return snap, nil
		}
		lastErr = errSNMPNoRxCounters
	}
	if hadAgent {
		return nil, lastErr
	}
	if lastErr != nil {
		return nil, fmt.Errorf("SNMP unreachable on %s:%d: %v", ip, portSNMP, lastErr)
	}
	return nil, fmt.Errorf("SNMP unreachable on %s:%d", ip, portSNMP)
}

func snmpMonitorSnapshot(ip, community string) (*MetricsSnapshot, error) {
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      uint16(portSNMP),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   4 * time.Second,
		Retries:   1,
		MaxOids:   60,
	}
	if err := snmp.Connect(); err != nil {
		return nil, err
	}
	defer snmp.Conn.Close()

	descrs, err := snmpBulkWalk(snmp, oidIfDescr)
	if err != nil || len(descrs) == 0 {
		return nil, fmt.Errorf("no interfaces")
	}
	hcIn, _ := snmpBulkWalk(snmp, oidIfHCInOctets)
	hcPkts, _ := snmpBulkWalk(snmp, oidIfHCInUcastPkts)
	inOctets, _ := snmpBulkWalk(snmp, oidIfInOctets)
	inPkts, _ := snmpBulkWalk(snmp, oidIfInUcastPkts)
	macsRaw, _ := snmpBulkWalk(snmp, oidIfPhysAddr)

	snap := &MetricsSnapshot{
		Time:      float64(time.Now().UnixNano()) / 1e9,
		RxBytes:   map[string]float64{},
		RxPackets: map[string]float64{},
		MACs:      map[string]string{},
	}

	counterAvailable := len(hcIn) > 0 || len(inOctets) > 0

	for oid, pdu := range descrs {
		dev := snmpString(pdu)
		if dev == "" || isVirtualIface(dev) {
			continue
		}
		idx := snmpIndex(oid, oidIfDescr)
		if idx == "" {
			continue
		}

		var rxBytes, rxPkts uint64
		gotCounter := false
		if pdu, ok := snmpMapLookup(hcIn, oidIfHCInOctets, idx); ok {
			gotCounter = true
			rxBytes = snmpUint(pdu)
		} else if pdu, ok := snmpMapLookup(inOctets, oidIfInOctets, idx); ok {
			gotCounter = true
			rxBytes = snmpUint(pdu)
		}
		if pdu, ok := snmpMapLookup(hcPkts, oidIfHCInUcastPkts, idx); ok {
			gotCounter = true
			rxPkts = snmpUint(pdu)
		} else if pdu, ok := snmpMapLookup(inPkts, oidIfInUcastPkts, idx); ok {
			gotCounter = true
			rxPkts = snmpUint(pdu)
		}
		if !gotCounter {
			continue
		}

		snap.RxBytes[dev] = float64(rxBytes)
		snap.RxPackets[dev] = float64(rxPkts)

		if macPDU, ok := snmpMapLookup(macsRaw, oidIfPhysAddr, idx); ok {
			if mac := snmpMAC(macPDU); mac != "" {
				snap.MACs[dev] = mac
			}
		}
	}

	if !counterAvailable || len(snap.RxBytes) == 0 {
		return snap, errSNMPNoRxCounters
	}
	return snap, nil
}

func fetchNetdataLiveRates(client *http.Client, ip string, port int) ([]IfRate, map[string]string, error) {
	url := fmt.Sprintf("http://%s:%d/api/v1/allmetrics?format=prometheus", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "zyre-dstat-scanner/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseNetdataLiveRates(io.LimitReader(resp.Body, 4<<20))
}

func parseNetdataLiveRates(body io.Reader) ([]IfRate, map[string]string, error) {
	bwRecv := map[string]float64{}
	pktRecv := map[string]float64{}

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		switch {
		case strings.Contains(line, "_kilobits_persec_average"):
			if extractLabelString(line, "dimension") != "received" {
				continue
			}
			dev := netdataDeviceFromLine(line)
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if val, ok := metricValue(line); ok && val > 0 {
				bwRecv[dev] = val * 1000 / 8
			}
		case strings.Contains(line, "_packets_persec_average"):
			if extractLabelString(line, "dimension") != "received" {
				continue
			}
			dev := netdataDeviceFromLine(line)
			if dev == "" || isVirtualIface(dev) {
				continue
			}
			if val, ok := metricValue(line); ok && val > 0 {
				pktRecv[dev] = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}

	devices := map[string]bool{}
	for d := range bwRecv {
		devices[d] = true
	}
	for d := range pktRecv {
		devices[d] = true
	}

	var rates []IfRate
	for dev := range devices {
		rates = append(rates, IfRate{
			Device:    dev,
			BytesPs:   bwRecv[dev],
			PacketsPs: pktRecv[dev],
		})
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].BytesPs > rates[j].BytesPs })
	if len(rates) == 0 {
		return nil, nil, fmt.Errorf("not Netdata Prometheus export (no netdata_net_* rate metrics)")
	}
	return rates, map[string]string{}, nil
}

func fetchTelegrafSnapshot(client *http.Client, url string) (*MetricsSnapshot, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	snap, err := parseTelegrafSnapshot(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if !isValidTelegrafSnapshot(snap) {
		return nil, fmt.Errorf("not Telegraf /metrics (missing net_bytes_recv)")
	}
	snap.Time = float64(time.Now().UnixNano()) / 1e9
	return snap, nil
}

func fetchMetricsSnapshot(client *http.Client, url string) (*MetricsSnapshot, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	snap, err := parseMetricsSnapshot(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if !isValidNodeExporterSnapshot(snap) {
		return nil, fmt.Errorf("not node_exporter /metrics (missing node_network_* series)")
	}
	snap.Time = float64(time.Now().UnixNano()) / 1e9
	return snap, nil
}

func formatTopIfaces(countable []IfRate, n int) string {
	sorted := append([]IfRate{}, countable...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].BytesPs > sorted[j].BytesPs })
	var parts []string
	for i := 0; i < len(sorted) && i < n; i++ {
		gbps := bytesPsToGbpsBinary(sorted[i].BytesPs)
		if gbps >= 0.01 {
			parts = append(parts, fmt.Sprintf("%s=%.1fG", sorted[i].Device, gbps))
		}
	}
	return strings.Join(parts, " ")
}

type nginxStatus struct {
	active   int
	accepts  int64
	handled  int64
	requests int64
	reading  int
	writing  int
	waiting  int
}

type l7SourceSpec struct {
	Name   string
	Short  string
	Paths  []string
	Ports  []int
	Parser func(body string, hdr http.Header) (*nginxStatus, bool)
}

type l7Hit struct {
	ip     string
	port   int
	scheme string
	path   string
	source string
	st     *nginxStatus
	hdr    http.Header
	t1     time.Time
}

var nginxStatusPaths = []string{"/nginx_status", "/status", "/stub_status", "/basic_status", "/nginx-status"}

var reNginxNums = regexp.MustCompile(`\b\d+\b`)

var l7Sources = map[string]l7SourceSpec{
	"nginx": {
		Name:   "nginx_status",
		Short:  "nginx",
		Paths:  []string{"/nginx_status", "/status", "/stub_status", "/basic_status", "/nginx-status"},
		Ports:  []int{80, 443},
		Parser: parseNginxStatusFromResponse,
	},
	"apache": {
		Name:   "Apache mod_status",
		Short:  "apache",
		Paths:  []string{"/server-status?auto", "/server-status"},
		Ports:  []int{80, 443, 8080},
		Parser: parseApacheStatusFromResponse,
	},
	"haproxy": {
		Name:   "HAProxy stats",
		Short:  "haproxy",
		Paths:  []string{"/stats;csv", "/haproxy?stats;csv", "/haproxy/stats;csv"},
		Ports:  []int{80, 443, 8404},
		Parser: parseHAProxyStatusFromResponse,
	},
	"envoy": {
		Name:   "Envoy stats",
		Short:  "envoy",
		Paths:  []string{"/stats?format=prometheus", "/stats/prometheus", "/stats"},
		Ports:  []int{80, 443, 9901},
		Parser: parseEnvoyStatusFromResponse,
	},
	"traefik": {
		Name:   "Traefik metrics",
		Short:  "traefik",
		Paths:  []string{"/metrics"},
		Ports:  []int{80, 443, 8080},
		Parser: parseTraefikStatusFromResponse,
	},
	"caddy": {
		Name:   "Caddy metrics",
		Short:  "caddy",
		Paths:  []string{"/metrics"},
		Ports:  []int{80, 443, 2019},
		Parser: parseCaddyStatusFromResponse,
	},
}

var l7SourceOrder = []string{"nginx", "apache", "haproxy", "envoy", "traefik", "caddy"}

func l7AliasToSource(token string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "nginx", "nginx_status", "stub_status":
		return "nginx", true
	case "apache", "mod_status", "server-status", "server_status":
		return "apache", true
	case "haproxy", "haproxy_stats", "haproxy-stats":
		return "haproxy", true
	case "envoy":
		return "envoy", true
	case "traefik":
		return "traefik", true
	case "caddy":
		return "caddy", true
	}
	return "", false
}

func hasL7Selector(args []string) bool {
	for _, a := range args {
		for _, part := range strings.FieldsFunc(strings.ToLower(strings.TrimSpace(a)), func(r rune) bool {
			return r == ',' || r == '+' || r == '|' || r == ';' || r == ' '
		}) {
			if part == "" {
				continue
			}
			if part == "all7" || part == "l7" {
				return true
			}
			if _, ok := l7AliasToSource(part); ok {
				return true
			}
		}
	}
	return false
}

var l7CdnISP = map[string]string{
	"cloudflare": "Cloudflare (L7 WAF/CDN)",
	"sucuri":     "Sucuri (L7 WAF)",
	"akamai":     "Akamai (L7 CDN)",
	"fastly":     "Fastly (L7 CDN)",
	"imperva":    "Imperva Incapsula (L7 WAF)",
	"incapsula":  "Imperva Incapsula (L7 WAF)",
	"stackpath":  "StackPath (L7 CDN)",
	"ddos-guard": "DDoS-Guard (L7 WAF)",
	"ddos guard": "DDoS-Guard (L7 WAF)",
	"qrator":     "Qrator (L7 WAF)",
	"g-core":     "G-Core (L7 CDN)",
	"gcore":      "G-Core (L7 CDN)",
	"bunny":      "BunnyCDN (L7 CDN)",
	"cdnetworks": "CDNetworks (L7 CDN)",
	"wangsu":     "Wangsu (L7 CDN)",
	"edgecast":   "Edgecast/Edgio (L7 CDN)",
	"edgio":      "Edgio (L7 CDN)",
	"cachefly":   "CacheFly (L7 CDN)",
	"limelight":  "Limelight (L7 CDN)",
}

func parseNginxStatus(body string) (*nginxStatus, bool) {
	if !strings.Contains(body, "Active connections:") || !strings.Contains(body, "server accepts handled requests") {
		return nil, false
	}
	lines := strings.Split(body, "\n")
	st := &nginxStatus{}
	gotActive, gotCounters := false, false

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "Active connections:") {
			nums := reNginxNums.FindAllString(line, -1)
			if len(nums) >= 1 {
				st.active, _ = strconv.Atoi(nums[0])
				gotActive = true
			}
		} else if strings.HasPrefix(line, "server accepts handled requests") {
			if i+1 < len(lines) {
				nums := reNginxNums.FindAllString(strings.TrimSpace(lines[i+1]), -1)
				if len(nums) >= 3 {
					st.accepts, _ = strconv.ParseInt(nums[0], 10, 64)
					st.handled, _ = strconv.ParseInt(nums[1], 10, 64)
					st.requests, _ = strconv.ParseInt(nums[2], 10, 64)
					gotCounters = true
				}
			}
		} else if strings.HasPrefix(line, "Reading:") {
			nums := reNginxNums.FindAllString(line, -1)
			if len(nums) >= 3 {
				st.reading, _ = strconv.Atoi(nums[0])
				st.writing, _ = strconv.Atoi(nums[1])
				st.waiting, _ = strconv.Atoi(nums[2])
			}
		}
	}

	if !gotActive || !gotCounters {
		return nil, false
	}
	return st, true
}

func parseNginxStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	return parseNginxStatus(body)
}

func parseApacheStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	lines := strings.Split(body, "\n")
	var totalReq int64
	var busy, idle int
	gotReq, gotBusy, gotIdle := false, false, false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Total Accesses:"):
			nums := reNginxNums.FindAllString(line, -1)
			if len(nums) >= 1 {
				totalReq, _ = strconv.ParseInt(nums[0], 10, 64)
				gotReq = true
			}
		case strings.HasPrefix(line, "BusyWorkers:"):
			nums := reNginxNums.FindAllString(line, -1)
			if len(nums) >= 1 {
				busy, _ = strconv.Atoi(nums[0])
				gotBusy = true
			}
		case strings.HasPrefix(line, "IdleWorkers:"):
			nums := reNginxNums.FindAllString(line, -1)
			if len(nums) >= 1 {
				idle, _ = strconv.Atoi(nums[0])
				gotIdle = true
			}
		}
	}
	if !gotReq {
		return nil, false
	}
	st := &nginxStatus{
		requests: totalReq,
		active:   busy + idle,
		writing:  busy,
		waiting:  idle,
	}
	if gotBusy {
		st.reading = busy
	}
	if !gotBusy && !gotIdle {
		st.active = 0
	}
	return st, true
}

func parseHAProxyStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	r := csv.NewReader(strings.NewReader(body))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return nil, false
	}

	headerIdx := -1
	for i, rec := range records {
		if len(rec) > 0 && strings.HasPrefix(strings.TrimSpace(rec[0]), "# pxname") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 || headerIdx+1 >= len(records) {
		return nil, false
	}

	header := records[headerIdx]
	col := map[string]int{}
	for i, h := range header {
		key := strings.TrimSpace(strings.TrimPrefix(h, "#"))
		col[key] = i
	}
	getInt := func(rec []string, key string) int64 {
		idx, ok := col[key]
		if !ok || idx >= len(rec) {
			return 0
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(rec[idx]), 10, 64)
		return v
	}
	getStr := func(rec []string, key string) string {
		idx, ok := col[key]
		if !ok || idx >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[idx])
	}

	var totalReq, active int64
	var rows int
	for _, rec := range records[headerIdx+1:] {
		if len(rec) == 0 {
			continue
		}
		sv := strings.ToUpper(getStr(rec, "svname"))
		if sv == "" || sv == "BACKEND" || sv == "FRONTEND" {
			continue
		}
		totalReq += getInt(rec, "stot")
		if scur := getInt(rec, "scur"); scur > 0 {
			active += scur
		}
		rows++
	}
	if rows == 0 || totalReq <= 0 {
		return nil, false
	}
	return &nginxStatus{
		requests: totalReq,
		active:   int(active),
		writing:  int(active),
	}, true
}

func parseEnvoyStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	var total, active int64
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "http_downstream_rq_total"):
			if v, ok := metricValue(line); ok {
				vi := int64(v)
				if vi > total {
					total = vi
				}
			}
		case strings.HasPrefix(line, "http_downstream_cx_active"):
			if v, ok := metricValue(line); ok && int64(v) > active {
				active = int64(v)
			}
		case strings.HasPrefix(line, "envoy_http_downstream_rq_total"):
			if v, ok := metricValue(line); ok {
				vi := int64(v)
				if vi > total {
					total = vi
				}
			}
		case strings.HasPrefix(line, "envoy_http_downstream_cx_active"):
			if v, ok := metricValue(line); ok && int64(v) > active {
				active = int64(v)
			}
		}
	}
	if total <= 0 {
		return nil, false
	}
	return &nginxStatus{
		requests: total,
		active:   int(active),
		writing:  int(active),
	}, true
}

func parseTraefikStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	var total, active int64
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "traefik_service_requests_total"):
			if v, ok := metricValue(line); ok {
				total += int64(v)
			}
		case strings.HasPrefix(line, "traefik_entrypoint_open_connections"):
			if v, ok := metricValue(line); ok {
				active += int64(v)
			}
		}
	}
	if total <= 0 {
		return nil, false
	}
	return &nginxStatus{
		requests: total,
		active:   int(active),
		writing:  int(active),
	}, true
}

func parseCaddyStatusFromResponse(body string, _ http.Header) (*nginxStatus, bool) {
	var total int64
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "http_requests_total"):
			if v, ok := metricValue(line); ok {
				total += int64(v)
			}
		case strings.HasPrefix(line, "caddy_http_requests_total"):
			if v, ok := metricValue(line); ok {
				total += int64(v)
			}
		}
	}
	if total <= 0 {
		return nil, false
	}
	return &nginxStatus{
		requests: total,
	}, true
}

func mergeUniqueInts(base []int, more []int) []int {
	seen := make(map[int]struct{}, len(base)+len(more))
	out := make([]int, 0, len(base)+len(more))
	for _, p := range base {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range more {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func defaultPortsForL7Selection(selection []string, forceScheme string) []int {
	var ports []int
	for _, key := range selection {
		spec, ok := l7Sources[key]
		if !ok {
			continue
		}
		ports = mergeUniqueInts(ports, spec.Ports)
	}
	if len(ports) == 0 {
		if forceScheme == "https" {
			return []int{443}
		}
		return []int{80}
	}
	sort.Ints(ports)
	return ports
}

func parseL7Selection(args []string) ([]string, bool, string, []int) {
	mode := "zmap"
	forceScheme := ""
	var ports []int
	selectedSet := map[string]bool{}
	hasAll7 := false
	explicitSource := false

	for _, a := range args {
		la := strings.ToLower(strings.TrimSpace(a))
		switch la {
		case "masscan", "massscan":
			mode = "masscan"
			continue
		case "zmap":
			mode = "zmap"
			continue
		case "http":
			forceScheme = "http"
			continue
		case "https", "ssl", "tls":
			forceScheme = "https"
			continue
		}

		for _, part := range strings.FieldsFunc(la, func(r rune) bool {
			return r == ',' || r == '+' || r == '|' || r == ';' || r == ' '
		}) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if part == "all7" || part == "l7" {
				hasAll7 = true
				continue
			}
			if src, ok := l7AliasToSource(part); ok {
				explicitSource = true
				selectedSet[src] = true
				continue
			}
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p < 65536 {
				ports = append(ports, p)
			}
		}
	}

	var selection []string
	if hasAll7 {
		selection = append(selection, l7SourceOrder...)
	} else if explicitSource {
		for _, key := range l7SourceOrder {
			if selectedSet[key] {
				selection = append(selection, key)
			}
		}
	} else {
		selection = []string{"nginx"}
	}
	if len(ports) == 0 {
		ports = defaultPortsForL7Selection(selection, forceScheme)
	}
	return selection, hasAll7, mode, ports
}

func fetchL7SecondSnapshot(client *http.Client, source string, scheme, ip string, port int, path string) (*nginxStatus, string, bool) {
	spec, ok := l7Sources[source]
	if !ok {
		return nil, scheme, false
	}
	st2, effScheme, _, ok := fetchL7Status(client, scheme, ip, port, path, spec.Parser)
	return st2, effScheme, ok
}

func probeAnyL7Source(client *http.Client, sourceOrder []string, ip string, port int, schemes []string) (string, *nginxStatus, string, string, http.Header, bool) {
	for _, source := range sourceOrder {
		spec, ok := l7Sources[source]
		if !ok {
			continue
		}
		if st, scheme, path, hdr, ok := probeL7Source(client, spec, ip, port, schemes); ok {
			return source, st, scheme, path, hdr, true
		}
	}
	return "", nil, "", "", nil, false
}

func detectL7Protection(hdr http.Header, ispLower string) protEntry {
	has := func(k string) bool { return len(hdr.Values(k)) > 0 }
	server := strings.ToLower(hdr.Get("Server"))
	powered := strings.ToLower(hdr.Get("X-Powered-By"))

	switch {
	case strings.Contains(server, "cloudflare") || has("Cf-Ray") || has("Cf-Cache-Status"):
		return protEntry{status: "PROTECTED", reason: "Cloudflare (L7 WAF/CDN)", clr: color.FgRed}
	case has("X-Sucuri-Id") || has("X-Sucuri-Cache") || strings.Contains(server, "sucuri"):
		return protEntry{status: "PROTECTED", reason: "Sucuri (L7 WAF)", clr: color.FgRed}
	case strings.Contains(server, "akamai") || has("X-Akamai-Transformed") || has("X-Akamai-Request-Id"):
		return protEntry{status: "PROTECTED", reason: "Akamai (L7 CDN)", clr: color.FgRed}
	case strings.Contains(server, "fastly") || has("Fastly-Debug-Digest") || strings.Contains(strings.ToLower(hdr.Get("X-Served-By")), "cache-"):
		return protEntry{status: "PROTECTED", reason: "Fastly (L7 CDN)", clr: color.FgRed}
	case has("X-Iinfo") || strings.Contains(server, "incapsula") || strings.Contains(strings.ToLower(hdr.Get("X-Cdn")), "incapsula"):
		return protEntry{status: "PROTECTED", reason: "Imperva Incapsula (L7 WAF)", clr: color.FgRed}
	case strings.Contains(server, "ddos-guard") || has("X-Ddg"):
		return protEntry{status: "PROTECTED", reason: "DDoS-Guard (L7 WAF)", clr: color.FgRed}
	case has("X-Qrator"):
		return protEntry{status: "PROTECTED", reason: "Qrator (L7 WAF)", clr: color.FgRed}
	case strings.Contains(server, "bunnycdn"):
		return protEntry{status: "PROTECTED", reason: "BunnyCDN (L7 CDN)", clr: color.FgRed}
	case strings.Contains(server, "modsecurity") || strings.Contains(server, "mod_security") || strings.Contains(powered, "mod_security"):
		return protEntry{status: "PROTECTED", reason: "ModSecurity WAF", clr: color.FgRed}
	}

	for k, r := range l7CdnISP {
		if strings.Contains(ispLower, k) {
			return protEntry{status: "PROTECTED", reason: r, clr: color.FgRed}
		}
	}
	return protEntry{status: "UNPROTECTED", reason: "Direct origin — no L7 filter", clr: color.FgGreen}
}

func fetchL7Status(client *http.Client, scheme, ip string, port int, path string, parser func(string, http.Header) (*nginxStatus, bool)) (*nginxStatus, string, http.Header, bool) {
	url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, port, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", nil, false
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "zyre-l7-scanner/1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", nil, false
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024))
		resp.Body.Close()
	}()

	effScheme := scheme
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme != "" {
		effScheme = resp.Request.URL.Scheme
	}

	if resp.StatusCode != 200 {
		return nil, effScheme, resp.Header, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, effScheme, resp.Header, false
	}
	st, ok := parser(string(body), resp.Header)
	return st, effScheme, resp.Header, ok
}

func probeL7Source(client *http.Client, spec l7SourceSpec, ip string, port int, schemes []string) (*nginxStatus, string, string, http.Header, bool) {
	for _, scheme := range schemes {
		for _, path := range spec.Paths {
			if st, effScheme, hdr, ok := fetchL7Status(client, scheme, ip, port, path, spec.Parser); ok {
				return st, effScheme, path, hdr, true
			}
		}
	}
	return nil, "", "", nil, false
}

func fetchNginxStatus(client *http.Client, scheme, ip string, port int, path string) (*nginxStatus, string, http.Header, bool) {
	return fetchL7Status(client, scheme, ip, port, path, parseNginxStatusFromResponse)
}

func probeNginx(client *http.Client, ip string, port int, schemes []string) (*nginxStatus, string, string, http.Header, bool) {
	return probeL7Source(client, l7Sources["nginx"], ip, port, schemes)
}

func newNginxClient() *http.Client {
	return &http.Client{
		Timeout: 1600 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   700 * time.Millisecond,
				KeepAlive: -1,
			}).DialContext,
			DisableKeepAlives:     true,
			MaxIdleConns:          0,
			ResponseHeaderTimeout: 900 * time.Millisecond,
			IdleConnTimeout:       1 * time.Millisecond,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   900 * time.Millisecond,
		},
	}
}

func schemesForPort(port int, force string) []string {
	switch force {
	case "http":
		return []string{"http"}
	case "https":
		return []string{"https"}
	}
	switch port {
	case 443, 8443, 4443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func runNginxScan(args []string) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(300)

	selection, all7, mode, ports := parseL7Selection(args)
	forceScheme := ""
	for _, a := range args {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "http" {
			forceScheme = "http"
		}
		if la == "https" || la == "ssl" || la == "tls" {
			forceScheme = "https"
		}
	}

	ui := globalUI
	bin := programBin()
	ui.playBootAnimation()

	portStr := make([]string, len(ports))
	for i, p := range ports {
		portStr[i] = strconv.Itoa(p)
	}
	scheme := "auto (http→https)"
	if forceScheme != "" {
		scheme = forceScheme
	}
	sourceLabel := strings.Join(selection, " + ")
	if all7 {
		sourceLabel = "all7 (" + sourceLabel + ")"
	}

	ui.boxTop("⚡ " + appTitle + " · Layer 7 Scanner")
	ui.boxRow("checking", sourceLabel+" → live RPS · protection")
	ui.boxRow("ports", strings.Join(portStr, " · "))
	ui.boxRow("scheme", scheme)
	ui.boxRow("input", mode)
	ui.boxRow("waiting", "IPs on stdin… "+bin+" help for usage")
	ui.boxBottom()
	printZmapStderrTip()

	outName := "nginx.txt"
	if all7 || len(selection) > 1 || selection[0] != "nginx" {
		outName = "l7.txt"
	}
	outFile, _ := os.OpenFile(outName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer outFile.Close()
	outWriter := newAsyncWriter(outFile)
	defer outWriter.Close()

	jobs := make(chan Job, 200_000)
	var total, attempted, foundCount int64

	go func() {
		lineScanner := bufio.NewScanner(os.Stdin)
		lineScanner.Buffer(make([]byte, 1*1024*1024), 1*1024*1024)
		for lineScanner.Scan() {
			raw := strings.TrimSpace(lineScanner.Text())
			if raw == "" || strings.HasPrefix(raw, "#") || isScannerNoise(raw) {
				continue
			}

			if mode == "masscan" && strings.HasPrefix(raw, "open ") {
				parts := strings.Fields(raw)
				if len(parts) >= 4 && net.ParseIP(parts[3]) != nil {
					op, _ := strconv.Atoi(parts[2])
					pl := ports
					if op != 0 {
						pl = []int{op}
					}
					for _, p := range pl {
						atomic.AddInt64(&total, 1)
						jobs <- Job{IP: parts[3], Port: p}
					}
					continue
				}
			}

			if match := cidrRegex.FindString(raw); match != "" {
				if ip, ipnet, err := net.ParseCIDR(match); err == nil {
					for ip2 := ip.Mask(ipnet.Mask); ipnet.Contains(ip2); incIP(ip2) {
						s := ip2.String()
						for _, p := range ports {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: s, Port: p}
						}
					}
					continue
				}
			}

			ipOnly, overridePort := parseIPAndOptionalPort(raw)
			if net.ParseIP(ipOnly) == nil {
				ipOnly = extractIPFromInputLine(raw)
			}
			if net.ParseIP(ipOnly) == nil {
				continue
			}
			pl := ports
			if overridePort != 0 {
				pl = []int{overridePort}
			}
			for _, p := range pl {
				atomic.AddInt64(&total, 1)
				jobs <- Job{IP: ipOnly, Port: p}
			}
		}
		close(jobs)
	}()

	startTime := time.Now()

	stopProgress := make(chan struct{})
	var spinFrame int64
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-tick.C:
				a := atomic.LoadInt64(&attempted)
				if a == 0 {
					continue
				}
				elapsed := time.Since(startTime).Seconds()
				if elapsed == 0 {
					continue
				}
				frame := atomic.AddInt64(&spinFrame, 1)
				ui.printProgress(frame, a, atomic.LoadInt64(&foundCount), float64(a)/elapsed)
			}
		}
	}()

	hitCh := make(chan l7Hit, 16384)

	l7RpsWindowMs := envIntInRange("DSTAT_L7_RPS_WINDOW_MS", 250, 100, 1500)
	l7SecondSnapshot := envBool("DSTAT_L7_SECOND_SNAPSHOT", true)
	l7Retries := envIntInRange("DSTAT_L7_RETRIES", 1, 0, 3)
	var ppWg sync.WaitGroup
	l7PostWorkers := envIntInRange("DSTAT_L7_POST_WORKERS", recommendedWorkerCount(24, 96, 768), 32, 1024)
	for i := 0; i < l7PostWorkers; i++ {
		ppWg.Add(1)
		go func() {
			defer ppWg.Done()
			client := newNginxClient()
			for h := range hitCh {
				rps := 0.0
				scheme := h.scheme
				if l7SecondSnapshot {
					time.Sleep(time.Duration(l7RpsWindowMs) * time.Millisecond)
					if st2, effScheme, ok := fetchL7SecondSnapshot(client, h.source, h.scheme, h.ip, h.port, h.path); ok {
						dt := time.Since(h.t1).Seconds()
						if dt > 0 && st2.requests >= h.st.requests {
							rps = float64(st2.requests-h.st.requests) / dt
						}
						scheme = effScheme
					}
				}

				isp, country := getIPInfoCached(h.ip)
				prot := detectL7Protection(h.hdr, strings.ToLower(isp))
				isHTTPS := strings.EqualFold(scheme, "https")

				displayMu.Lock()
				fmt.Print("\r\033[2K")
				green := ui.col(color.FgHiGreen, true).SprintFunc()
				cyan := ui.col(color.FgHiCyan, true).SprintFunc()
				white := ui.col(color.FgHiWhite, false).SprintFunc()
				d := ui.col(color.Faint, false).SprintFunc()
				schemeBadge := ui.col(color.FgHiYellow, true).Sprint(" HTTP ")
				if isHTTPS {
					schemeBadge = ui.col(color.FgHiGreen, true).Sprint(" HTTPS ")
				}
				protBadge := ui.col(prot.clr, true).Sprintf(" %s ", prot.status)
				loc := strings.TrimSpace(strings.Trim(fmt.Sprintf("%s %s", country, isp), " "))
				sourceTag := termBadge(strings.ToUpper(h.source), 60, 231, 10)
				fmt.Printf("  %s %s %s %s  %s  %s %s  %s\n",
					green("✓"),
					schemeBadge,
					protBadge,
					sourceTag,
					cyan(fmt.Sprintf("%s://%s:%d%s", scheme, h.ip, h.port, h.path)),
					d("rps"), white(fmt.Sprintf("%.0f", rps)),
					d(prot.reason+" · "+loc))
				displayMu.Unlock()

				outWriter.Write(fmt.Sprintf("%s://%s:%d%s\tsource=%s\tscheme=%s\tprot=%s(%s)\trps=%.0f\t%s\n",
					scheme, h.ip, h.port, h.path, h.source, strings.ToUpper(scheme), prot.status, prot.reason,
					rps, loc))

				atomic.AddInt64(&foundCount, 1)
			}
		}()
	}

	// Dynamic default to reduce stalls on very large target streams.
	// Override with DSTAT_L7_WORKERS when needed.
	workerCount := envIntInRange("DSTAT_L7_WORKERS", recommendedWorkerCount(192, 768, 3072), 128, 4096)
	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := newNginxClient()
			for j := range jobs {
				atomic.AddInt64(&attempted, 1)
				schemes := schemesForPort(j.Port, forceScheme)
				t1 := time.Now()
				var (
					source string
					st     *nginxStatus
					scheme string
					path   string
					hdr    http.Header
					ok     bool
				)
				for attempt := 0; attempt <= l7Retries; attempt++ {
					source, st, scheme, path, hdr, ok = probeAnyL7Source(client, selection, j.IP, j.Port, schemes)
					if ok {
						break
					}
					if attempt < l7Retries {
						time.Sleep(20 * time.Millisecond)
					}
				}
				if ok {
					hitCh <- l7Hit{ip: j.IP, port: j.Port, scheme: scheme, path: path, source: source, st: st, hdr: hdr, t1: t1}
				}
			}
		}()
	}

	wg.Wait()
	close(hitCh)
	ppWg.Wait()
	close(stopProgress)

	elapsed := time.Since(startTime)
	ui.clearProgressLine()
	ui.boxTop("Done")
	ui.boxRow("found", fmt.Sprintf("%d layer7 targets", atomic.LoadInt64(&foundCount)))
	ui.boxRow("queued", fmt.Sprintf("%d targets", atomic.LoadInt64(&total)))
	ui.boxRow("checked", fmt.Sprintf("%d IPs", atomic.LoadInt64(&attempted)))
	ui.boxRow("took", elapsed.Round(time.Second).String())
	if atomic.LoadInt64(&foundCount) > 0 {
		ui.boxRow("saved to", outName)
	}
	ui.boxBottom()
}
