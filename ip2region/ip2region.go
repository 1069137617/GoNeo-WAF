package ip2region

import (
	"fmt"
	"os"
	"strings"
	"sync"

	xdb "github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

type Searcher struct {
	inner *xdb.Searcher
	mu    sync.RWMutex
}

type RegionInfo struct {
	Country  string
	Province string
	City     string
	ISP      string
	IsoCode  string
}

var (
	defaultSearcher *Searcher
	once            sync.Once
)

func New(filepath string) (*Searcher, error) {
	cBuff, err := xdb.LoadContentFromFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("读取ip2region数据库失败: %w", err)
	}

	header, err := xdb.LoadHeaderFromBuff(cBuff)
	if err != nil {
		return nil, fmt.Errorf("读取ip2region文件头失败: %w", err)
	}

	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("检测IP版本失败: %w", err)
	}

	inner, err := xdb.NewWithBuffer(version, cBuff)
	if err != nil {
		return nil, fmt.Errorf("创建ip2region查询器失败: %w", err)
	}

	return &Searcher{inner: inner}, nil
}

func GetDefault() (*Searcher, error) {
	var initErr error
	once.Do(func() {
		dbPath := "data/ip2region_v4.xdb"
		defaultSearcher, initErr = New(dbPath)
	})
	return defaultSearcher, initErr
}

func (s *Searcher) Search(ipStr string) (*RegionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	region, err := s.inner.Search(ipStr)
	if err != nil {
		return nil, err
	}

	return parseRegionString(region), nil
}

func parseRegionString(regionStr string) *RegionInfo {
	info := &RegionInfo{}
	parts := strings.Split(regionStr, "|")

	for i, part := range parts {
		part = strings.TrimSpace(part)
		switch i {
		case 0:
			info.Country = part
		case 1:
			info.Province = part
		case 2:
			info.City = part
		case 3:
			info.ISP = part
		case 4:
			info.IsoCode = part
		}
	}

	return info
}

func (s *Searcher) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inner != nil {
		s.inner.Close()
	}
}

type IPGroup struct {
	CountryCode string
	CountryName string
}

var ipGroupMap = map[string]IPGroup{
	"CN": {"CN", "China"},
	"US": {"US", "United States"},
	"JP": {"JP", "Japan"},
	"KR": {"KR", "South Korea"},
	"IN": {"IN", "India"},
	"GB": {"GB", "United Kingdom"},
	"DE": {"DE", "Germany"},
	"FR": {"FR", "France"},
	"RU": {"RU", "Russia"},
	"BR": {"BR", "Brazil"},
	"CA": {"CA", "Canada"},
	"AU": {"AU", "Australia"},
	"MX": {"MX", "Mexico"},
	"ID": {"ID", "Indonesia"},
	"IT": {"IT", "Italy"},
	"ES": {"ES", "Spain"},
	"NL": {"NL", "Netherlands"},
	"SA": {"SA", "Saudi Arabia"},
	"TH": {"TH", "Thailand"},
	"VN": {"VN", "Vietnam"},
	"TR": {"TR", "Turkey"},
	"PL": {"PL", "Poland"},
	"UA": {"UA", "Ukraine"},
	"AR": {"AR", "Argentina"},
	"TW": {"TW", "Taiwan"},
	"HK": {"HK", "Hong Kong"},
	"SG": {"SG", "Singapore"},
	"MY": {"MY", "Malaysia"},
	"PH": {"PH", "Philippines"},
	"PK": {"PK", "Pakistan"},
	"BD": {"BD", "Bangladesh"},
	"EG": {"EG", "Egypt"},
	"NG": {"NG", "Nigeria"},
	"KE": {"KE", "Kenya"},
	"ZA": {"ZA", "South Africa"},
	"AE": {"AE", "UAE"},
	"IL": {"IL", "Israel"},
	"IR": {"IR", "Iran"},
	"IQ": {"IQ", "Iraq"},
}

func GetCountryGroup(isoCode string) string {
	if group, ok := ipGroupMap[isoCode]; ok {
		return group.CountryName
	}
	return isoCode
}

func LoadFromFile(dbPath string) (*Searcher, error) {
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cBuff, err := xdb.LoadContent(file)
	if err != nil {
		return nil, fmt.Errorf("加载ip2region数据库内容失败: %w", err)
	}

	header, err := xdb.LoadHeaderFromBuff(cBuff)
	if err != nil {
		return nil, fmt.Errorf("读取ip2region文件头失败: %w", err)
	}

	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("检测IP版本失败: %w", err)
	}

	inner, err := xdb.NewWithBuffer(version, cBuff)
	if err != nil {
		return nil, fmt.Errorf("创建ip2region查询器失败: %w", err)
	}

	return &Searcher{inner: inner}, nil
}
