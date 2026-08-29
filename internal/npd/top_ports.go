package npd

const MaxCuratedTopPorts = 100

var curatedTopTCPPorts = []uint16{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
	79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 512, 513, 514, 515, 543, 544, 548, 554, 587,
	593, 631, 646, 873, 902, 990, 993, 995, 1025, 1026,
	1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900,
	2000, 2001, 2049, 2121, 2375, 2376, 2483, 2484, 3000, 3128,
	3268, 3306, 3389, 3690, 4000, 4444, 5000, 5001, 5060, 5061,
	5432, 5672, 5900, 5985, 5986, 6000, 6379, 6667, 7001, 8000,
	8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 10000,
}

// TopPorts returns the first n ports from Wraith's curated common TCP port set.
// The returned slice is a copy and can be safely modified by callers.
func TopPorts(n int) ([]uint16, error) {
	if n < 1 {
		return nil, ErrInvalidSpec
	}
	if n > len(curatedTopTCPPorts) {
		return nil, ErrPortLimit
	}
	return append([]uint16(nil), curatedTopTCPPorts[:n]...), nil
}

// Top100 returns Wraith's curated 100 common TCP ports.
func Top100() []uint16 {
	ports, _ := TopPorts(MaxCuratedTopPorts)
	return ports
}

// AllPorts returns every TCP port from 1 through 65535.
func AllPorts() []uint16 {
	ports := make([]uint16, MaxPorts)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	return ports
}
