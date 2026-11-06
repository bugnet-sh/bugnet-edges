package tlsconf

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// checkEvery is how often a pair's files are checked for a new modification time
const checkEvery = time.Minute

// pairFile is fullchain.pem and key.pem in one directory, loaded again once either file changes
type pairFile struct {
	dir string
	now func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]time.Time
	checked time.Time
}

func loadPair(dir string, now func() time.Time) (*pairFile, error) {
	p := &pairFile{dir: dir, now: now, checked: now()}
	stamp, err := p.stamps()
	if err != nil {
		return nil, err
	}
	if err := p.load(stamp); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pairFile) paths() [2]string {
	return [2]string{filepath.Join(p.dir, "fullchain.pem"), filepath.Join(p.dir, "key.pem")}
}

func (p *pairFile) stamps() ([2]time.Time, error) {
	var out [2]time.Time
	for i, path := range p.paths() {
		fi, err := os.Stat(path)
		if err != nil {
			return out, err
		}
		out[i] = fi.ModTime()
	}
	return out, nil
}

func (p *pairFile) load(stamp [2]time.Time) error {
	paths := p.paths()
	cert, err := tls.LoadX509KeyPair(paths[0], paths[1])
	if err != nil {
		return err
	}
	p.cert, p.stamp = &cert, stamp
	return nil
}

// current is the pair to serve, the last good one while the files are missing or do not match
func (p *pairFile) current() *tls.Certificate {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now := p.now(); now.Sub(p.checked) >= checkEvery {
		p.checked = now
		if stamp, err := p.stamps(); err == nil && stamp != p.stamp {
			_ = p.load(stamp)
		}
	}
	return p.cert
}

func (p *pairFile) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.current(), nil
}
