package jail

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Opts holds the options to be passed in to
// create the new jail.
type Opts struct {
	Version  uint32
	Path     string
	Name     string
	Hostname string
	IP4      string
	Chdir    bool
}

// Create takes the given parameters, validates, and creates a new jail.
func Create(o *Opts) (int32, error) {
	if err := o.validate(); err != nil {
		return 0, err
	}

	jn, err := unix.BytePtrFromString(o.Name)
	if err != nil {
		return 0, err
	}

	jp, err := unix.BytePtrFromString(o.Path)
	if err != nil {
		return 0, err
	}

	hn, err := unix.BytePtrFromString(o.Name)
	if err != nil {
		return 0, err
	}

	j := &jail{
		Version:  o.Version,
		Path:     uintptr(unsafe.Pointer(jp)),
		Hostname: uintptr(unsafe.Pointer(hn)),
		Name:     uintptr(unsafe.Pointer(jn)),
	}
	if o.IP4 != "" {
		uint32ip := ip2int(net.ParseIP(o.IP4))
		ia := &inAddr{
			sAddr: inAddrT(uint32ip),
		}
		j.IP4s = 1
		j.IP6s = uint32(0)
		j.IP4 = uintptr(unsafe.Pointer(ia))
	}

	r1, _, e1 := unix.Syscall(sysJail, uintptr(unsafe.Pointer(j)), 0, 0)
	if e1 != 0 {
		switch int(e1) {
		case ErrJailPermDenied:
			return 0, fmt.Errorf("unprivileged user: %d", e1)
		case ErrJailFaultOutsideOfAllocatedSpace:
			return 0, fmt.Errorf("fault outside of allocation space: %d", e1)
		case ErrJailInvalidVersion:
			return 0, fmt.Errorf("invalid version: %d", e1)
		case ErrjailNoFreeJIDFound:
			return 0, fmt.Errorf("no free JID found: %d", e1)
		case ErrJailNoSuchFileDirectory:
			return 0, fmt.Errorf("No such file or directory: %s\n", o.Path)
		}
		return 0, fmt.Errorf("%d", e1)
	}

	if o.Chdir {
		if err := os.Chdir("/"); err != nil {
			return 0, err
		}
	}

	return int32(r1), nil
}

// validate makes sure the required fields are present.
func (o *Opts) validate() error {
	if o.Path == "" {
		return errors.New("missing path")
	}
	if o.Name == "" {
		return errors.New("missing name")
	}

	return nil
}

// Clone creates a new version of the previously created jail.
func (j *jail) Clone() (int, error) {
	nj := &jail{
		Version:  j.Version,
		Path:     j.Path,
		Name:     j.Name,
		Hostname: j.Hostname,
	}

	r1, _, e1 := unix.Syscall(sysJail, uintptr(unsafe.Pointer(nj)), 0, 0)
	if e1 != 0 {
		return 0, fmt.Errorf("%d", e1)
	}

	return int(r1), nil
}

// jail contains the data that will be passed into
// the jail(2) syscall.
type jail struct {
	Version  uint32
	Path     uintptr
	Name     uintptr
	Hostname uintptr
	IP4s     uint32
	IP6s     uint32
	IP4      uintptr
	IP6      uintptr
}

// typedef uint32_t in_addr_t
type inAddrT uint32

// inAddr
type inAddr struct {
	sAddr inAddrT
}

// ip2int converts the given IP address to an uint32.
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}

	return binary.LittleEndian.Uint32(ip)
}

// uint32ip converts an uint32 representation of a string into an IP.
func uint32ip(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)

	return ip.String()
}
