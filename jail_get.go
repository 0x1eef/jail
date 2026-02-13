package jail

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// jail_get(2) wrapper
func Get(params Params, flags uintptr) (int32, error) {
	iov, keep, err := params.buildIovec()
	if err != nil {
		return 0, err
	}
	return get(iov, keep, flags)
}

// jail_get(2)
func get(iov []unix.Iovec, keep []any, flags uintptr) (int32, error) {
	jid, _, e1 := unix.Syscall(uintptr(sysJailGet), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), flags)
	runtime.KeepAlive(keep)
	if e1 != 0 {
		switch int(e1) {
		case ErrJailGetFaultOutsideOfAllocatedSpace:
			return 0, fmt.Errorf("fault outside of allocated space: %w", e1)
		case enoent:
			return 0, fmt.Errorf("jail referred to either does not exist or is inaccessible: %w", e1)
		case einval:
			return 0, fmt.Errorf("invalid param provided: %w", e1)
		default:
			return 0, fmt.Errorf("%w", e1)
		}
	}
	return int32(jid), nil
}
