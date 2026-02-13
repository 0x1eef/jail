package jail

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// jail_set(2) wrapper
func Set(params Params, flags uintptr) (int32, error) {
	iov, keep, err := params.buildIovec()
	if err != nil {
		return 0, err
	}
	return set(iov, keep, flags)
}

// jail_set(2)
func set(iov []unix.Iovec, keep []interface{}, flags uintptr) (int32, error) {
	jid, _, e1 := unix.Syscall(uintptr(sysJailSet), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), flags)
	runtime.KeepAlive(keep)
	if e1 != 0 {
		switch int(e1) {
		case eperm:
			return 0, fmt.Errorf("not allowed or restricted: %w", e1)
		case ErrJailSetFaultOutsideOfAllocatedSpace:
			return 0, fmt.Errorf("fault outside of allocated space: %w", e1)
		case ErrJailSetParamNotExist, ErrJailSetParamWrongSize:
			return 0, fmt.Errorf("invalid param provided: %w", e1)
		case ErrJailSetUpdateFlagNotSet:
			return 0, fmt.Errorf("set update flag not set: %w", e1)
		case ErrJailSetNameTooLong:
			return 0, fmt.Errorf("set name too long: %w", e1)
		case ErrJailSetNoIDsLeft:
			return 0, fmt.Errorf("no JID's left: %w", e1)
		}
	}
	return int32(jid), nil
}
