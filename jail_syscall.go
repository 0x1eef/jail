package jail

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const EtcdConfigFile = "/etc/jail.conf"

const (
	sysJail       = 338
	sysJailAttach = 436
	sysJailGet    = 506
	sysJailSet    = 507
	sysJailRemove = 508
)

const (
	// CreateFlag Create a new jail. If a jid or name parameters exists, they
	// must not refer to an existing jail.
	CreateFlag = uintptr(0x01)

	// UpdateFlag Modify an existing jail. One of the jid or name parameters must
	// exist, and must refer to an existing jail. If both JAIL_CREATE and JAIL_UPDATE
	// are set, a jail will be created if it does not yet exist, and modified if
	// it does exist.
	UpdateFlag = uintptr(0x02)

	// AttachFlag In addition to creating or modifying the jail, attach the current
	// process to it, as with the jail_attach() system call.
	AttachFlag = uintptr(0x04)

	// DyingFlag Allow setting a jail that is in the process of being removed.
	DyingFlag = uintptr(0x08)

	// SetMaskFlag ...
	SetMaskFlag = uintptr(0x0f)

	// GetMaskFlag ...
	GetMaskFlag = uintptr(0x08)
)

// jailAPIVersion is the current jail API version.
const jailAPIVersion uint32 = 2

// MaxChildJails is the maximum number of jails
// for the system.
const MaxChildJails int64 = 999999

// jail_get(2) system call
func get(iov []unix.Iovec, keep []interface{}, flags uintptr) error {
	_, _, e1 := unix.Syscall(uintptr(sysJailGet), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), flags)
	runtime.KeepAlive(keep)
	if e1 != 0 {
		switch int(e1) {
		case ErrJailGetFaultOutsideOfAllocatedSpace:
			return fmt.Errorf("fault outside of allocated space: %w", e1)
		case enoent:
			return fmt.Errorf("jail referred to either does not exist or is inaccessible: %w", e1)
		case einval:
			return fmt.Errorf("invalid param provided: %w", e1)
		}
	}
	return nil
}

// jail_set(2) system call
func set(iov []unix.Iovec, keep []interface{}, flags uintptr) error {
	_, _, e1 := unix.Syscall(uintptr(sysJailSet), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)), flags)
	runtime.KeepAlive(keep)
	if e1 != 0 {
		switch int(e1) {
		case eperm:
			return fmt.Errorf("not allowed or restricted: %w", e1)
		case ErrJailSetFaultOutsideOfAllocatedSpace:
			return fmt.Errorf("fault outside of allocated space: %w", e1)
		case ErrJailSetParamNotExist, ErrJailSetParamWrongSize:
			return fmt.Errorf("invalid param provided: %w", e1)
		case ErrJailSetUpdateFlagNotSet:
			return fmt.Errorf("set update flag not set: %w", e1)
		case ErrJailSetNameTooLong:
			return fmt.Errorf("set name too long: %w", e1)
		case ErrJailSetNoIDsLeft:
			return fmt.Errorf("no JID's left: %w", e1)
		}
	}
	return nil
}
