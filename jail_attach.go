package jail

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Attach receives a jail ID and attempts to attach the current
// process to that jail.
func Attach(jailID int32) error {
	return attachRemove(sysJailAttach, jailID)
}

// Remove receives a jail ID and attempts to remove the associated jail.
func Remove(jailID int32) error {
	return attachRemove(sysJailRemove, jailID)
}

// attachRemove
func attachRemove(call, jailID int32) error {
	jid := uintptr(unsafe.Pointer(&jailID))
	_, _, e1 := unix.Syscall(uintptr(call), jid, 0, 0)
	if e1 != 0 {
		switch int(e1) {
		case ErrJailAttachUnprivilegedUser:
			return fmt.Errorf("unprivileged user")
		case ErrjailAttachJIDNotExist:
			return fmt.Errorf("JID does not exist")
		}
	}

	return nil
}
