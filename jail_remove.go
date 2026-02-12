package jail

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Removes a jail
func Remove(jid int32) error {
	_, _, e1 := unix.Syscall(uintptr(sysJailRemove), uintptr(jid), 0, 0)
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
