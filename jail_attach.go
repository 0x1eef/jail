package jail

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Attach the current proccess to a jail
func Attach(jid int32) error {
	_, _, e1 := unix.Syscall(uintptr(sysJailAttach), uintptr(jid), 0, 0)
	if e1 != 0 {
		switch int(e1) {
		case ErrJailAttachUnprivilegedUser:
			return fmt.Errorf("unprivileged user")
		case ErrjailAttachJIDNotExist:
			return fmt.Errorf("JID does not exist")
		default:
			return fmt.Errorf("%v", e1)
		}
	}
	return nil
}
