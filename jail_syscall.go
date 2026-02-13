package jail

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
