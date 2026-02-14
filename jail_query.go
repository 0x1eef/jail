package jail

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

// Find a jail by ID.
func FindByID(jid int32) (*Jail, error) {
	var (
		null             = "\x00"
		name             = make([]byte, 1024)
		path             = make([]byte, 1024)
		hostname         = make([]byte, 1024)
		osrelease        = make([]byte, 1024)
		vnet             int32
		enforceStatFS    int32
		osreldate        int32
		secureLevel      int32
		parent           int32
		dying            int32
		persist          int32
		devfsRuleset     int32
		canSetHostname   int32
		canExtattr       int32
		canSetTime       int32
		canRoot          int32
		canChflags       int32
		canReservedPorts int32
		canRawSockets    int32
		canMount         int32
		canMountDevfs    int32
		canMountProcfs   int32
		canMountTmpfs    int32
		canMountNullfs   int32
		canMountZfs      int32
		canMlock         int32
		canReadMsgbuf    int32
		canSocketAF      int32
		canQuotas        int32
		canAdjTime       int32
		canRouting       int32
		canSetAudit      int32
		canUPDebug       int32
		canUPTamper      int32
		canVMM           int32
	)
	params := NewParams()
	params.Add("jid", jid)
	params.Add("name", name)
	params.Add("path", path)
	params.Add("vnet", &vnet)
	params.Add("enforce_statfs", &enforceStatFS)
	params.Add("host.hostname", hostname)
	params.Add("osrelease", osrelease)
	params.Add("osreldate", &osreldate)
	params.Add("securelevel", &secureLevel)
	params.Add("parent", &parent)
	params.Add("dying", &dying)
	params.Add("persist", &persist)
	params.Add("devfs_ruleset", &devfsRuleset)
	params.Add("allow.set_hostname", &canSetHostname)
	params.Add("allow.extattr", &canExtattr)
	params.Add("allow.settime", &canSetTime)
	params.Add("allow.suser", &canRoot)
	params.Add("allow.chflags", &canChflags)
	params.Add("allow.reserved_ports", &canReservedPorts)
	params.Add("allow.raw_sockets", &canRawSockets)
	params.Add("allow.mount", &canMount)
	params.Add("allow.mount.devfs", &canMountDevfs)
	params.Add("allow.mount.procfs", &canMountProcfs)
	params.Add("allow.mount.tmpfs", &canMountTmpfs)
	params.Add("allow.mount.nullfs", &canMountNullfs)
	params.Add("allow.mount.zfs", &canMountZfs)
	params.Add("allow.mlock", &canMlock)
	params.Add("allow.read_msgbuf", &canReadMsgbuf)
	params.Add("allow.socket_af", &canSocketAF)
	params.Add("allow.quotas", &canQuotas)
	params.Add("allow.adjtime", &canAdjTime)
	params.Add("allow.routing", &canRouting)
	params.Add("allow.setaudit", &canSetAudit)
	params.Add("allow.unprivileged_proc_debug", &canUPDebug)
	params.Add("allow.unprivileged_parent_tampering", &canUPTamper)
	params.Add("allow.vmm", &canVMM)
	if _, err := Get(params, 0); err != nil {
		return nil, err
	}
	return &Jail{
		ID:            jid,
		Name:          string(bytes.Trim(name, null)),
		Path:          string(bytes.Trim(path, null)),
		Hostname:      string(bytes.Trim(hostname, null)),
		OSRelease:     string(bytes.Trim(osrelease, null)),
		Vnet:          vnet == 1,
		EnforceStatFS: enforceStatFS,
		OSRelDate:     osreldate,
		SecureLevel:   secureLevel,
		Parent:        parent,
		DevFSRuleset:  devfsRuleset,
		Dying:         dying == 1,
		Persist:       persist == 1,
		Perms: Perms{
			AllowSetHostname:                 canSetHostname == 1,
			AllowExtattr:                     canExtattr == 1,
			AllowSetTime:                     canSetTime == 1,
			AllowRoot:                        canRoot == 1,
			AllowChflags:                     canChflags == 1,
			AllowReservedPorts:               canReservedPorts == 1,
			AllowRawSockets:                  canRawSockets == 1,
			AllowMount:                       canMount == 1,
			AllowMountDevfs:                  canMountDevfs == 1,
			AllowMountProcfs:                 canMountProcfs == 1,
			AllowMountTmpfs:                  canMountTmpfs == 1,
			AllowMountNullfs:                 canMountNullfs == 1,
			AllowMountZfs:                    canMountZfs == 1,
			AllowMlock:                       canMlock == 1,
			AllowReadMsgbuf:                  canReadMsgbuf == 1,
			AllowSocketAF:                    canSocketAF == 1,
			AllowQuotas:                      canQuotas == 1,
			AllowAdjTime:                     canAdjTime == 1,
			AllowRouting:                     canRouting == 1,
			AllowSetAudit:                    canSetAudit == 1,
			AllowUnprivilegedProcDebug:       canUPDebug == 1,
			AllowUnprivilegedParentTampering: canUPTamper == 1,
			AllowVMM:                         canVMM == 1,
		},
	}, nil
}

// Returns all living jails
func Living() ([]*Jail, error) {
	return filterByDying(false)
}

// Returns all dying jails
func Dying() ([]*Jail, error) {
	return filterByDying(true)
}

// Returns all known jails (both living and dying)
func All() ([]*Jail, error) {
	if ids, err := AllByID(); err != nil {
		return nil, err
	} else {
		jails := make([]*Jail, 0, len(ids))
		for _, id := range ids {
			if j, err := FindByID(id); err != nil {
				return nil, err
			} else {
				jails = append(jails, j)
			}
		}
		return jails, nil
	}
}

// Returns all known jail IDs (both living and dying)
func AllByID() ([]int32, error) {
	var (
		jids    []int32
		jid     int32 = 0
		lastjid int32 = 0
	)
	for {
		params := NewParams()
		params.Add("jid", &jid)
		params.Add("lastjid", &lastjid)
		if _, err := Get(params, 0); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return jids, nil
			}
			return jids, err
		}
		jids = append(jids, jid)
		lastjid = jid
	}
}

// Returns all known jail names (both living and dying)
func AllByName() ([]string, error) {
	ids, err := AllByID()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		j, err := FindByID(id)
		if err != nil {
			return nil, err
		}
		names = append(names, j.Name)
	}
	return names, nil
}

// Filters jails on their dying status
func filterByDying(dying bool) ([]*Jail, error) {
	if jails, err := All(); err != nil {
		return nil, err
	} else {
		slice := make([]*Jail, 0, len(jails))
		for _, j := range jails {
			if j.Dying == dying {
				slice = append(slice, j)
			}
		}
		return slice, nil
	}
}
