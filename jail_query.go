package jail

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Find a jail by ID.
func FindByID(jid int32) (*Jail, error) {
	j := &Jail{ID: jid}
	setBool := func(target *bool, mib string) error {
		v, err := j.GetBool(mib)
		if err != nil {
			return err
		}
		*target = v
		return nil
	}
	setBoolOptional := func(target *bool, mib string) error {
		v, err := j.GetBool(mib)
		if err != nil {
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
				return nil
			}
			return err
		}
		*target = v
		return nil
	}
	var err error
	if j.Name, err = j.GetString("name"); err != nil {
		return nil, err
	}
	if j.Path, err = j.GetString("path"); err != nil {
		return nil, err
	}
	if j.Hostname, err = j.GetString("host.hostname"); err != nil {
		return nil, err
	}
	if j.OSRelease, err = j.GetString("osrelease"); err != nil {
		return nil, err
	}
	if j.EnforceStatFS, err = j.GetInt32("enforce_statfs"); err != nil {
		return nil, err
	}
	if j.OSRelDate, err = j.GetInt32("osreldate"); err != nil {
		return nil, err
	}
	if j.SecureLevel, err = j.GetInt32("securelevel"); err != nil {
		return nil, err
	}
	if j.Parent, err = j.GetInt32("parent"); err != nil {
		return nil, err
	}
	if j.DevFSRuleset, err = j.GetInt32("devfs_ruleset"); err != nil {
		return nil, err
	}
	if j.Vnet, err = j.GetBool("vnet"); err != nil {
		return nil, err
	}
	if j.Dying, err = j.GetBool("dying"); err != nil {
		return nil, err
	}
	if j.Persist, err = j.GetBool("persist"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowSetHostname, "allow.set_hostname"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowExtattr, "allow.extattr"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowReservedPorts, "allow.reserved_ports"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowSetTime, "allow.settime"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowRoot, "allow.suser"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowChflags, "allow.chflags"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowRawSockets, "allow.raw_sockets"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowMount, "allow.mount"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowMountDevfs, "allow.mount.devfs"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowMlock, "allow.mlock"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowReadMsgbuf, "allow.read_msgbuf"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowSocketAF, "allow.socket_af"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowQuotas, "allow.quotas"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowAdjTime, "allow.adjtime"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowRouting, "allow.routing"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowSetAudit, "allow.setaudit"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowUnprivilegedProcDebug, "allow.unprivileged_proc_debug"); err != nil {
		return nil, err
	}
	if err := setBool(&j.Perms.AllowUnprivilegedParentTampering, "allow.unprivileged_parent_tampering"); err != nil {
		return nil, err
	}
	if err := setBoolOptional(&j.Perms.AllowMountProcfs, "allow.mount.procfs"); err != nil {
		return nil, err
	}
	if err := setBoolOptional(&j.Perms.AllowMountTmpfs, "allow.mount.tmpfs"); err != nil {
		return nil, err
	}
	if err := setBoolOptional(&j.Perms.AllowMountNullfs, "allow.mount.nullfs"); err != nil {
		return nil, err
	}
	if err := setBoolOptional(&j.Perms.AllowMountZfs, "allow.mount.zfs"); err != nil {
		return nil, err
	}
	if err := setBoolOptional(&j.Perms.AllowVMM, "allow.vmm"); err != nil {
		return nil, err
	}
	return j, nil
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
