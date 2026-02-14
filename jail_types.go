package jail

type Jail struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Hostname      string `json:"hostname"`
	OSRelease     string `json:"osrelease"`
	OSRelDate     int32  `json:"osreldate"`
	ID            int32  `json:"id"`
	SecureLevel   int32  `json:"securelevel"`
	Parent        int32  `json:"parent"`
	EnforceStatFS int32  `json:"enforce_statfs"`
	DevFSRuleset  int32  `json:"devfs_ruleset"`
	Vnet          bool   `json:"vnet"`
	Dying         bool   `json:"dying"`
	Persist       bool   `json:"persist"`
	Perms         Perms  `json:"perms"`
}

type Perms struct {
	AllowSetHostname                 bool `json:"allow_sethostname"`
	AllowExtattr                     bool `json:"allow_extattr"`
	AllowReservedPorts               bool `json:"allow_reservedports"`
	AllowSetTime                     bool `json:"allow_settime"`
	AllowRoot                        bool `json:"allow_suser"`
	AllowChflags                     bool `json:"allow_chflags"`
	AllowRawSockets                  bool `json:"allow_raw_sockets"`
	AllowMount                       bool `json:"allow_mount"`
	AllowMountDevfs                  bool `json:"allow_mount_devfs"`
	AllowMountProcfs                 bool `json:"allow_mount_procfs"`
	AllowMountTmpfs                  bool `json:"allow_mount_tmpfs"`
	AllowMountNullfs                 bool `json:"allow_mount_nullfs"`
	AllowMountZfs                    bool `json:"allow_mount_zfs"`
	AllowMlock                       bool `json:"allow_mlock"`
	AllowReadMsgbuf                  bool `json:"allow_read_msgbuf"`
	AllowSocketAF                    bool `json:"allow_socket_af"`
	AllowQuotas                      bool `json:"allow_quotas"`
	AllowAdjTime                     bool `json:"allow_adjtime"`
	AllowRouting                     bool `json:"allow_routing"`
	AllowSetAudit                    bool `json:"allow_setaudit"`
	AllowUnprivilegedProcDebug       bool `json:"allow_unprivileged_proc_debug"`
	AllowUnprivilegedParentTampering bool `json:"allow_unprivileged_parent_tampering"`
	AllowVMM                         bool `json:"allow_vmm"`
}

// Allow sethostname(3) in a jail
func (j *Jail) AllowSetHostname() error {
	return j.SetParam("allow.set_hostname", int32(1))
}

// Deny sethostname(3) in a jail
func (j *Jail) DenySetHostname() error {
	return j.SetParam("allow.noset_hostname", int32(1))
}

// Allow use of extended attributes
func (j *Jail) AllowExtattr() error {
	return j.SetParam("allow.extattr", int32(1))
}

// Deny use of extended attributes
func (j *Jail) DenyExtattr() error {
	return j.SetParam("allow.noextattr", int32(1))
}

// Allow setting global system time (eg via date(1))
func (j *Jail) AllowSetTime() error {
	return j.SetParam("allow.settime", int32(1))
}

// Deny setting global system time
func (j *Jail) DenySetTime() error {
	return j.SetParam("allow.nosettime", int32(1))
}

// Allow root to act as a superuser
func (j *Jail) AllowRoot() error {
	return j.SetParam("allow.suser", int32(1))
}

// Deny root to act as a superuser
func (j *Jail) DenyRoot() error {
	return j.SetParam("allow.nosuser", int32(1))
}

// Allow chflags(2) inside the jail
func (j *Jail) AllowChflags() error {
	return j.SetParam("allow.chflags", int32(1))
}

// Deny chflags(2) inside the jail
func (j *Jail) DenyChflags() error {
	return j.SetParam("allow.nochflags", int32(1))
}

// Allow jail root to bind to ports lower than 1024
func (j *Jail) AllowReservedPorts() error {
	return j.SetParam("allow.reserved_ports", int32(1))
}

// Deny jail root to bind to ports lower than 1024
func (j *Jail) DenyReservedPorts() error {
	return j.SetParam("allow.noreserved_ports", int32(1))
}

// Allow raw sockets inside the jail
func (j *Jail) AllowRawSockets() error {
	return j.SetParam("allow.raw_sockets", int32(1))
}

// Deny raw sockets inside the jail
func (j *Jail) DenyRawSockets() error {
	return j.SetParam("allow.noraw_sockets", int32(1))
}

// Allow mounting of jail-friendly filesystems
func (j *Jail) AllowMount() error {
	return j.SetParam("allow.mount", int32(1))
}

// Deny mounting of jail-friendly filesystems
func (j *Jail) DenyMount() error {
	return j.SetParam("allow.nomount", int32(1))
}

// Allow mounting devfs inside the jail
func (j *Jail) AllowMountDevfs() error {
	return j.SetParam("allow.mount.devfs", int32(1))
}

// Deny mounting devfs inside the jail
func (j *Jail) DenyMountDevfs() error {
	return j.SetParam("allow.nomount.devfs", int32(1))
}

// Allow mounting procfs inside the jail
func (j *Jail) AllowMountProcfs() error {
	return j.SetParam("allow.mount.procfs", int32(1))
}

// Deny mounting procfs inside the jail
func (j *Jail) DenyMountProcfs() error {
	return j.SetParam("allow.nomount.procfs", int32(1))
}

// Allow mounting tmpfs inside the jail
func (j *Jail) AllowMountTmpfs() error {
	return j.SetParam("allow.mount.tmpfs", int32(1))
}

// Deny mounting tmpfs inside the jail
func (j *Jail) DenyMountTmpfs() error {
	return j.SetParam("allow.nomount.tmpfs", int32(1))
}

// Allow mounting nullfs inside the jail
func (j *Jail) AllowMountNullfs() error {
	return j.SetParam("allow.mount.nullfs", int32(1))
}

// Deny mounting nullfs inside the jail
func (j *Jail) DenyMountNullfs() error {
	return j.SetParam("allow.nomount.nullfs", int32(1))
}

// Allow mounting ZFS inside the jail
func (j *Jail) AllowMountZfs() error {
	return j.SetParam("allow.mount.zfs", int32(1))
}

// Deny mounting ZFS inside the jail
func (j *Jail) DenyMountZfs() error {
	return j.SetParam("allow.nomount.zfs", int32(1))
}

// Allow mlock(2) inside the jail
func (j *Jail) AllowMlock() error {
	return j.SetParam("allow.mlock", int32(1))
}

// Deny mlock(2) inside the jail
func (j *Jail) DenyMlock() error {
	return j.SetParam("allow.nomlock", int32(1))
}

// Allow reading kernel message buffer inside the jail
func (j *Jail) AllowReadMsgbuf() error {
	return j.SetParam("allow.read_msgbuf", int32(1))
}

// Deny reading kernel message buffer inside the jail
func (j *Jail) DenyReadMsgbuf() error {
	return j.SetParam("allow.noread_msgbuf", int32(1))
}

// Allow access to additional socket address families
func (j *Jail) AllowSocketAF() error {
	return j.SetParam("allow.socket_af", int32(1))
}

// Deny access to additional socket address families
func (j *Jail) DenySocketAF() error {
	return j.SetParam("allow.nosocket_af", int32(1))
}

// Allow administering quotas inside the jail
func (j *Jail) AllowQuotas() error {
	return j.SetParam("allow.quotas", int32(1))
}

// Deny administering quotas inside the jail
func (j *Jail) DenyQuotas() error {
	return j.SetParam("allow.noquotas", int32(1))
}

// Allow adjtime(2) inside the jail
func (j *Jail) AllowAdjTime() error {
	return j.SetParam("allow.adjtime", int32(1))
}

// Deny adjtime(2) inside the jail
func (j *Jail) DenyAdjTime() error {
	return j.SetParam("allow.noadjtime", int32(1))
}

// Allow modifying routing table inside the jail
func (j *Jail) AllowRouting() error {
	return j.SetParam("allow.routing", int32(1))
}

// Deny modifying routing table inside the jail
func (j *Jail) DenyRouting() error {
	return j.SetParam("allow.norouting", int32(1))
}

// Allow setting audit session state inside the jail
func (j *Jail) AllowSetAudit() error {
	return j.SetParam("allow.setaudit", int32(1))
}

// Deny setting audit session state inside the jail
func (j *Jail) DenySetAudit() error {
	return j.SetParam("allow.nosetaudit", int32(1))
}

// Allow unprivileged process debugging inside the jail
func (j *Jail) AllowUnprivilegedProcDebug() error {
	return j.SetParam("allow.unprivileged_proc_debug", int32(1))
}

// Deny unprivileged process debugging inside the jail
func (j *Jail) DenyUnprivilegedProcDebug() error {
	return j.SetParam("allow.nounprivileged_proc_debug", int32(1))
}

// Allow unprivileged parent tampering with jail processes
func (j *Jail) AllowUnprivilegedParentTampering() error {
	return j.SetParam("allow.unprivileged_parent_tampering", int32(1))
}

// Deny unprivileged parent tampering with jail processes
func (j *Jail) DenyUnprivilegedParentTampering() error {
	return j.SetParam("allow.nounprivileged_parent_tampering", int32(1))
}

// Allow VMM access inside the jail
func (j *Jail) AllowVMM() error {
	return j.SetParam("allow.vmm", int32(1))
}

// Deny VMM access inside the jail
func (j *Jail) DenyVMM() error {
	return j.SetParam("allow.novmm", int32(1))
}

// Set the jail name
func (j *Jail) SetName(name string) error {
	return j.SetParam("name", name)
}

// Set the jail hostname
func (j *Jail) SetHostname(name string) error {
	return j.SetParam("host.hostname", name)
}

// Set an arbitrary jail param
func (j *Jail) SetParam(name string, v any) error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add(name, v)
	_, err := Set(params, UpdateFlag)
	return err
}

// Attach the current process to a jail
func (j *Jail) Attach() error {
	return Attach(j.ID)
}

// Remove a jail
func (j *Jail) Remove() error {
	return Remove(j.ID)
}
