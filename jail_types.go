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
	AllowSetHostname   bool `json:"allow_sethostname"`
	AllowExtattr       bool `json:"allow_extattr"`
	AllowReservedPorts bool `json:"allow_reservedports"`
	AllowSetTime       bool `json:"allow_settime"`
	AllowRoot          bool `json:"allow_suser"`
	AllowChflags       bool `json:"allow_chflags"`
}

// Allow sethostname(3) in a jail
func (j *Jail) AllowSetHostname() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.set_hostname", int32(1))
	return Set(params, UpdateFlag)
}

// Deny sethostname(3) in a jail
func (j *Jail) DenySetHostname() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.noset_hostname", int32(1))
	return Set(params, UpdateFlag)
}

// Allow use of extended attributes
func (j *Jail) AllowExtattr() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.extattr", int32(1))
	return Set(params, UpdateFlag)
}

// Deny use of extended attributes
func (j *Jail) DenyExtattr() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.noextattr", int32(1))
	return Set(params, UpdateFlag)
}

// Allow setting global system time (eg via date(1))
func (j *Jail) AllowSetTime() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.settime", int32(1))
	return Set(params, UpdateFlag)
}

// Deny setting global system time
func (j *Jail) DenySetTime() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.nosettime", int32(1))
	return Set(params, UpdateFlag)
}

// Allow root to act as a superuser
func (j *Jail) AllowRoot() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.suser", int32(1))
	return Set(params, UpdateFlag)
}

// Deny root to act as a superuser
func (j *Jail) DenyRoot() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.nosuser", int32(1))
	return Set(params, UpdateFlag)
}

// Allow chflags(2) inside the jail
func (j *Jail) AllowChflags() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.chflags", int32(1))
	return Set(params, UpdateFlag)
}

// Deny chflags(2) inside the jail
func (j *Jail) DenyChflags() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.nochflags", int32(1))
	return Set(params, UpdateFlag)
}

// Allow jail root to bind to ports lower than 1024
func (j *Jail) AllowReservedPorts() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.reserved_ports", int32(1))
	return Set(params, UpdateFlag)
}

// Deny jail root to bind to ports lower than 1024
func (j *Jail) DenyReservedPorts() error {
	params := NewParams()
	params.Add("jid", j.ID)
	params.Add("allow.noreserved_ports", int32(1))
	return Set(params, UpdateFlag)
}
