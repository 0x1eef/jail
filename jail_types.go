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
	return j.SetParam("allow.nosuer", int32(1))
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
