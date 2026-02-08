package jail

type Jail struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Hostname    string `json:"hostname"`
	OSRelease   string `json:"osrelease"`
	OSRelDate   int32  `json:"osreldate"`
	ID          int32  `json:"id"`
	SecureLevel int32  `json:"securelevel"`
	Parent      int32  `json:"parent"`
	Dying       bool   `json:"dying"`
	Persist     bool   `json:"persist"`
	Perms       Perms  `json:"perms"`
}

type Perms struct {
	AllowSetHostname bool `json:"set_hostname"`
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
