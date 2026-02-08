package jail

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

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
}

// Find a jail by ID.
func FindByID(jid int32) (*Jail, error) {
	var (
		null        = "\x00"
		name        = make([]byte, 1024)
		path        = make([]byte, 1024)
		hostname    = make([]byte, 1024)
		osrelease   = make([]byte, 1024)
		osreldate   int32
		secureLevel int32
		parent      int32
		dying       int32
		persist     int32
	)
	params := NewParams()
	params.Add("jid", jid)
	params.Add("name", name)
	params.Add("path", path)
	params.Add("host.hostname", hostname)
	params.Add("osrelease", osrelease)
	params.Add("osreldate", &osreldate)
	params.Add("securelevel", &secureLevel)
	params.Add("parent", &parent)
	params.Add("dying", &dying)
	params.Add("persist", &persist)
	if err := Get(params, 0); err != nil {
		return nil, err
	}
	return &Jail{
		ID:          jid,
		Name:        string(bytes.Trim(name, null)),
		Path:        string(bytes.Trim(path, null)),
		Hostname:    string(bytes.Trim(hostname, null)),
		OSRelease:   string(bytes.Trim(osrelease, null)),
		OSRelDate:   osreldate,
		SecureLevel: secureLevel,
		Parent:      parent,
		Dying:       dying == 1,
		Persist:     persist == 1,
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
		if err := Get(params, 0); err != nil {
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
