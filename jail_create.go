package jail

// Creates a new jail
func NewJail(path string) (*Jail, error) {
	params := NewParams()
	params.Add("path", path)
	params.Add("persist", int32(1))
	if jid, err := Set(params, CreateFlag); err != nil {
		return nil, err
	} else {
		if j, err := FindByID(jid); err != nil {
			return nil, err
		} else {
			return j, nil
		}
	}
}
