package jail

// Set creates a new jail, or modifies an existing
// one, and optionally locks the current process in it.
func Set(params Params, flags uintptr) error {
	iov, keep, err := params.buildIovec()
	if err != nil {
		return err
	}
	return set(iov, keep, flags)
}

// Get retrieves a matching jail based on the provided params.
func Get(params Params, flags uintptr) error {
	iov, keep, err := params.buildIovec()
	if err != nil {
		return err
	}
	return get(iov, keep, flags)
}
