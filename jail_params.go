package jail

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	JailRawValue    = 0x01
	JailBool        = 0x02
	JailParamNoBool = 0x04
	JailParamSys    = 0x80
)

// JailParam
// TODO(briandowns) add more as they are identified.
type JailParam struct {
	Name       string
	Value      interface{}
	ValueLen   int
	ElemLen    int
	CtlType    int
	StructType int
	Flags      int
}

// Params contains the individual settings passed in to either get
// or set a jail.
type Params map[string]interface{}

// NewParams creates a new value of type Params by
// initializing the underlying map.
func NewParams() Params {
	return make(map[string]interface{})
}

// Add adds the given key and value to the params map.
func (p Params) Add(k string, v interface{}) error {
	if p == nil {
		return errors.New("cannot assign values to nil map")
	}

	if _, ok := p[k]; !ok {
		p[k] = v
		return nil
	}

	return fmt.Errorf("key of %q already set with value of %v", k, p[k])
}

// Validate is used to make sure that the params assigned
// are indeed correct and usable. This has been exposed for
// a caller to do validation as well as the package interally.
func (p Params) Validate() error {
	return nil
}

// buildIovec takes the containing map value and builds
// out a slice of syscall.Iovec.
func (p Params) buildIovec() ([]unix.Iovec, []interface{}, error) {
	iovec := make([]unix.Iovec, 0, len(p)*2)
	keep := make([]interface{}, 0, len(p)*2)
	for k, v := range p {
		kb := append([]byte(k), 0)
		iovec = append(iovec, unix.Iovec{
			Base: &kb[0],
			Len:  uint64(len(kb)),
		})
		keep = append(keep, kb)
		base, size, keepv, err := p.encodeParamValue(v)
		if err != nil {
			return nil, nil, errors.New("invalid value passed in for key: " + k)
		}
		keep = append(keep, keepv)
		iovec = append(iovec, unix.Iovec{
			Base: base,
			Len:  size,
		})
	}
	return iovec, keep, nil
}

func (p Params) encodeParamValue(v interface{}) (*byte, uint64, interface{}, error) {
	switch vv := v.(type) {
	case []byte:
		if len(vv) == 0 {
			return nil, 0, nil, errors.New("invalid value")
		}
		return &vv[0], uint64(len(vv)), vv, nil
	case string:
		vb := append([]byte(vv), 0)
		return &vb[0], uint64(len(vb)), vb, nil
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Ptr:
			if rv.IsNil() {
				return nil, 0, nil, errors.New("invalid value")
			}
			ev := rv.Elem()
			switch ev.Kind() {
			case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return (*byte)(unsafe.Pointer(rv.Pointer())), uint64(ev.Type().Size()), v, nil
			default:
				return nil, 0, nil, errors.New("invalid value")
			}
		case reflect.Bool:
			b := int32(0)
			if rv.Bool() {
				b = 1
			}
			return (*byte)(unsafe.Pointer(&b)), uint64(unsafe.Sizeof(b)), &b, nil
		case reflect.Int:
			n := int(rv.Int())
			return (*byte)(unsafe.Pointer(&n)), uint64(unsafe.Sizeof(n)), &n, nil
		case reflect.Int8:
			n := int8(rv.Int())
			return (*byte)(unsafe.Pointer(&n)), uint64(unsafe.Sizeof(n)), &n, nil
		case reflect.Int16:
			n := int16(rv.Int())
			return (*byte)(unsafe.Pointer(&n)), uint64(unsafe.Sizeof(n)), &n, nil
		case reflect.Int32:
			n := int32(rv.Int())
			return (*byte)(unsafe.Pointer(&n)), uint64(unsafe.Sizeof(n)), &n, nil
		case reflect.Int64:
			n := int64(rv.Int())
			return (*byte)(unsafe.Pointer(&n)), uint64(unsafe.Sizeof(n)), &n, nil
		default:
			return nil, 0, nil, errors.New("invalid value")
		}
	}
}
