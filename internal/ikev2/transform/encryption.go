package transform

type Encryption struct {
	ID     uint16
	Name   string
	KeyLen uint16
}

var encriptionById = map[uint16][]*Encryption{}
var encriptionByName = map[string]*Encryption{}

func MustRegisterEncryption(id uint16, name string, keyLen uint16) {
	if _, ok := encriptionById[id]; ok {
		panic("duplicate encryption algo")
	}

	if _, ok := encriptionByName[name]; ok {
		panic("duplicate encryption name")
	}

	e := &Encryption{
		ID:     id,
		Name:   name,
		KeyLen: keyLen,
	}
	encriptionById[id] = append(encriptionById[id], e)
	encriptionByName[name] = e
}

func FindEncryption(id uint16, keyLen uint16) *Encryption {
	es := encriptionById[id]
	for _, e := range es {
		if e.KeyLen == keyLen {
			return e
		}
	}
	return nil
}
