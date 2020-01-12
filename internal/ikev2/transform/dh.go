package transform

var dhById = map[uint16]*DH{}
var dhByName = map[string]*DH{}

type DH struct {
	ID   uint16
	Name string
}

func MustRegisterDH(id uint16, name string) {
	if _, ok := dhById[id]; ok {
		panic("duplicate dh algo id")
	}

	if _, ok := dhByName[name]; ok {
		panic("duplicate dh algo name")
	}

	d := &DH{
		ID:   id,
		Name: name,
	}

	dhById[id] = d
	dhByName[name] = d
}

func FindDH(id uint16) *DH {
	return dhById[id]
}
