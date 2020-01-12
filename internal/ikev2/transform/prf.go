package transform

var prfById = map[uint16]*PRF{}
var prfByName = map[string]*PRF{}

type PRF struct {
	ID   uint16
	Name string
}

func MustRegisterPRF(id uint16, name string) {
	if _, ok := prfById[id]; ok {
		panic("duplicate prf algo id")
	}

	if _, ok := prfByName[name]; ok {
		panic("duplicate prf algo name")
	}

	p := &PRF{
		ID:   id,
		Name: name,
	}

	prfById[id] = p
	prfByName[name] = p
}

func FindPRF(id uint16) *PRF {
	return prfById[id]
}
