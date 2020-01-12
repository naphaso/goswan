package transform

var authById = map[uint16]*Auth{}
var authByName = map[string]*Auth{}

type Auth struct {
	ID   uint16
	Name string
}

func MustRegisterAuth(id uint16, name string) {
	if _, ok := authById[id]; ok {
		panic("duplicate auth algo id")
	}

	if _, ok := authByName[name]; ok {
		panic("duplicate auth algo name")
	}

	a := &Auth{
		ID:   id,
		Name: name,
	}

	authById[id] = a
	authByName[name] = a
}

func FindAuth(id uint16) *Auth {
	return authById[id]
}
