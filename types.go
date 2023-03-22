package linceClient

type Licenses struct {
	product        string
	license        string
	maxConnections int
	connections    int
}

type Answer struct {
	Status    string `json:"status"`
	Signature string `json:"signature"`
}

type Status struct {
	Status string `json:"status"`
}