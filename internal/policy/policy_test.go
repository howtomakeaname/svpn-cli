package policy

import "testing"

func TestIssuedRulesAndBoundaries(t *testing.T) {
	p, err := Parse([]byte(`{"RetCode":0,"BusinessList":[{"BusinessId":143,"Data":{"Configs":[{"Details":{"switch":"1","smartgate_details":[{"id":"sg1","set_id":"set1"}],"accessiblearea":[
{"areaid":"ip","type":"ip","connaddr":"172.16.0.1-172.31.255.254;2001:db8::/32","filterport":"1","connport":"22","protocol":"2","smartgate_id":["sg1"]},
{"areaid":"domain","type":"domain","connaddr":"*.campus.example","filterport":"1","connport":"80","filterport_v1":"1","connport_v1":"443;8000-8002","protocol":"3"},
{"areaid":"udp","type":"ip","connaddr":"192.0.2.53","filterport":"1","connport":"53","protocol":"1"}
]}}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		host      string
		port      int
		area      string
		protected bool
	}{
		{"172.16.0.1", 22, "ip", false}, {"172.31.255.254", 22, "ip", false}, {"172.31.255.255", 22, "", false},
		{"172.20.2.3", 23, "", true}, {"2001:db8:ffff::1", 22, "ip", false}, {"2001:db9::1", 22, "", false},
		{"A.CAMPUS.EXAMPLE.", 443, "domain", false}, {"a.b.campus.example", 8002, "domain", false},
		{"a.campus.example", 80, "", true}, {"campus.example", 443, "", false}, {"campus.example.evil", 443, "", false},
		{"192.0.2.53", 53, "", true},
	} {
		a, blocked := p.Match(tt.host, tt.port)
		id := ""
		if a != nil {
			id = a.ID
		}
		if id != tt.area || blocked != tt.protected {
			t.Errorf("%s:%d -> %s/%v, want %s/%v", tt.host, tt.port, id, blocked, tt.area, tt.protected)
		}
	}
	if p.Areas[0].SetID != "set1" {
		t.Fatal("missing issued gateway set")
	}
}

func TestRefuseUnrecognizedPolicy(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"RetCode":1}`, `{"RetCode":0,"BusinessList":[]}`,
		`{"RetCode":0,"BusinessList":[{"BusinessId":143,"Data":{"Configs":[{"Details":{"switch":"0"}}]}}]}`,
		`{"RetCode":0,"BusinessList":[{"BusinessId":143,"Data":{"Configs":[{"Details":{"switch":"1","accessiblearea":[{"areaid":"bad","type":"ip","connaddr":"0.0.0.0/0","filterport":"surprise","protocol":"2"}]}}]}}]}`,
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("accepted unknown policy: %s", data)
		}
	}
}
