package ldapdir

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseRange(t *testing.T) {
	cases := []struct {
		in   string
		want RangeInfo
		ok   bool
	}{
		{"member;range=0-1499", RangeInfo{Base: "member", High: 1499}, true},
		{"member;range=1500-*", RangeInfo{Base: "member", Last: true}, true},
		{"member", RangeInfo{}, false},
		{"member;range=x", RangeInfo{}, false},
		{"member;range=0-abc", RangeInfo{}, false},
	}
	for _, c := range cases {
		got, ok := ParseRange(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v %v", c.in, got, ok)
		}
	}
}

func TestRangedRequestRewritesOnlyMember(t *testing.T) {
	got := rangedRequest([]string{"cn", "Member", "mail"}, 1500)
	want := []string{"cn", "Member;range=0-1499", "mail"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

// Repeated fetches work against a server that, like AD, returns at most chunk values per request.
func fakeServer(total, chunk int) func(string) ([]RangedValues, error) {
	return func(spec string) ([]RangedValues, error) {
		var lo int
		if _, err := fmt.Sscanf(spec, "member;range=%d-*", &lo); err != nil {
			return nil, err
		}
		if lo >= total {
			return nil, nil
		}
		hi := min(lo+chunk-1, total-1)
		name := fmt.Sprintf("member;range=%d-%d", lo, hi)
		if hi == total-1 {
			name = fmt.Sprintf("member;range=%d-*", lo)
		}
		values := make([]string, 0, hi-lo+1)
		for i := lo; i <= hi; i++ {
			values = append(values, fmt.Sprintf("m%d", i))
		}
		return []RangedValues{{Name: name, Values: values}}, nil
	}
}

func TestCollectRangesFollowsEveryChunk(t *testing.T) {
	for _, total := range []int{1501, 3000, 3001, 7500} {
		got, err := CollectRanges("member", 1500, fakeServer(total, 1500))
		if err != nil || len(got) != total-1500 {
			t.Errorf("total=%d: got %d values, err=%v", total, len(got), err)
		}
		if len(got) > 0 && (got[0] != "m1500" || got[len(got)-1] != fmt.Sprintf("m%d", total-1)) {
			t.Errorf("total=%d: wrong boundaries %s..%s", total, got[0], got[len(got)-1])
		}
	}
}

func TestCollectRangesStopsWhenServerReturnsNothing(t *testing.T) {
	got, err := CollectRanges("member", 5000, fakeServer(10, 1500))
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
