package policy

import (
	"fmt"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanWrite proves that a valid ref exists in read-allow AND write-allow,
// excluding both deny languages. No candidate names are sampled.
func (p *Policy) CanWrite(repo Repository, branchesOnly bool) (bool, error) {
	if !p.Read(repo) {
		return false, nil
	}
	actions := []byte{'w'}
	if !branchesOnly {
		actions = append(actions, 'd')
	}
	prefixes := []string{"refs/heads/"}
	if !branchesOnly {
		prefixes = append(prefixes, "refs/tags/")
	}
	for _, action := range actions {
		for _, prefix := range prefixes {
			ok, err := p.intersect(repo, action, prefix)
			if err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}
func union(parts []string) *syntax.Prog {
	expr := `[^\x00-\x{10ffff}]`
	if len(parts) > 0 {
		expr = "(?:" + strings.Join(parts, "|") + ")"
	}
	re, _ := syntax.Parse(expr, syntax.Perl)
	prog, _ := syntax.Compile(re.Simplify())
	return prog
}
func closure(p *syntax.Prog, seeds []uint32) []uint32 {
	seen := make([]bool, len(p.Inst))
	stack := append([]uint32(nil), seeds...)
	out := []uint32{}
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		in := p.Inst[pc]
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, in.Out, in.Arg)
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			stack = append(stack, in.Out)
		case syntax.InstFail:
		default:
			out = append(out, pc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func step(p *syntax.Prog, pcs []uint32, c rune) []uint32 {
	next := []uint32{}
	for _, pc := range pcs {
		in := p.Inst[pc]
		switch in.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if in.MatchRune(c) {
				next = append(next, in.Out)
			}
		}
	}
	return closure(p, next)
}
func accept(p *syntax.Prog, pcs []uint32) bool {
	for _, pc := range pcs {
		if p.Inst[pc].Op == syntax.InstMatch {
			return true
		}
	}
	return false
}

// refState recognizes Git's ref component restrictions while exploring the DFA.
type refState struct {
	Start, Dot, At bool
	Lock           int
}

func (s refState) next(c rune) (refState, bool) {
	if c <= 32 || c == 127 || c >= 0xd800 && c <= 0xdfff || strings.ContainsRune(`~^:?*[\`, c) {
		return s, false
	}
	if c == '/' {
		if s.Start || s.Lock == 5 {
			return s, false
		}
		return refState{Start: true}, true
	}
	if s.Start && c == '.' || s.Dot && c == '.' || s.At && c == '{' {
		return s, false
	}
	suffix := ".lock"[:s.Lock] + string(c)
	lock := 0
	for n := 1; n <= 5; n++ {
		if strings.HasSuffix(suffix, ".lock"[:n]) {
			lock = n
		}
	}
	return refState{Dot: c == '.', At: c == '@', Lock: lock}, true
}
func (s refState) valid() bool { return !s.Start && !s.Dot && s.Lock != 5 }

type product struct {
	PC  [4][]uint32
	Ref refState
}

func (s product) key() string {
	var b strings.Builder
	for _, pcs := range s.PC {
		for _, pc := range pcs {
			b.WriteString(strconv.Itoa(int(pc)))
			b.WriteByte(',')
		}
		b.WriteByte(';')
	}
	fmt.Fprintf(&b, "%t:%t:%t:%d", s.Ref.Start, s.Ref.Dot, s.Ref.At, s.Ref.Lock)
	return b.String()
}
func (p *Policy) intersect(repo Repository, action byte, prefix string) (bool, error) {
	var expr [4][]string
	for _, r := range p.Rules {
		if !r.MatchesRepository(repo) {
			continue
		}
		if strings.ContainsRune(r.Actions, 'r') {
			i := 0
			if r.Deny {
				i = 2
			}
			expr[i] = append(expr[i], r.refExpr)
		}
		if strings.ContainsRune(r.Actions, rune(action)) {
			i := 1
			if r.Deny {
				i = 3
			}
			expr[i] = append(expr[i], r.refExpr)
		}
	}
	if len(expr[0]) == 0 || len(expr[1]) == 0 {
		return false, nil
	}
	var progs [4]*syntax.Prog
	start := product{Ref: refState{Start: true}}
	bounds := map[int]bool{0: true, utf8.MaxRune + 1: true}
	// These split every character class that the ref validator treats differently.
	for c := 0; c <= 128; c++ {
		bounds[c] = true
	}
	bounds[0xd800] = true
	bounds[0xe000] = true
	for i := range progs {
		progs[i] = union(expr[i])
		if len(progs[i].Inst) > 32768 {
			return false, fmt.Errorf("permission automaton too large")
		}
		start.PC[i] = closure(progs[i], []uint32{uint32(progs[i].Start)})
		for _, c := range prefix {
			start.PC[i] = step(progs[i], start.PC[i], c)
		}
		for _, in := range progs[i].Inst {
			if in.Op == syntax.InstRune || in.Op == syntax.InstRune1 {
				if len(in.Rune) == 1 {
					bounds[int(in.Rune[0])] = true
					bounds[int(in.Rune[0])+1] = true
				} else {
					for j := 0; j+1 < len(in.Rune); j += 2 {
						bounds[int(in.Rune[j])] = true
						bounds[int(in.Rune[j+1])+1] = true
					}
				}
			}
		}
	}
	alphabet := []int{}
	for c := range bounds {
		if c <= utf8.MaxRune {
			alphabet = append(alphabet, c)
		}
	}
	sort.Ints(alphabet)
	if len(alphabet) > 2048 {
		return false, fmt.Errorf("permission alphabet too large")
	}
	queue := []product{start}
	seen := map[string]bool{start.key(): true}
	for at := 0; at < len(queue); at++ {
		s := queue[at]
		if s.Ref.valid() && accept(progs[0], s.PC[0]) && accept(progs[1], s.PC[1]) && !accept(progs[2], s.PC[2]) && !accept(progs[3], s.PC[3]) {
			return true, nil
		}
		for _, c := range alphabet {
			rs, ok := s.Ref.next(rune(c))
			if !ok {
				continue
			}
			n := product{Ref: rs}
			for i := range progs {
				n.PC[i] = step(progs[i], s.PC[i], rune(c))
			}
			if len(n.PC[0]) == 0 || len(n.PC[1]) == 0 {
				continue
			}
			k := n.key()
			if !seen[k] {
				if len(seen) >= MaxStates {
					return false, fmt.Errorf("permission intersection exceeds complexity limit")
				}
				seen[k] = true
				queue = append(queue, n)
			}
		}
	}
	return false, nil
}
