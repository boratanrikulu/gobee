package transpile

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
)

// Diagnostic is a validator finding at a specific source position.
type Diagnostic struct {
	Pos token.Position
	Msg string
}

func (d Diagnostic) String() string { return fmt.Sprintf("%s: %s", d.Pos, d.Msg) }
func (d Diagnostic) Error() string  { return d.String() }

// Diagnostics is a slice of diagnostics with a combined Error rendering.
type Diagnostics []Diagnostic

func (ds Diagnostics) Error() string {
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.Error()
	}
	return strings.Join(parts, "\n")
}

// allowedImports lists the package paths a kernel-side .go file may import.
// Anything else is rejected up front: BPF programs run in the kernel and have
// no access to the Go standard library or third-party packages.
//
// `unsafe` is allowed solely for `unsafe.Pointer(...)` casts when calling
// auto-generated helpers that take `void *` arguments. The emitter rewrites
// those casts as no-ops; nothing else from `unsafe` is exposed.
var allowedImports = map[string]bool{
	bpfPkgPath: true,
	"unsafe":   true,
}

// Validate checks that every //bpf:section function in the program uses only
// the supported Go subset. Returns all findings sorted by source position.
func Validate(prog *Program) Diagnostics {
	v := &validator{prog: prog}
	v.checkImports()
	for _, p := range prog.Programs {
		v.checkFunc(p.Decl)
	}
	for _, h := range prog.Helpers {
		v.checkFunc(h.Decl)
	}
	sort.SliceStable(v.diags, func(i, j int) bool {
		a, b := v.diags[i].Pos, v.diags[j].Pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
	return v.diags
}

type validator struct {
	prog  *Program
	diags Diagnostics
}

func (v *validator) emit(pos token.Pos, format string, args ...any) {
	v.diags = append(v.diags, Diagnostic{
		Pos: v.prog.FileSet.Position(pos),
		Msg: fmt.Sprintf(format, args...),
	})
}

func (v *validator) checkImports() {
	for _, imp := range v.prog.File.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			v.emit(imp.Pos(), "malformed import path %s", imp.Path.Value)
			continue
		}
		if allowedImports[path] {
			continue
		}
		v.emit(imp.Pos(), "import %q is not allowed in BPF programs; only %q can be imported", path, bpfPkgPath)
	}
}

func (v *validator) checkFunc(fd *ast.FuncDecl) {
	if fd.Recv != nil {
		v.emit(fd.Pos(), "methods on user types are not supported")
	}
	if fd.Type.TypeParams != nil {
		v.emit(fd.Type.TypeParams.Pos(), "generic functions are not supported")
	}
	if fd.Type.Results != nil && fd.Type.Results.NumFields() > 1 {
		v.emit(fd.Type.Results.Pos(), "multiple return values are not supported")
	}
	if fd.Body == nil {
		return
	}
	ast.Inspect(fd.Body, v.visit)
	v.checkBodyTypes(fd.Body)
}

func (v *validator) visit(n ast.Node) bool {
	if n == nil {
		return false
	}
	switch x := n.(type) {
	case *ast.RangeStmt:
		v.emit(x.Pos(), "range loops are not supported; use a constant-bounded for loop")
	case *ast.SwitchStmt:
		v.emit(x.Pos(), "switch is not supported; use if/else if")
	case *ast.TypeSwitchStmt:
		v.emit(x.Pos(), "type switch is not supported")
	case *ast.GoStmt:
		v.emit(x.Pos(), "goroutines are not supported in BPF programs")
	case *ast.DeferStmt:
		v.emit(x.Pos(), "defer is not supported in BPF programs")
	case *ast.SelectStmt:
		v.emit(x.Pos(), "select is not supported in BPF programs")
	case *ast.SendStmt:
		v.emit(x.Pos(), "channel sends are not supported in BPF programs")
	case *ast.TypeAssertExpr:
		v.emit(x.Pos(), "type assertions are not supported in BPF programs")
	case *ast.SliceExpr:
		v.emit(x.Pos(), "slices are not supported")
	case *ast.FuncLit:
		v.emit(x.Pos(), "function literals/closures are not supported")
	case *ast.ChanType:
		v.emit(x.Pos(), "channels are not supported in BPF programs")
	case *ast.MapType:
		v.emit(x.Pos(), "Go's builtin map is not supported; declare a BPF map as `var X = bpf.HashMap[K, V]{MaxEntries: N}` (or ArrayMap, LruHashMap, …)")
	case *ast.InterfaceType:
		v.emit(x.Pos(), "interfaces are not supported")
	case *ast.ArrayType:
		if x.Len == nil {
			v.emit(x.Pos(), "slices are not supported; use a fixed-size [N]T array")
		}
	case *ast.ForStmt:
		v.checkForStmt(x)
	case *ast.CallExpr:
		v.checkCall(x)
	}
	return true
}

func (v *validator) checkCall(call *ast.CallExpr) {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return
	}
	switch id.Name {
	case "make":
		v.emit(call.Pos(), "make is not supported (no heap allocation in BPF programs)")
	case "new":
		v.emit(call.Pos(), "new is not supported (no heap allocation in BPF programs)")
	case "panic":
		v.emit(call.Pos(), "panic is not supported in BPF programs")
	case "recover":
		v.emit(call.Pos(), "recover is not supported in BPF programs")
	}
}

func (v *validator) checkForStmt(fs *ast.ForStmt) {
	if fs.Init == nil && fs.Cond == nil && fs.Post == nil {
		v.emit(fs.Pos(), "infinite for loops are not allowed; use constant-bounded for")
	}
}

// checkBodyTypes flags forbidden basic types (string) reachable inside the
// function body. This catches `var s string`, `s := "hi"`, etc., which a
// pure-AST visitor would miss because the type information is on the type
// checker side.
func (v *validator) checkBodyTypes(body *ast.BlockStmt) {
	bodyStart := body.Pos()
	bodyEnd := body.End()
	for ident, obj := range v.prog.Info.Defs {
		if ident.Pos() < bodyStart || ident.Pos() > bodyEnd {
			continue
		}
		if obj == nil {
			continue
		}
		if isStringType(obj.Type()) {
			v.emit(ident.Pos(), "strings are not supported in BPF programs")
		}
	}
}

func isStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Kind() == types.String || b.Kind() == types.UntypedString
	}
	return false
}
