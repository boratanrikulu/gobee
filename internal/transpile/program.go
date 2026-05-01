// Package transpile turns gobee Go input into BPF C.
//
// Pipeline: ParseFile (go/parser + go/types) → Validate (the supported
// Go subset) → Emit (AST walker that writes BPF C, plus a sourcemap
// sidecar for verifier-error mapping).
//
// The canonical "what is supported / WIP / planned / rejected" matrix
// lives in docs/status.md in the gobee repository. When you add or
// remove support for something here, update that file in the same
// commit.
package transpile

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Program is the intermediate representation produced by parsing a single
// gobee input file. The C emitter consumes this and writes BPF C.
type Program struct {
	FileSet *token.FileSet
	File    *ast.File
	Pkg     *types.Package
	Info    *types.Info

	License  string
	Maps     []*MapDecl
	Programs []*ProgramFunc
	Helpers  []*HelperFunc
	Types    []*UserTypeDecl
	Consts   []*UserConstDecl
}

// HelperFunc is a top-level function without a //bpf:section directive.
// The emitter renders these as `static __always_inline` functions in C
// so callers (the //bpf:section programs) can use them like ordinary
// helpers without paying a non-inlined call (the BPF verifier doesn't
// support indirect calls in most program types, so inlining is the
// safe default).
type HelperFunc struct {
	Name string
	Pos  token.Position
	Decl *ast.FuncDecl
}

// UserConstDecl is a package-level const declaration. The bindings emitter
// re-publishes these (capitalized) so userspace can reference the same
// values the kernel-side program uses.
type UserConstDecl struct {
	Name  string
	Pos   token.Position
	Type  ast.Expr // optional explicit type from the spec; may be nil
	Value ast.Expr // RHS of the const declaration
}

// UserTypeDecl is a user-defined struct (e.g. a ringbuf event payload).
// The emitter renders these as `struct <Name> { ... };` in C.
type UserTypeDecl struct {
	Name string
	Pos  token.Position
	Type *types.Named
	Spec *ast.TypeSpec
}

// MapDecl is a BPF map declared at package scope. The map kind comes from
// the Go type (ArrayMap, HashMap, RingBuf, …); K and V from the generic
// type arguments; MaxEntries from the struct-literal initializer.
type MapDecl struct {
	Name       string         // Go identifier and emitted C symbol
	Pos        token.Position // location of the var name
	Type       string         // "array" | "hash"
	KeyType    types.Type     // resolved from generic instantiation
	ValType    types.Type     // resolved from generic instantiation
	MaxEntries int
	Flags      string // optional, raw directive value
	Spec       *ast.ValueSpec
}

// ProgramFunc is a top-level function annotated with `//bpf:section`.
type ProgramFunc struct {
	Name    string
	Section string // e.g. "xdp"
	Pos     token.Position
	Decl    *ast.FuncDecl
}
