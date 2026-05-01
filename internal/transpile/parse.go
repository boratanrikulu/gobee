package transpile

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
)

// ParseFile loads a single Go file, type-checks it, and returns the gobee IR.
// Diagnostics from the Go front-end are returned as errors with file:line:col
// positions intact.
func ParseFile(filename string) (*Program, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	conf := &types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check(f.Name.Name, fset, []*ast.File{f}, info)
	if err != nil {
		return nil, fmt.Errorf("typecheck: %w", err)
	}

	prog := &Program{FileSet: fset, File: f, Pkg: pkg, Info: info}

	if err := collectFileDirectives(prog); err != nil {
		return nil, err
	}
	if err := collectDecls(prog); err != nil {
		return nil, err
	}

	if prog.License == "" {
		return nil, fmt.Errorf("%s: missing //bpf:license directive", fset.Position(f.Pos()))
	}
	if len(prog.Programs) == 0 {
		return nil, fmt.Errorf("%s: no //bpf:section functions found", fset.Position(f.Pos()))
	}
	return prog, nil
}

func collectFileDirectives(prog *Program) error {
	for _, cg := range prog.File.Comments {
		for _, c := range cg.List {
			d, err := parseDirective(c.Text)
			if err != nil {
				return fmt.Errorf("%s: %w", prog.FileSet.Position(c.Pos()), err)
			}
			if d == nil {
				continue
			}
			switch d.name {
			case "license":
				if len(d.args) == 0 {
					return fmt.Errorf("%s: //bpf:license requires a name (e.g. GPL)", prog.FileSet.Position(c.Pos()))
				}
				prog.License = d.args[0]
			}
		}
	}
	return nil
}

func collectDecls(prog *Program) error {
	for _, decl := range prog.File.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if dr := docDirective(d.Doc, "section"); dr != nil {
				if len(dr.args) == 0 {
					return fmt.Errorf("%s: //bpf:section requires a section name", prog.FileSet.Position(d.Pos()))
				}
				prog.Programs = append(prog.Programs, &ProgramFunc{
					Name:    d.Name.Name,
					Section: dr.args[0],
					Pos:     prog.FileSet.Position(d.Pos()),
					Decl:    d,
				})
				continue
			}
			// `func main() {}` is the conventional placeholder so the
			// kernel-side file type-checks as a Go program. Drop it.
			if d.Name.Name == "main" && d.Recv == nil {
				continue
			}
			// Methods on user types aren't supported (rejected by the
			// validator with a clear message). Skip the silent drop here
			// so the validator owns the diagnostic.
			if d.Recv != nil {
				continue
			}
			prog.Helpers = append(prog.Helpers, &HelperFunc{
				Name: d.Name.Name,
				Pos:  prog.FileSet.Position(d.Pos()),
				Decl: d,
			})
		case *ast.GenDecl:
			switch d.Tok {
			case token.VAR:
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						md, err := tryBuildMapDecl(name, vs, i, prog)
						if err != nil {
							return err
						}
						if md != nil {
							prog.Maps = append(prog.Maps, md)
						}
					}
				}
			case token.TYPE:
				for _, spec := range d.Specs {
					ts := spec.(*ast.TypeSpec)
					obj := prog.Info.Defs[ts.Name]
					if obj == nil {
						continue
					}
					named, ok := obj.Type().(*types.Named)
					if !ok {
						continue
					}
					if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
						continue
					}
					prog.Types = append(prog.Types, &UserTypeDecl{
						Name: ts.Name.Name,
						Pos:  prog.FileSet.Position(ts.Pos()),
						Type: named,
						Spec: ts,
					})
				}
			case token.CONST:
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						var val ast.Expr
						if i < len(vs.Values) {
							val = vs.Values[i]
						}
						if val == nil {
							continue
						}
						prog.Consts = append(prog.Consts, &UserConstDecl{
							Name:  name.Name,
							Pos:   prog.FileSet.Position(name.Pos()),
							Type:  vs.Type,
							Value: val,
						})
					}
				}
			}
		}
	}
	return nil
}

// tryBuildMapDecl examines a single var name from a ValueSpec. If the
// var's type is a known bpf-package map (ArrayMap, HashMap, RingBuf, …),
// it returns a populated *MapDecl. Otherwise it returns (nil, nil).
//
// The map kind comes from the Go type; MaxEntries is read from the
// var's struct-literal initializer.
func tryBuildMapDecl(nameIdent *ast.Ident, vs *ast.ValueSpec, idx int, prog *Program) (*MapDecl, error) {
	pos := prog.FileSet.Position(nameIdent.Pos())
	obj := prog.Info.Defs[nameIdent]
	if obj == nil {
		return nil, nil
	}
	nt, ok := obj.Type().(*types.Named)
	if !ok {
		return nil, nil
	}
	tobj := nt.Obj()
	if tobj.Pkg() == nil || tobj.Pkg().Path() != bpfPkgPath {
		return nil, nil
	}
	directive, ok := bpfMapGoTypeToDirective[tobj.Name()]
	if !ok {
		return nil, nil
	}

	md := &MapDecl{
		Name: nameIdent.Name,
		Pos:  pos,
		Type: directive,
		Spec: vs,
	}
	if targs := nt.TypeArgs(); targs != nil {
		switch targs.Len() {
		case 1:
			md.ValType = targs.At(0)
		case 2:
			md.KeyType = targs.At(0)
			md.ValType = targs.At(1)
		default:
			return nil, fmt.Errorf("%s: %s has %d type arguments; expected 1 or 2", pos, nameIdent.Name, targs.Len())
		}
	}

	// Storage maps (TaskStorage, SkStorage, InodeStorage) are sized by the
	// kernel — the user doesn't pass MaxEntries — so an empty `{}` literal
	// is the canonical form. All other map types require MaxEntries.
	noMaxEntries := storageMapDirectives[directive]

	if vs.Values == nil || idx >= len(vs.Values) {
		if noMaxEntries {
			return md, nil
		}
		return nil, fmt.Errorf("%s: %s must be initialized with a struct literal (e.g. %s{MaxEntries: 1024})", pos, nameIdent.Name, tobj.Name())
	}
	cl, ok := vs.Values[idx].(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("%s: %s must be initialized with a %s{...} struct literal", pos, nameIdent.Name, tobj.Name())
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("%s: %s initializer must use field names (e.g. MaxEntries: 1024)", pos, nameIdent.Name)
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "MaxEntries":
			lit, ok := kv.Value.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				return nil, fmt.Errorf("%s: MaxEntries must be an integer literal", pos)
			}
			n, err := strconv.Atoi(lit.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: MaxEntries: %w", pos, err)
			}
			if n <= 0 {
				return nil, fmt.Errorf("%s: MaxEntries must be > 0", pos)
			}
			md.MaxEntries = n
		}
	}
	if md.MaxEntries == 0 && !noMaxEntries {
		return nil, fmt.Errorf("%s: %s missing MaxEntries field", pos, nameIdent.Name)
	}
	return md, nil
}

// storageMapDirectives is the set of map kinds the kernel sizes
// dynamically — MaxEntries is not user-controlled.
var storageMapDirectives = map[string]bool{
	"task_storage":  true,
	"sk_storage":    true,
	"inode_storage": true,
}
