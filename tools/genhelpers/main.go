// Command genhelpers reads libbpf's bpf_helper_defs.h and emits Go stubs for
// every BPF helper into bpf/helpers_generated.go.
//
// Usage:
//
//	go run ./tools/genhelpers > bpf/helpers_generated.go
//
// The vendored header lives at tools/genhelpers/data/bpf_helper_defs.h. See
// the sibling SOURCE.md for provenance and bump instructions.
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const headerPath = "tools/genhelpers/data/bpf_helper_defs.h"

// helperDecl matches the static-function-pointer declaration libbpf uses for
// every helper. Captures: ret type, helper C name, parameter list verbatim.
//
// Example match:
//
//	static long (* const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
var helperDecl = regexp.MustCompile(`^static\s+(.+?)\s*\(\*\s*const\s+(\w+)\s*\)\s*\((.*)\)\s*=\s*\(void\s*\*\)\s*\d+\s*;`)

// docStart marks the start of a doc comment. Each helper's doc comment block
// immediately precedes its declaration with no blank line in between.
var docStart = regexp.MustCompile(`^/\*$`)
var docEnd = regexp.MustCompile(`^\s*\*/$`)

func main() {
	body, err := os.ReadFile(headerPath)
	if err != nil {
		die(err)
	}

	helpers, err := parseHelpers(string(body))
	if err != nil {
		die(err)
	}
	sort.Slice(helpers, func(i, j int) bool { return helpers[i].cName < helpers[j].cName })

	if err := emit(os.Stdout, helpers); err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "genhelpers: emitted %d helpers (%d skipped)\n", countEmitted(helpers), countSkipped(helpers))
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "genhelpers: %v\n", err)
	os.Exit(1)
}

// helper is one parsed entry from bpf_helper_defs.h.
type helper struct {
	cName   string
	goName  string
	retType string // empty == void
	params  []param
	doc     []string // verbatim doc-comment lines (already stripped of `* ` prefix)
	skip    string   // non-empty == this helper is emitted as a commented stub with this reason
}

type param struct {
	cType string // raw C type as parsed
	name  string
	goTyp string // mapped Go type, populated during type mapping
}

func parseHelpers(src string) ([]helper, error) {
	var out []helper
	scanner := bufio.NewScanner(strings.NewReader(src))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var (
		inDoc      bool
		curDoc     []string
		pendingDoc []string
	)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case docStart.MatchString(line):
			inDoc = true
			curDoc = curDoc[:0]
		case docEnd.MatchString(line):
			inDoc = false
			pendingDoc = append(pendingDoc[:0], curDoc...)
		case inDoc:
			curDoc = append(curDoc, strings.TrimPrefix(strings.TrimPrefix(line, " * "), " *"))
		default:
			m := helperDecl.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			h := helper{
				cName:   m[2],
				retType: strings.TrimSpace(m[1]),
				doc:     append([]string(nil), pendingDoc...),
			}
			h.goName = goNameFor(h.cName)
			if reason, params, ok := parseParams(m[3]); ok {
				h.params = params
			} else {
				h.skip = reason
			}
			if h.skip == "" {
				if reason := mapTypes(&h); reason != "" {
					h.skip = reason
				}
			}
			out = append(out, h)
			pendingDoc = pendingDoc[:0]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no helpers parsed from %s", headerPath)
	}
	return out, nil
}

// parseParams splits a comma-separated C parameter list. Returns ok=false
// (with a reason) for variadic or otherwise unsupported shapes.
func parseParams(raw string) (string, []param, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "void" || raw == "" {
		return "", nil, true
	}
	if strings.Contains(raw, "...") {
		return "variadic helpers are not yet supported", nil, false
	}
	parts := splitTopLevel(raw, ',')
	params := make([]param, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Last whitespace-separated token is the name; the rest is the type.
		idx := strings.LastIndex(p, " ")
		if idx < 0 {
			return fmt.Sprintf("unparseable parameter %q", p), nil, false
		}
		typ := strings.TrimSpace(p[:idx])
		name := strings.TrimSpace(p[idx+1:])
		// Pointer asterisks may live with the name; normalize so the type owns them.
		for strings.HasPrefix(name, "*") {
			typ += " *"
			name = strings.TrimSpace(name[1:])
		}
		// Reserved Go words / blank names: rename.
		name = sanitizeParamName(name)
		params = append(params, param{cType: typ, name: name})
	}
	return "", params, true
}

func splitTopLevel(s string, sep byte) []string {
	var (
		parts []string
		depth int
		buf   strings.Builder
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		}
		if c == sep && depth == 0 {
			parts = append(parts, buf.String())
			buf.Reset()
			continue
		}
		buf.WriteByte(c)
	}
	if buf.Len() > 0 {
		parts = append(parts, buf.String())
	}
	return parts
}

// goNameFor turns a C helper name into its exported Go counterpart.
// The leading `bpf_` is dropped; remaining snake_case becomes PascalCase.
//
//	bpf_map_lookup_elem → MapLookupElem
//	bpf_ktime_get_ns    → KtimeGetNs
//	bpf_get_current_pid_tgid → GetCurrentPidTgid
func goNameFor(c string) string {
	c = strings.TrimPrefix(c, "bpf_")
	parts := strings.Split(c, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func sanitizeParamName(name string) string {
	if name == "" {
		return "arg"
	}
	switch name {
	case "type", "func", "map", "range", "chan", "select", "case", "default", "go", "var", "const", "import", "package", "interface", "struct":
		return name + "_"
	}
	return name
}

// mapTypes resolves each parameter's C type to a Go type and computes the Go
// return type. Returns a skip reason if any parameter or the return type
// can't be safely mapped at this stage.
func mapTypes(h *helper) string {
	for i := range h.params {
		gt, reason := cTypeToGo(h.params[i].cType)
		if reason != "" {
			return fmt.Sprintf("parameter %q (%s): %s", h.params[i].name, h.params[i].cType, reason)
		}
		h.params[i].goTyp = gt
	}
	if h.retType == "void" {
		return ""
	}
	gt, reason := cTypeToGo(h.retType)
	if reason != "" {
		return fmt.Sprintf("return type (%s): %s", h.retType, reason)
	}
	h.retType = gt
	return ""
}

// cTypeToGo maps a single C type to its Go counterpart.
//
//   - integer types map directly
//   - char* / const char* are rejected (strings are not BPF-safe)
//   - struct foo * collapses to unsafe.Pointer until kernel struct stubs
//     are auto-generated alongside the helper surface
//   - void * is unsafe.Pointer
//   - enum types map to uint32 (typical BPF enum width)
func cTypeToGo(c string) (string, string) {
	c = strings.TrimSpace(c)
	// Strip calling-convention attributes that may show up before the type
	// (e.g. `__bpf_fastcall __u32` on a return type).
	for _, prefix := range []string{"__bpf_fastcall ", "const "} {
		c = strings.TrimSpace(strings.TrimPrefix(c, prefix))
	}

	if c == "void" {
		return "", "void cannot appear as a parameter type"
	}
	if c == "void *" || c == "const void *" {
		return "unsafe.Pointer", ""
	}
	if strings.Contains(c, "char *") {
		return "", "string-typed parameters are not BPF-safe"
	}
	if strings.HasSuffix(c, "*") {
		// struct foo * — typed kernel struct stubs aren't generated yet,
		// so collapse to a raw pointer for now.
		return "unsafe.Pointer", ""
	}
	switch c {
	case "__u8", "u8":
		return "uint8", ""
	case "__u16", "u16", "__be16", "__le16":
		return "uint16", ""
	case "__u32", "u32", "__be32", "__le32", "__wsum", "__sum16":
		return "uint32", ""
	case "__u64", "u64", "__be64", "__le64":
		return "uint64", ""
	case "__s8", "s8":
		return "int8", ""
	case "__s16", "s16":
		return "int16", ""
	case "__s32", "s32", "int":
		return "int32", ""
	case "__s64", "s64", "long", "long long":
		return "int64", ""
	}
	if strings.HasPrefix(c, "enum ") {
		return "uint32", ""
	}
	return "", fmt.Sprintf("unmapped C type %q", c)
}

func emit(w *os.File, helpers []helper) error {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	bw.WriteString(`// Code generated by tools/genhelpers. DO NOT EDIT.
//
// This file is a derivative work of libbpf's bpf_helper_defs.h. Function
// names and doc comments are taken from that header. Per libbpf's
// dual-license, we use the BSD-2-Clause terms, reproduced below; gobee
// itself remains MIT, but this file carries libbpf's notice as required.
//
//   SPDX-License-Identifier: BSD-2-Clause
//
//   Copyright (c) the libbpf authors. All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//     1. Redistributions of source code must retain the above copyright
//        notice, this list of conditions and the following disclaimer.
//
//     2. Redistributions in binary form must reproduce the above copyright
//        notice, this list of conditions and the following disclaimer in
//        the documentation and/or other materials provided with the
//        distribution.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
//
// Source:    tools/genhelpers/data/bpf_helper_defs.h (libbpf v1.5.0)
// Provenance: tools/genhelpers/data/SOURCE.md

package bpf

import "unsafe"

var _ unsafe.Pointer // keep the import even when no helper needs it

`)
	for _, h := range helpers {
		emitDoc(bw, h)
		if h.skip != "" {
			fmt.Fprintf(bw, "// SKIPPED: %s\n", h.skip)
			fmt.Fprintf(bw, "// func %s(...) { ... }\n\n", h.goName)
			continue
		}
		var b strings.Builder
		b.WriteString("func ")
		b.WriteString(h.goName)
		b.WriteByte('(')
		for i, p := range h.params {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(p.name)
			b.WriteByte(' ')
			b.WriteString(p.goTyp)
		}
		b.WriteByte(')')
		if h.retType != "" && h.retType != "void" {
			b.WriteByte(' ')
			b.WriteString(h.retType)
		}
		b.WriteString(" { panic(stubMsg) }\n\n")
		bw.WriteString(b.String())
	}
	return nil
}

func emitDoc(w *bufio.Writer, h helper) {
	fmt.Fprintf(w, "// %s wraps the BPF helper `%s`.\n", h.goName, h.cName)
	if len(h.doc) > 0 {
		w.WriteString("//\n")
		// Skip the first line (it's just the C name) and write the rest.
		body := h.doc
		if len(body) > 0 && strings.TrimSpace(body[0]) == h.cName {
			body = body[1:]
		}
		for _, line := range body {
			line = strings.TrimRight(line, " \t")
			fmt.Fprintf(w, "// %s\n", strings.TrimPrefix(line, " "))
		}
	}
}

func countEmitted(hs []helper) int {
	n := 0
	for _, h := range hs {
		if h.skip == "" {
			n++
		}
	}
	return n
}

func countSkipped(hs []helper) int {
	n := 0
	for _, h := range hs {
		if h.skip != "" {
			n++
		}
	}
	return n
}
