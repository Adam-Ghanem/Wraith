package jsanalysis

import (
	"testing"
	"time"
)

func TestStaticAnalyzeRecognizesSupportedClientsWithoutGuessingGenericWrappers(t *testing.T) {
	source := []byte("fetch(`/api/users/${id}`, { method: \"PATCH\" });\n" +
		"axios({ method: \"PUT\", url: \"/api/profile\" });\n" +
		"xhr.open(\"DELETE\", \"/api/users/42\");\n" +
		"request(\"/api/must-not-be-reported\");\n")
	report, err := StaticAnalyze(StaticInput{SourceID: "local:clients.js", Body: source}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Requests) != 3 {
		t.Fatalf("requests=%#v, want exactly supported client calls", report.Requests)
	}
	if report.Requests[0].Method != "PUT" || report.Requests[1].Method != "DELETE" || report.Requests[2].Method != "PATCH" || report.Requests[2].URL != "/api/users/{parameter}" {
		t.Fatalf("request extraction mismatch: %#v", report.Requests)
	}
}

func TestStaticAnalyzeRejectsASTsBeyondConfiguredTraversalLimit(t *testing.T) {
	limits := DefaultStaticLimits()
	limits.MaxASTNodes = 1
	if _, err := StaticAnalyze(StaticInput{SourceID: "local:many-nodes.js", Body: []byte("const x = { a: 1, b: 2 }")}, limits); err == nil {
		t.Fatal("expected AST traversal limit rejection")
	}
}

func TestStaticAnalyzeFailsClosedWhenReferenceLimitIsReached(t *testing.T) {
	limits := DefaultStaticLimits()
	limits.MaxReferences = 1
	if _, err := StaticAnalyze(StaticInput{SourceID: "local:references.js", Body: []byte(`fetch("/api/one"); fetch("/api/two")`)}, limits); err == nil {
		t.Fatal("expected reference-limit rejection")
	}
}

func TestStaticAnalyzeFailsClosedWhenParserBudgetIsExceeded(t *testing.T) {
	limits := DefaultStaticLimits()
	limits.MaxParseDuration = time.Nanosecond
	if _, err := StaticAnalyze(StaticInput{SourceID: "local:timed.js", Body: []byte(`const value = 1`)}, limits); err == nil {
		t.Fatal("expected parser-budget rejection")
	}
}

func TestStaticAnalyzeExtractsLocalParameterNamesAndStrongTechnologySignals(t *testing.T) {
	source := []byte(`
import React from "react";
React.createElement("div");
const params = new URLSearchParams({ search: value });
const form = new FormData(); form.append("email", value);
axios.get("/api/profile");
`)
	report, err := StaticAnalyze(StaticInput{SourceID: "local:signals.js", Body: source}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Parameters) != 2 || report.Parameters[0].Name != "search" || report.Parameters[1].Name != "email" {
		t.Fatalf("parameters=%#v", report.Parameters)
	}
	if len(report.Technologies) != 2 || report.Technologies[0].Name != "Axios" || report.Technologies[1].Name != "React" {
		t.Fatalf("technologies=%#v", report.Technologies)
	}
}

func TestStaticAnalyzeDetectsOnlyStructuralTechnologySignals(t *testing.T) {
	source := []byte(`
import React from "react"; React.createElement("div");
import { createApp } from "vue"; createApp({});
import { RouterModule } from "@angular/router"; RouterModule.forRoot([]);
import NextPage from "next"; import router from "next/router";
defineNuxtConfig({}); useFetch("/api/data");
__webpack_require__(1); webpackJsonp.push([]);
const api = import.meta.env.VITE_API_URL;
axios.get("/api/profile"); $.ajax({url:"/api/legacy"});
`)
	report, err := StaticAnalyze(StaticInput{SourceID: "local:technologies.js", Body: source}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Angular", "Axios", "JQuery", "Next.js", "Nuxt", "React", "Vite", "Vue", "Webpack"}
	if len(report.Technologies) != len(want) {
		t.Fatalf("technologies=%#v", report.Technologies)
	}
	for index, name := range want {
		if report.Technologies[index].Name != name {
			t.Fatalf("technologies=%#v", report.Technologies)
		}
	}
}

func TestStaticAnalyzeNormalizesDirectStringConcatenationTemplates(t *testing.T) {
	report, err := StaticAnalyze(StaticInput{SourceID: "local:dynamic.js", Body: []byte(`fetch("/api/" + path, {method:"GET"})`)}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Requests) != 1 || report.Requests[0].URL != "/api/{parameter}" || report.Requests[0].Confidence != "medium" {
		t.Fatalf("requests=%#v", report.Requests)
	}
}

func TestStaticAnalyzeStripsQueryValuesFromStaticReferences(t *testing.T) {
	report, err := StaticAnalyze(StaticInput{SourceID: "local:redaction.js", Body: []byte(`fetch("/api/session?token=secret-value&mode=read")`)}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Requests) != 1 || report.Requests[0].URL != "/api/session?mode&token" || len(report.Parameters) != 2 || !report.Parameters[1].SensitiveReference {
		t.Fatalf("report=%#v", report)
	}
}
