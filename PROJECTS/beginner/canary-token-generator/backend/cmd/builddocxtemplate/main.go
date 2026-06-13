// ©AngelaMos | 2026
// main.go

package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/footer2.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>
`

	packageRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
`

	documentXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    <w:p><w:r><w:t xml:space="preserve">Internal document - confidential. Do not redistribute.</w:t></w:r></w:p>
    <w:sectPr>
      <w:footerReference w:type="default" r:id="rIdFooter"/>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>
`

	documentRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer2.xml"/>
</Relationships>
`

	footer2XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p>
    <w:r><w:fldChar w:fldCharType="begin"/></w:r>
    <w:r><w:instrText xml:space="preserve"> INCLUDEPICTURE "HONEY_TRACK_URL" \d \* MERGEFORMAT </w:instrText></w:r>
    <w:r><w:fldChar w:fldCharType="end"/></w:r>
  </w:p>
</w:ftr>
`

	pathContentTypes = "[Content_Types].xml"
	pathPackageRels  = "_rels/.rels"
	pathDocument     = "word/document.xml"
	pathDocumentRels = "word/_rels/document.xml.rels"
	pathFooter2      = "word/footer2.xml"

	dirPerm  os.FileMode = 0o755
	filePerm os.FileMode = 0o644
)

type entry struct {
	name   string
	body   string
	method uint16
}

func entries() []entry {
	return []entry{
		{name: pathContentTypes, body: contentTypesXML, method: zip.Store},
		{name: pathPackageRels, body: packageRelsXML, method: zip.Deflate},
		{name: pathDocument, body: documentXML, method: zip.Deflate},
		{name: pathDocumentRels, body: documentRelsXML, method: zip.Store},
		{name: pathFooter2, body: footer2XML, method: zip.Deflate},
	}
}

func main() {
	out := flag.String("out", "", "output path for template.docx")
	flag.Parse()

	if *out == "" {
		log.Fatal("usage: builddocxtemplate -out <path>")
	}

	if err := buildTemplate(*out); err != nil {
		log.Fatalf("build docx template: %v", err)
	}

	fmt.Printf("wrote %s\n", *out)
}

func buildTemplate(out string) (err error) {
	cleaned := filepath.Clean(out)
	if mkErr := os.MkdirAll(filepath.Dir(cleaned), dirPerm); mkErr != nil {
		return fmt.Errorf("mkdir parent: %w", mkErr)
	}

	f, oErr := os.OpenFile(
		cleaned,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		filePerm,
	)
	if oErr != nil {
		return fmt.Errorf("open output: %w", oErr)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close output: %w", cerr)
		}
	}()

	w := zip.NewWriter(f)
	for _, e := range entries() {
		hdr := &zip.FileHeader{Name: e.name, Method: e.method}
		fw, cErr := w.CreateHeader(hdr)
		if cErr != nil {
			return fmt.Errorf("create %s: %w", e.name, cErr)
		}
		if _, wErr := fw.Write([]byte(e.body)); wErr != nil {
			return fmt.Errorf("write %s: %w", e.name, wErr)
		}
	}
	if zErr := w.Close(); zErr != nil {
		return fmt.Errorf("close zip writer: %w", zErr)
	}
	return nil
}
