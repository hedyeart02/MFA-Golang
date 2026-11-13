package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type DocxBuilder struct {
	bodyXML strings.Builder
	media   map[string][]byte
	rels    []DocRel
	nextRId int
	figNum  int
}

type DocRel struct {
	ID     string
	Type   string
	Target string
}

func NewDocxBuilder() *DocxBuilder {
	return &DocxBuilder{
		media:   make(map[string][]byte),
		rels:    make([]DocRel, 0),
		nextRId: 1,
		figNum:  1,
	}
}

func (b *DocxBuilder) addRel(relType, target string) string {
	id := fmt.Sprintf("rId%d", b.nextRId)
	b.nextRId++
	b.rels = append(b.rels, DocRel{ID: id, Type: relType, Target: target})
	return id
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func (b *DocxBuilder) AddTitle(text string, subtitle string) {
	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:spacing w:before="360" w:after="120"/>
    <w:jc w:val="center"/>
  </w:pPr>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="0F172A"/>
      <w:sz w:val="56"/>
    </w:rPr>
    <w:t>%s</w:t>
  </w:r>
</w:p>`, escapeXML(text)))

	if subtitle != "" {
		b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:spacing w:before="60" w:after="400"/>
    <w:jc w:val="center"/>
  </w:pPr>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:color w:val="00B050"/>
      <w:b/>
      <w:sz w:val="28"/>
    </w:rPr>
    <w:t>%s</w:t>
  </w:r>
</w:p>`, escapeXML(subtitle)))
	}
}

func (b *DocxBuilder) AddHeading(text string, level int) {
	sz := "36" // 18pt
	color := "0F172A"
	spaceBefore := "400"
	spaceAfter := "140"

	switch level {
	case 1:
		sz = "36"
		color = "0F172A"
		spaceBefore = "480"
		spaceAfter = "160"
	case 2:
		sz = "28"
		color = "00B050"
		spaceBefore = "340"
		spaceAfter = "120"
	case 3:
		sz = "24"
		color = "334155"
		spaceBefore = "240"
		spaceAfter = "80"
	}

	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:pStyle w:val="Heading%d"/>
    <w:spacing w:before="%s" w:after="%s"/>
    <w:keepNext/>
  </w:pPr>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="%s"/>
      <w:sz w:val="%s"/>
    </w:rPr>
    <w:t>%s</w:t>
  </w:r>
</w:p>`, level, spaceBefore, spaceAfter, color, sz, escapeXML(text)))
}

func (b *DocxBuilder) AddParagraph(text string) {
	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:spacing w:after="160" w:line="260" w:lineRule="auto"/>
  </w:pPr>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:color w:val="334155"/>
      <w:sz w:val="22"/>
    </w:rPr>
    <w:t xml:space="preserve">%s</w:t>
  </w:r>
</w:p>`, escapeXML(text)))
}

func (b *DocxBuilder) AddBullet(text string, boldPrefix string) {
	boldPart := ""
	if boldPrefix != "" {
		boldPart = fmt.Sprintf(`<w:r><w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/><w:b/><w:color w:val="0F172A"/><w:sz w:val="22"/></w:rPr><w:t xml:space="preserve">%s: </w:t></w:r>`, escapeXML(boldPrefix))
	}

	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>
    <w:spacing w:after="100" w:line="260" w:lineRule="auto"/>
    <w:ind w:left="360" w:hanging="240"/>
  </w:pPr>
  <w:r>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/><w:color w:val="00B050"/><w:sz w:val="22"/></w:rPr>
    <w:t xml:space="preserve">• </w:t>
  </w:r>
  %s
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:color w:val="334155"/>
      <w:sz w:val="22"/>
    </w:rPr>
    <w:t xml:space="preserve">%s</w:t>
  </w:r>
</w:p>`, boldPart, escapeXML(text)))
}

func (b *DocxBuilder) AddNumberedItem(num int, title string, desc string) {
	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:spacing w:after="120" w:line="260" w:lineRule="auto"/>
    <w:ind w:left="420" w:hanging="300"/>
  </w:pPr>
  <w:r>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/><w:b/><w:color w:val="00B050"/><w:sz w:val="22"/></w:rPr>
    <w:t xml:space="preserve">%d. </w:t>
  </w:r>
  <w:r>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/><w:b/><w:color w:val="0F172A"/><w:sz w:val="22"/></w:rPr>
    <w:t xml:space="preserve">%s: </w:t>
  </w:r>
  <w:r>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/><w:color w:val="334155"/><w:sz w:val="22"/></w:rPr>
    <w:t xml:space="preserve">%s</w:t>
  </w:r>
</w:p>`, num, escapeXML(title), escapeXML(desc)))
}

func (b *DocxBuilder) AddCodeBlock(code string) {
	lines := strings.Split(code, "\n")
	var codeRuns strings.Builder
	for i, l := range lines {
		if i > 0 {
			codeRuns.WriteString("<w:br/>")
		}
		codeRuns.WriteString(fmt.Sprintf(`<w:t xml:space="preserve">%s</w:t>`, escapeXML(l)))
	}

	b.bodyXML.WriteString(fmt.Sprintf(`
<w:tbl>
  <w:tblPr>
    <w:tblW w:w="9200" w:type="dxa"/>
    <w:tblBorders>
      <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
      <w:left w:val="single" w:sz="18" w:space="0" w:color="00B050"/>
      <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
      <w:right w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
    </w:tblBorders>
    <w:tblCellMar>
      <w:top w:w="140" w:type="dxa"/>
      <w:left w:w="220" w:type="dxa"/>
      <w:bottom w:w="140" w:type="dxa"/>
      <w:right w:w="220" w:type="dxa"/>
    </w:tblCellMar>
    <w:jc w:val="center"/>
  </w:tblPr>
  <w:tr>
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="9200" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="0C1523"/>
      </w:tcPr>
      <w:p>
        <w:pPr>
          <w:spacing w:after="0" w:line="240" w:lineRule="auto"/>
        </w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>
            <w:color w:val="3DCD58"/>
            <w:sz w:val="18"/>
          </w:rPr>
          %s
        </w:r>
      </w:p>
    </w:tc>
  </w:tr>
</w:tbl>
<w:p><w:pPr><w:spacing w:after="160"/></w:pPr></w:p>`, codeRuns.String()))
}

func (b *DocxBuilder) AddCallout(title, text string, borderColor, bgColor string) {
	b.bodyXML.WriteString(fmt.Sprintf(`
<w:tbl>
  <w:tblPr>
    <w:tblW w:w="9200" w:type="dxa"/>
    <w:tblBorders>
      <w:top w:val="none"/>
      <w:left w:val="single" w:sz="24" w:space="0" w:color="%s"/>
      <w:bottom w:val="none"/>
      <w:right w:val="none"/>
    </w:tblBorders>
    <w:tblCellMar>
      <w:top w:w="140" w:type="dxa"/>
      <w:left w:w="200" w:type="dxa"/>
      <w:bottom w:w="140" w:type="dxa"/>
      <w:right w:w="200" w:type="dxa"/>
    </w:tblCellMar>
    <w:jc w:val="center"/>
  </w:tblPr>
  <w:tr>
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="9200" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="%s"/>
      </w:tcPr>
      <w:p>
        <w:pPr><w:spacing w:after="60"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:b/>
            <w:color w:val="%s"/>
            <w:sz w:val="22"/>
          </w:rPr>
          <w:t>%s</w:t>
        </w:r>
      </w:p>
      <w:p>
        <w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:color w:val="334155"/>
            <w:sz w:val="20"/>
          </w:rPr>
          <w:t>%s</w:t>
        </w:r>
      </w:p>
    </w:tc>
  </w:tr>
</w:tbl>
<w:p><w:pPr><w:spacing w:after="160"/></w:pPr></w:p>`, borderColor, bgColor, borderColor, escapeXML(title), escapeXML(text)))
}

func (b *DocxBuilder) AddTable(headers []string, rows [][]string) {
	var sb strings.Builder
	colWidth := 9200 / len(headers)

	sb.WriteString(`
<w:tbl>
  <w:tblPr>
    <w:tblW w:w="9200" w:type="dxa"/>
    <w:tblBorders>
      <w:top w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>
      <w:left w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>
      <w:bottom w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>
      <w:right w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>
      <w:insideH w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
      <w:insideV w:val="single" w:sz="4" w:space="0" w:color="E2E8F0"/>
    </w:tblBorders>
    <w:tblCellMar>
      <w:top w:w="120" w:type="dxa"/>
      <w:left w:w="160" w:type="dxa"/>
      <w:bottom w:w="120" w:type="dxa"/>
      <w:right w:w="160" w:type="dxa"/>
    </w:tblCellMar>
    <w:jc w:val="center"/>
  </w:tblPr>
  <w:tr>`)

	// Header row
	for _, h := range headers {
		sb.WriteString(fmt.Sprintf(`
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="%d" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="0F172A"/>
      </w:tcPr>
      <w:p>
        <w:pPr><w:spacing w:after="0"/><w:jc w:val="left"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:b/>
            <w:color w:val="FFFFFF"/>
            <w:sz w:val="20"/>
          </w:rPr>
          <w:t>%s</w:t>
        </w:r>
      </w:p>
    </w:tc>`, colWidth, escapeXML(h)))
	}
	sb.WriteString("  </w:tr>")

	// Data rows
	for rowIdx, row := range rows {
		fill := "FFFFFF"
		if rowIdx%2 == 1 {
			fill = "F8FAFC"
		}
		sb.WriteString("  <w:tr>")
		for _, cell := range row {
			sb.WriteString(fmt.Sprintf(`
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="%d" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="%s"/>
      </w:tcPr>
      <w:p>
        <w:pPr><w:spacing w:after="0"/><w:jc w:val="left"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:color w:val="334155"/>
            <w:sz w:val="19"/>
          </w:rPr>
          <w:t>%s</w:t>
        </w:r>
      </w:p>
    </w:tc>`, colWidth, fill, escapeXML(cell)))
		}
		sb.WriteString("  </w:tr>")
	}
	sb.WriteString(`</w:tbl><w:p><w:pPr><w:spacing w:after="160"/></w:pPr></w:p>`)
	b.bodyXML.WriteString(sb.String())
}

func (b *DocxBuilder) AddImage(relID string, widthCX, heightCY int64, caption string) {
	currentFig := b.figNum
	b.figNum++

	b.bodyXML.WriteString(fmt.Sprintf(`
<w:p>
  <w:pPr>
    <w:spacing w:before="180" w:after="80"/>
    <w:jc w:val="center"/>
  </w:pPr>
  <w:r>
    <w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0">
        <wp:extent cx="%d" cy="%d"/>
        <wp:docPr id="%d" name="Figure %d"/>
        <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
          <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
              <pic:nvPicPr>
                <pic:cNvPr id="%d" name="Figure %d"/>
                <pic:cNvPicPr/>
              </pic:nvPicPr>
              <pic:blipFill>
                <a:blip r:embed="%s" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
                <a:stretch><a:fillRect/></a:stretch>
              </pic:blipFill>
              <pic:spPr>
                <a:xfrm>
                  <a:off x="0" y="0"/>
                  <a:ext cx="%d" cy="%d"/>
                </a:xfrm>
                <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
              </pic:spPr>
            </pic:pic>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing>
  </w:r>
</w:p>
<w:p>
  <w:pPr>
    <w:spacing w:after="240"/>
    <w:jc w:val="center"/>
  </w:pPr>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="0F172A"/>
      <w:sz w:val="19"/>
    </w:rPr>
    <w:t>Figure %d: </w:t>
  </w:r>
  <w:r>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:i/>
      <w:color w:val="64748B"/>
      <w:sz w:val="19"/>
    </w:rPr>
    <w:t>%s</w:t>
  </w:r>
</w:p>`, widthCX, heightCY, currentFig, currentFig, currentFig, currentFig, relID, widthCX, heightCY, currentFig, escapeXML(caption)))
}

func (b *DocxBuilder) AddImagePlaceholder(title string, guidance string) {
	currentFig := b.figNum
	b.figNum++

	b.bodyXML.WriteString(fmt.Sprintf(`
<w:tbl>
  <w:tblPr>
    <w:tblW w:w="9200" w:type="dxa"/>
    <w:tblBorders>
      <w:top w:val="dashed" w:sz="8" w:space="0" w:color="94A3B8"/>
      <w:left w:val="dashed" w:sz="8" w:space="0" w:color="94A3B8"/>
      <w:bottom w:val="dashed" w:sz="8" w:space="0" w:color="94A3B8"/>
      <w:right w:val="dashed" w:sz="8" w:space="0" w:color="94A3B8"/>
    </w:tblBorders>
    <w:tblCellMar>
      <w:top w:w="300" w:type="dxa"/>
      <w:left w:w="300" w:type="dxa"/>
      <w:bottom w:w="300" w:type="dxa"/>
      <w:right w:w="300" w:type="dxa"/>
    </w:tblCellMar>
    <w:jc w:val="center"/>
  </w:tblPr>
  <w:tr>
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="9200" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="F8FAFC"/>
      </w:tcPr>
      <w:p>
        <w:pPr><w:jc w:val="center"/><w:spacing w:after="80"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:b/>
            <w:color w:val="00B050"/>
            <w:sz w:val="24"/>
          </w:rPr>
          <w:t>[ 📷 SCREENSHOT PLACEHOLDER ]</w:t>
        </w:r>
      </w:p>
      <w:p>
        <w:pPr><w:jc w:val="center"/><w:spacing w:after="60"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:b/>
            <w:color w:val="0F172A"/>
            <w:sz w:val="22"/>
          </w:rPr>
          <w:t>Figure %d: %s</w:t>
        </w:r>
      </w:p>
      <w:p>
        <w:pPr><w:jc w:val="center"/><w:spacing w:after="0"/></w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
            <w:i/>
            <w:color w:val="64748B"/>
            <w:sz w:val="18"/>
          </w:rPr>
          <w:t>%s</w:t>
        </w:r>
      </w:p>
    </w:tc>
  </w:tr>
</w:tbl>
<w:p><w:pPr><w:spacing w:after="200"/></w:pPr></w:p>`, currentFig, escapeXML(title), escapeXML(guidance)))
}

func (b *DocxBuilder) AddPageBreak() {
	b.bodyXML.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

func (b *DocxBuilder) Save(filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	// 1. [Content_Types].xml
	ctFile, err := zw.Create("[Content_Types].xml")
	if err != nil {
		return err
	}
	ctXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Default Extension="jpeg" ContentType="image/jpeg"/>
  <Default Extension="jpg" ContentType="image/jpeg"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`
	if _, err := ctFile.Write([]byte(ctXML)); err != nil {
		return err
	}

	// 2. _rels/.rels
	rootRelsFile, err := zw.Create("_rels/.rels")
	if err != nil {
		return err
	}
	rootRelsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	if _, err := rootRelsFile.Write([]byte(rootRelsXML)); err != nil {
		return err
	}

	// 3. word/styles.xml
	stylesFile, err := zw.Create("word/styles.xml")
	if err != nil {
		return err
	}
	stylesXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Segoe UI" w:cs="Segoe UI"/>
        <w:sz w:val="22"/>
        <w:color w:val="334155"/>
      </w:rPr>
    </w:rPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Normal" w:default="1">
    <w:name w:val="Normal"/>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="0F172A"/>
      <w:sz w:val="36"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="00B050"/>
      <w:sz w:val="28"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading3">
    <w:name w:val="heading 3"/>
    <w:rPr>
      <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
      <w:b/>
      <w:color w:val="334155"/>
      <w:sz w:val="24"/>
    </w:rPr>
  </w:style>
</w:styles>`
	if _, err := stylesFile.Write([]byte(stylesXML)); err != nil {
		return err
	}

	// 4. word/_rels/document.xml.rels
	docRelsFile, err := zw.Create("word/_rels/document.xml.rels")
	if err != nil {
		return err
	}
	var docRelsXML strings.Builder
	docRelsXML.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
`)
	for _, rel := range b.rels {
		docRelsXML.WriteString(fmt.Sprintf(`  <Relationship Id="%s" Type="%s" Target="%s"/>
`, rel.ID, rel.Type, rel.Target))
	}
	docRelsXML.WriteString(`</Relationships>`)
	if _, err := docRelsFile.Write([]byte(docRelsXML.String())); err != nil {
		return err
	}

	// 5. word/media/*
	for path, data := range b.media {
		mediaFile, err := zw.Create("word/" + path)
		if err != nil {
			return err
		}
		if _, err := mediaFile.Write(data); err != nil {
			return err
		}
	}

	// 6. word/document.xml
	docFile, err := zw.Create("word/document.xml")
	if err != nil {
		return err
	}
	fullDocXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:body>
    %s
    <w:sectPr>
      <w:pgSz w:w="12240" w:h="15840"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>`, b.bodyXML.String())

	_, err = docFile.Write([]byte(fullDocXML))
	return err
}

func main() {
	builder := NewDocxBuilder()

	// Load real images if available
	schneiderLogoBytes, _ := os.ReadFile("web/static/img/schneider-electric.png")
	var logoRId string
	if len(schneiderLogoBytes) > 0 {
		builder.media["media/logo.png"] = schneiderLogoBytes
		logoRId = builder.addRel("http://schemas.openxmlformats.org/officeDocument/2006/relationships/image", "media/logo.png")
	}

	userImg1Path := `C:\Users\SESA757023\.gemini\antigravity\brain\988bb0b6-559a-47a9-8eec-6d936397d9d5\.user_uploaded\media_1794524128876_5c3a29d7.jpg`
	userImg1Bytes, _ := os.ReadFile(userImg1Path)
	var img1RId string
	if len(userImg1Bytes) > 0 {
		builder.media["media/entra_base64_err.jpg"] = userImg1Bytes
		img1RId = builder.addRel("http://schemas.openxmlformats.org/officeDocument/2006/relationships/image", "media/entra_base64_err.jpg")
	}

	userImg2Path := `C:\Users\SESA757023\.gemini\antigravity\brain\988bb0b6-559a-47a9-8eec-6d936397d9d5\.user_uploaded\media_1794524868965_6f4f7dbc.jpg`
	userImg2Bytes, _ := os.ReadFile(userImg2Path)
	var img2RId string
	if len(userImg2Bytes) > 0 {
		builder.media["media/entra_identifier_err.jpg"] = userImg2Bytes
		img2RId = builder.addRel("http://schemas.openxmlformats.org/officeDocument/2006/relationships/image", "media/entra_identifier_err.jpg")
	}

	// ==================== COVER PAGE ====================
	if logoRId != "" {
		builder.AddImage(logoRId, 2400000, 600000, "Schneider Electric Official Brand")
	}
	builder.AddTitle("SAMLGuard Enterprise MFA Gateway", "Installation, Multi-Platform Deployment & Administration Manual")

	builder.AddCallout("Document Metadata",
		"Application: SAMLGuard for Schneider Electric EcoStruxure IT Advisor\n"+
			"Version: v1.1.1 (Release Build)\n"+
			"Author / Integration: Hidayat Ahmad / Schneider Electric System Architecture\n"+
			"Date: November 2026\n"+
			"Platforms: Linux (systemd + Webmin :10000), Windows Server (SCM Service), Docker",
		"00B050", "F0FDF4")

	builder.AddParagraph("This comprehensive manual provides complete deployment, installation, multi-factor authentication (MFA) configuration, and operational guidelines for deploying SAMLGuard as a secure SAML 2.0 Reverse Proxy Gateway for Schneider Electric EcoStruxure IT Advisor.")

	builder.AddPageBreak()

	// ==================== TABLE OF CONTENTS SUMMARY ====================
	builder.AddHeading("Table of Contents", 1)
	builder.AddBullet("Overview of architecture, components, and traffic redirection flow", "1. Executive Summary & Architecture")
	builder.AddBullet("Single-command installation, permissions, systemd service, and port 8443 co-hosting", "2. First-Time Linux Service Installation")
	builder.AddBullet("Installing samlguard-webmin.wbm.gz, sidebar navigation, certificates, logs, and uninstallation", "3. Webmin Management Suite Integration")
	builder.AddBullet("PowerShell service installer, firewall configuration, and service control manager", "4. Windows Server Deployment")
	builder.AddBullet("Comprehensive breakdown of config.yaml, admin credentials, and security settings", "5. Configuration Reference (config.yaml)")
	builder.AddBullet("Resolution of AADSTS750056 (Base64) and AADSTS700016 (Identifier mismatch)", "6. Microsoft Entra ID (Azure AD) SSO Integration")
	builder.AddBullet("Mobile Outlook lock-screen alerts, Mailgun SMTP, and air-gapped offline TOTP", "7. Multi-Factor Authentication (MFA) Setup")
	builder.AddBullet("Diagnostics, log inspection, port checking, and operational procedures", "8. Troubleshooting & Maintenance Runbook")

	builder.AddPageBreak()

	// ==================== SECTION 1: ARCHITECTURE ====================
	builder.AddHeading("1. Executive Summary & Architecture", 1)
	builder.AddParagraph("SAMLGuard acts as a zero-trust, reverse proxy identity mediation gateway positioned between downstream Service Providers (such as Schneider Electric EcoStruxure IT Advisor) and upstream SAML 2.0 Identity Providers (such as Microsoft Entra ID, PingFederate, Keycloak, or Okta).")

	builder.AddImagePlaceholder("SAMLGuard Architectural Topology",
		"Replace with a high-level network topology diagram showing: User Browser -> SAMLGuard Gateway (:8443) -> Upstream IdP (Entra ID) -> MFA Challenge (Mailgun Email OTP / TOTP) -> Schneider IT Advisor (:443).")

	builder.AddHeading("Authentication Flow Sequence", 2)
	builder.AddNumberedItem(1, "SP-Initiated Request", "User navigates to Schneider IT Advisor. ITA initiates SAML login by redirecting the browser with an AuthnRequest to SAMLGuard (https://<server>:8443/saml/sso).")
	builder.AddNumberedItem(2, "Upstream IdP Redirection", "SAMLGuard validates the inbound request, builds a deflated SAML 2.0 AuthnRequest, and redirects the user to Microsoft Entra ID or the local IdP.")
	builder.AddNumberedItem(3, "Primary Authentication", "User enters primary corporate credentials at the upstream IdP. The IdP signs an assertion and returns the user to SAMLGuard (/saml/acs).")
	builder.AddNumberedItem(4, "MFA Verification", "SAMLGuard intercepts the callback, checks user authorization, and triggers the configured MFA factor (High-Priority Mobile Email OTP or TOTP Authenticator).")
	builder.AddNumberedItem(5, "Downstream Assertion", "Once MFA succeeds, SAMLGuard generates a freshly signed SAML response tailored for Schneider IT Advisor and posts it to ITA's callback endpoint.")

	builder.AddTable([]string{"Component", "Network Endpoint", "Role / Protocol", "Default Port"},
		[][]string{
			{"EcoStruxure IT Advisor", "https://192.168.0.119/api/current", "Downstream Service Provider (SP)", "443 (HTTPS)"},
			{"SAMLGuard Gateway", "https://192.168.0.119:8443", "SAML 2.0 Reverse Proxy & MFA Engine", "8443 (HTTPS)"},
			{"Webmin Server", "https://192.168.0.119:10000", "Linux Appliance & Service Management", "10000 (HTTPS)"},
			{"Upstream Identity Provider", "https://login.microsoftonline.com/...", "Primary Corporate IdP (Entra ID / PingID)", "443 (HTTPS)"},
		})

	builder.AddPageBreak()

	// ==================== SECTION 2: FIRST-TIME LINUX INSTALLATION ====================
	builder.AddHeading("2. First-Time Linux Service Installation", 1)
	builder.AddParagraph("For Linux servers running Ubuntu, Debian, Red Hat Enterprise Linux (RHEL), or Rocky Linux, SAMLGuard provides an automated native installer that configures an isolated system service.")

	builder.AddHeading("Prerequisites & Packaging", 2)
	builder.AddParagraph("Ensure you have copied the release tarball and Webmin package from the dist/ folder to the Linux server:")
	builder.AddBullet("samlguard-v1.1.1-linux-amd64.tar.gz (Native standalone binary & scripts)", "Binary Package")
	builder.AddBullet("samlguard-webmin.wbm.gz (Webmin management suite)", "Webmin Suite")

	builder.AddHeading("Installation Commands", 2)
	builder.AddCodeBlock(`# 1. Extract the release package
tar -xzf samlguard-v1.1.1-linux-amd64.tar.gz
cd samlguard-v1.1.1-linux-amd64

# 2. Run the automated installer as root
sudo ./scripts/linux/install.sh ./bin/samlguard

# 3. Verify service registration and status
sudo systemctl status samlguard`)

	builder.AddImagePlaceholder("Linux Terminal - install.sh Execution & systemctl status",
		"Replace with a terminal screenshot showing the execution of sudo ./scripts/linux/install.sh and the active (running) status in systemctl status samlguard.")

	builder.AddCallout("Co-hosting with Schneider IT Advisor on Port 8443",
		"Schneider IT Advisor occupies port 443 by default. SAMLGuard is configured out-of-the-box to run on port 8443 with TLS enabled, allowing both systems to run seamlessly on the exact same IP address without port conflict.",
		"00B050", "F0FDF4")

	builder.AddPageBreak()

	// ==================== SECTION 3: WEBMIN MANAGEMENT SUITE ====================
	builder.AddHeading("3. Webmin Management Suite Integration", 1)
	builder.AddParagraph("SAMLGuard includes an integrated 5-module Webmin package (samlguard-webmin.wbm.gz) that adds a dedicated SAMLGuard management category in the Webmin sidebar.")

	builder.AddHeading("Installing the Webmin Module Package", 2)
	builder.AddNumberedItem(1, "Log In to Webmin", "Open your web browser and navigate to https://<server-ip>:10000.")
	builder.AddNumberedItem(2, "Open Webmin Modules", "In the Webmin menu, navigate to Webmin -> Webmin Configuration -> Webmin Modules.")
	builder.AddNumberedItem(3, "Upload Package", "Select 'From uploaded file', browse to dist/samlguard-webmin.wbm.gz, and click 'Install Module'.")
	builder.AddNumberedItem(4, "Refresh Sidebar", "Click 'Refresh Modules' at the bottom of the left sidebar to reveal the SAMLGuard category.")

	builder.AddImagePlaceholder("Webmin - Upload and Install Module Screen",
		"Replace with a screenshot of Webmin -> Webmin Configuration -> Webmin Modules showing the file upload selection for samlguard-webmin.wbm.gz.")

	builder.AddImagePlaceholder("Webmin - SAMLGuard Sidebar Category & Status Screen",
		"Replace with a screenshot of the Webmin left sidebar showing the expanded SAMLGuard menu (About, Certificates, Debug, Setup, Status) and the service status card.")

	builder.AddHeading("Webmin Module Features", 2)
	builder.AddBullet("Version information, active network port, and direct link to the web Admin Console.", "About (samlguard_about)")
	builder.AddBullet("Inspect X.509 certificate metadata, validity dates, and upload new .crt / .key files.", "Certificates (samlguard_certs)")
	builder.AddBullet("View, filter, and export live journalctl -u samlguard logs and inspect active sockets.", "Debug / Logs (samlguard_logs)")
	builder.AddBullet("Inspect parsed configuration summary and edit /etc/samlguard/config.yaml directly in the browser.", "Setup (samlguard_setup)")
	builder.AddBullet("Start, stop, restart, enable on boot, verify /health probe, and perform 1-click upgrades.", "Status (samlguard_status)")

	builder.AddHeading("Uninstalling the Webmin Modules", 2)
	builder.AddParagraph("To uninstall SAMLGuard from Webmin without affecting the underlying system:")
	builder.AddNumberedItem(1, "Open Delete Tab", "Navigate to Webmin -> Webmin Configuration -> Webmin Modules, then click the 'Delete' tab at the top.")
	builder.AddNumberedItem(2, "Select Modules", "Check the 5 SAMLGuard modules (samlguard_about, samlguard_certs, samlguard_logs, samlguard_setup, samlguard_status).")
	builder.AddNumberedItem(3, "Confirm Removal", "Click 'Delete Selected Modules'. The built-in uninstall hook will clean up category mappings and flush Webmin cache.")

	builder.AddImagePlaceholder("Webmin - Delete Modules Screen",
		"Replace with a screenshot of the Delete tab in Webmin Modules with the 5 SAMLGuard modules selected for removal.")

	builder.AddPageBreak()

	// ==================== SECTION 4: WINDOWS SERVER DEPLOYMENT ====================
	builder.AddHeading("4. Windows Server Deployment", 1)
	builder.AddParagraph("For deployments on Windows Server 2019/2022/2025, SAMLGuard integrates natively with the Windows Service Control Manager (SCM).")

	builder.AddHeading("Automated Service Installation", 2)
	builder.AddCodeBlock(`# Open PowerShell as Administrator
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Execute service installer
.\scripts\windows\install-service.ps1 -BinarySource .\bin\samlguard.exe

# Configure Windows Firewall rule for HTTPS port 8443
New-NetFirewallRule -DisplayName "SAMLGuard HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow

# Start and verify the Windows Service
Start-Service -Name SAMLGuard
Get-Service -Name SAMLGuard`)

	builder.AddTable([]string{"Item", "Windows File Location", "Security Permissions"},
		[][]string{
			{"Binary Executable", "C:\\Program Files\\SAMLGuard\\samlguard.exe", "Administrators / SYSTEM (Execute)"},
			{"Configuration File", "C:\\ProgramData\\SAMLGuard\\config.yaml", "Administrators / SYSTEM (Read/Write)"},
			{"SQLite Database", "C:\\ProgramData\\SAMLGuard\\data\\samlguard.db", "Administrators / SYSTEM (Read/Write)"},
			{"Certificates & Keys", "C:\\ProgramData\\SAMLGuard\\cert\\", "Administrators / SYSTEM (Restricted)"},
		})

	builder.AddPageBreak()

	// ==================== SECTION 5: CONFIGURATION GUIDE ====================
	builder.AddHeading("5. Configuration Reference (config.yaml)", 1)
	builder.AddParagraph("The bootstrap configuration file is located at /etc/samlguard/config.yaml on Linux and C:\\ProgramData\\SAMLGuard\\config.yaml on Windows. Key configuration blocks are detailed below:")

	builder.AddCodeBlock(`server:
  host: 0.0.0.0
  port: 8443
  tls_enabled: true

saml:
  entity_id: https://192.168.0.119:8443
  sso_url: https://192.168.0.119:8443/login
  acs_url: https://192.168.0.119/api/current/authentication/saml2-callback
  cert_file: ./cert/saml-signing.crt
  key_file: ./cert/saml-signing.key
  active_idp: entra

mfa:
  default_provider: email
  otp_expiry: 5m
  resend_cooldown: 1m
  max_retries: 5
  trust_device_days: 30

smtp:
  host: smtp.mailgun.org
  port: 587
  username: postmaster@your-domain.com
  password: "YOUR_MAILGUN_PASSWORD"
  from: no-reply@your-domain.com
  from_name: Schneider IT Advisor
  encryption: starttls`)

	builder.AddImagePlaceholder("SAMLGuard Web Admin Console - Gateway & Security Settings",
		"Replace with a screenshot of https://192.168.0.119:8443/admin/settings showing the Gateway Settings tab and MFA policies.")

	builder.AddPageBreak()

	// ==================== SECTION 6: ENTRA ID INTEGRATION ====================
	builder.AddHeading("6. Microsoft Entra ID (Azure AD) SSO Integration", 1)
	builder.AddParagraph("This section covers the integration with corporate Microsoft Entra ID and documents the resolution of common SAML errors encountered during deployment.")

	builder.AddHeading("Issue 1: AADSTS750056 (Base64 Encoding Error)", 2)
	builder.AddParagraph("Error: 'AADSTS750056: SAML message was not properly base64-encoded.'")
	builder.AddParagraph("Root Cause: The HTTP-Redirect URL passed a plain correlation string (?SAMLRequest=SG_...) instead of an RFC 1951 DEFLATE-compressed, Base64-encoded <samlp:AuthnRequest> XML document.")
	builder.AddParagraph("Resolution: Implemented buildOutboundAuthnRequest and deflateAndEncode in internal/gateway/handler/handler.go to generate compliant SAML 2.0 requests.")

	if img1RId != "" {
		builder.AddImage(img1RId, 5486400, 3086100, "Microsoft Entra ID Error AADSTS750056 (Resolved)")
	} else {
		builder.AddImagePlaceholder("Microsoft Entra ID Error AADSTS750056", "Screenshot showing the AADSTS750056 error in Microsoft Entra ID sign-in.")
	}

	builder.AddHeading("Issue 2: AADSTS700016 (Application Identifier Mismatch)", 2)
	builder.AddParagraph("Error: 'AADSTS700016: Application with identifier https://192.168.0.119:8443 was not found in the directory.'")
	builder.AddParagraph("Root Cause: Microsoft Entra ID requires the <saml:Issuer> in the AuthnRequest to match the registered 'Identifier (Entity ID)' in the Enterprise Application under Basic SAML Configuration.")
	builder.AddParagraph("Resolution: In the Microsoft Entra admin center, set Identifier (Entity ID) to https://192.168.0.119:8443 and Reply URL (ACS) to https://192.168.0.119:8443/saml/acs. Alternatively, update SAMLGuard's Entity ID in Admin Settings to match the existing registration.")

	if img2RId != "" {
		builder.AddImage(img2RId, 5486400, 3086100, "Microsoft Entra ID Error AADSTS700016 (Application Identifier Mismatch)")
	} else {
		builder.AddImagePlaceholder("Microsoft Entra ID Error AADSTS700016", "Screenshot showing the AADSTS700016 error in Schneider Electric production tenant.")
	}

	builder.AddImagePlaceholder("Microsoft Entra Admin Center - Basic SAML Configuration",
		"Replace with a screenshot of Microsoft Entra admin center -> Enterprise applications -> [App] -> Single sign-on -> SAML -> Section 1 (Basic SAML Configuration).")

	builder.AddPageBreak()

	// ==================== SECTION 7: MFA & MAILGUN SETUP ====================
	builder.AddHeading("7. Multi-Factor Authentication (MFA) Setup", 1)
	builder.AddParagraph("SAMLGuard supports multiple flexible MFA methods tailored for enterprise environments, including cloud push alerts and air-gapped offline networks.")

	builder.AddHeading("High-Priority Mobile Lock-Screen Email Alerts", 2)
	builder.AddParagraph("To provide an experience similar to PingID or Push Notifications without requiring proprietary cloud apps, SAMLGuard formats Email OTP messages with urgent push headers (X-Priority: 1, Importance: High) and embeds the 6-digit code directly in the subject line brackets:")
	builder.AddBullet("[582 104] Schneider IT Advisor Sign-In Code", "Subject Format")
	builder.AddBullet("Users see the 6-digit code directly on their smartphone lock screen preview banner in Microsoft Outlook without unlocking the phone.", "Instant Visibility")

	builder.AddImagePlaceholder("Mobile Lock-Screen Notification Preview & Outlook Card",
		"Replace with an iPhone or Android lock-screen screenshot showing the Outlook notification preview with [582 104] and the opened branded HTML email.")

	builder.AddHeading("Mailgun SMTP Configuration", 2)
	builder.AddParagraph("SAMLGuard integrates directly with Mailgun SMTP for high-deliverability email dispatch:")
	builder.AddTable([]string{"Parameter", "Mailgun Configuration Value", "Description"},
		[][]string{
			{"SMTP Host", "smtp.mailgun.org", "Mailgun US/Global SMTP server (or smtp.eu.mailgun.org for EU)"},
			{"SMTP Port", "587", "Port with STARTTLS encryption"},
			{"SMTP Username", "postmaster@your-domain.com", "SMTP credential created under Mailgun Sending Domains"},
			{"SMTP Password", "YOUR_MAILGUN_SMTP_PASSWORD", "API or SMTP password generated in Mailgun"},
			{"From Address", "no-reply@your-domain.com", "Must match your verified Mailgun sending domain"},
			{"From Name", "Schneider IT Advisor", "Sender display name shown in user mailboxes"},
		})

	builder.AddImagePlaceholder("SAMLGuard Admin Console - Live SMTP Test with Mailgun",
		"Replace with a screenshot of Admin Settings -> MFA & Security Policies -> Live SMTP Test showing a successful test email dispatch.")

	builder.AddHeading("Offline / Air-Gapped Datacenter MFA (TOTP)", 2)
	builder.AddParagraph("For strictly isolated on-premises environments with zero internet access, SAMLGuard's TOTP Authenticator requires no external network connectivity:")
	builder.AddBullet("Math-Based: Uses RFC 6238 HMAC-SHA1 algorithm based solely on server time and secret key.", "Zero Internet")
	builder.AddBullet("Works in Airplane Mode: Phone needs no Wi-Fi, cellular data, or SIM card.", "Offline Phone")
	builder.AddBullet("Fully Compatible: Works with Microsoft Authenticator, Google Authenticator, or KeePassXC.", "Universal Support")

	builder.AddPageBreak()

	// ==================== SECTION 8: TROUBLESHOOTING ====================
	builder.AddHeading("8. Troubleshooting & Maintenance Runbook", 1)
	builder.AddParagraph("Common operational procedures and diagnostic commands:")

	builder.AddTable([]string{"Symptom / Issue", "Root Cause", "Resolution Command / Action"},
		[][]string{
			{"Service fails to bind port 8443", "Port already in use or permission denied", "Check with 'sudo ss -tulpn | grep 8443'. Reapply 'sudo setcap cap_net_bind_service=+ep /usr/local/bin/samlguard'."},
			{"AADSTS700016 in Entra ID", "Entity ID mismatch between SP and IdP", "Set Identifier (Entity ID) in Entra ID to match SAMLGuard's Entity ID (https://192.168.0.119:8443)."},
			{"Mailgun SMTP test fails", "Port 587 blocked or unverified sender", "Verify outbound firewall on port 587. Ensure From Address matches your verified Mailgun domain."},
			{"User locked out of MFA", "Max retries (5) exceeded", "Admin can unlock or reset the user in Admin Console -> User Management."},
			{"Webmin SAMLGuard menu missing", "Caches not refreshed after install", "Click 'Refresh Modules' in Webmin bottom sidebar or restart Webmin ('sudo systemctl restart webmin')."},
		})

	builder.AddHeading("Diagnostic Commands Quick Reference", 2)
	builder.AddCodeBlock(`# Check service status
sudo systemctl status samlguard

# Follow live service logs
sudo journalctl -u samlguard -f

# Verify listening port
sudo ss -tulpn | grep samlguard

# Query internal health probe
curl -k https://localhost:8443/health`)

	// Save document
	outPath := "docs/SAMLGuard_Deployment_and_User_Manual.docx"
	if err := builder.Save(outPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving docx: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully generated DOCX manual at: %s\n", outPath)

	// Also copy to root for easy user access
	rootOut := "SAMLGuard_Deployment_and_User_Manual.docx"
	if err := builder.Save(rootOut); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving root docx: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully copied DOCX manual to root: %s\n", rootOut)
}
