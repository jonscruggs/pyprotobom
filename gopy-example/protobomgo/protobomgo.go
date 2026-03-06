// Package protobomgo provides a gopy-friendly wrapper around the protobom Go
// library.  gopy works best with exported types that use primitive Go types,
// so this thin layer converts between the rich protobuf-generated protobom
// types and simple strings/slices that cross the Python boundary cleanly.
package protobomgo

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// ---------- lightweight Python-visible value types ----------

// NodeInfo is a simplified view of a protobom Node suitable for Python.
type NodeInfo struct {
	ID               string
	Type             string // "PACKAGE" or "FILE"
	Name             string
	Version          string
	FileName         string
	Copyright        string
	LicenseConcluded string
	Comment          string
	Description      string
	Purl             string
}

// EdgeInfo is a simplified view of a protobom Edge.
// Field names avoid Python reserved words (e.g. "from").
type EdgeInfo struct {
	Type     string
	FromNode string
	ToNodes  string // comma-separated list of target node IDs
}

// DocumentInfo holds the top-level metadata of a parsed SBOM document.
type DocumentInfo struct {
	ID      string
	Name    string
	Version string
	Format  string // detected source format, e.g. "text/spdx+json;version=2.3"
}

// ---------- document handle (opaque to Python, passed by ID) ----------

// docStore keeps parsed documents in memory so Python can reference them
// through a simple string handle.
var docStore = map[string]*sbom.Document{}

// ---------- public API (all arguments/returns are gopy-friendly) ----------

// ReadFile parses an SBOM file (SPDX or CycloneDX) and returns a handle ID
// that can be passed to the other functions.
func ReadFile(path string) (string, error) {
	r := reader.New()
	doc, err := r.ParseFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	id := doc.Metadata.GetId()
	if id == "" {
		id = path // fallback handle
	}
	docStore[id] = doc
	return id, nil
}

// GetDocumentInfo returns metadata about a previously parsed document.
func GetDocumentInfo(handle string) (DocumentInfo, error) {
	doc, ok := docStore[handle]
	if !ok {
		return DocumentInfo{}, fmt.Errorf("unknown document handle: %s", handle)
	}

	info := DocumentInfo{
		ID:      doc.Metadata.GetId(),
		Name:    doc.Metadata.GetName(),
		Version: doc.Metadata.GetVersion(),
	}

	if doc.Metadata.SourceData != nil {
		info.Format = doc.Metadata.SourceData.Format
	}
	return info, nil
}

// GetNodeCount returns the number of nodes in the document's graph.
func GetNodeCount(handle string) (int, error) {
	doc, ok := docStore[handle]
	if !ok {
		return 0, fmt.Errorf("unknown document handle: %s", handle)
	}
	return len(doc.NodeList.Nodes), nil
}

// GetNodeIDs returns all node IDs as a comma-separated string.
func GetNodeIDs(handle string) (string, error) {
	doc, ok := docStore[handle]
	if !ok {
		return "", fmt.Errorf("unknown document handle: %s", handle)
	}
	ids := make([]string, 0, len(doc.NodeList.Nodes))
	for _, n := range doc.NodeList.Nodes {
		ids = append(ids, n.Id)
	}
	return strings.Join(ids, ","), nil
}

// GetNodeInfo returns details about a single node by its ID.
func GetNodeInfo(handle, nodeID string) (NodeInfo, error) {
	doc, ok := docStore[handle]
	if !ok {
		return NodeInfo{}, fmt.Errorf("unknown document handle: %s", handle)
	}

	for _, n := range doc.NodeList.Nodes {
		if n.Id == nodeID {
			return nodeInfoFromNode(n), nil
		}
	}
	return NodeInfo{}, fmt.Errorf("node %s not found", nodeID)
}

// GetRootNodeIDs returns the root element IDs as a comma-separated string.
func GetRootNodeIDs(handle string) (string, error) {
	doc, ok := docStore[handle]
	if !ok {
		return "", fmt.Errorf("unknown document handle: %s", handle)
	}
	return strings.Join(doc.NodeList.RootElements, ","), nil
}

// GetEdges returns all edges in a document as a JSON array of EdgeInfo.
func GetEdges(handle string) (string, error) {
	doc, ok := docStore[handle]
	if !ok {
		return "", fmt.Errorf("unknown document handle: %s", handle)
	}

	edges := make([]EdgeInfo, 0, len(doc.NodeList.Edges))
	for _, e := range doc.NodeList.Edges {
		edges = append(edges, EdgeInfo{
			Type:     e.Type.String(),
			FromNode: e.From,
			ToNodes:  strings.Join(e.To, ","),
		})
	}

	data, err := json.Marshal(edges)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteFile serialises the referenced document to the given format and writes
// it to path.  format should be one of the format constants such as
// "text/spdx+json;version=2.3" or "application/vnd.cyclonedx+json;version=1.5".
func WriteFile(handle, path, format string) error {
	doc, ok := docStore[handle]
	if !ok {
		return fmt.Errorf("unknown document handle: %s", handle)
	}

	w := writer.New(writer.WithFormat(formats.Format(format)))
	return w.WriteFile(doc, path)
}

// ConvertFile is a convenience wrapper: read an SBOM in any supported format
// and write it out in the requested target format.
func ConvertFile(inputPath, outputPath, outputFormat string) error {
	handle, err := ReadFile(inputPath)
	if err != nil {
		return err
	}
	return WriteFile(handle, outputPath, outputFormat)
}

// NewDocument creates a new empty SBOM document in memory and returns its
// handle.
func NewDocument(id, name, version string) string {
	doc := sbom.NewDocument()
	doc.Metadata.Id = id
	doc.Metadata.Name = name
	doc.Metadata.Version = version
	docStore[id] = doc
	return id
}

// AddNode adds a new package node to the document and returns the node ID.
func AddNode(handle, nodeID, name, version, purl string) error {
	doc, ok := docStore[handle]
	if !ok {
		return fmt.Errorf("unknown document handle: %s", handle)
	}

	n := sbom.NewNode()
	n.Id = nodeID
	n.Name = name
	n.Version = version
	n.Type = sbom.Node_PACKAGE
	if purl != "" {
		n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purl
	}

	doc.NodeList.Nodes = append(doc.NodeList.Nodes, n)
	return nil
}

// AddRootNode adds a node ID to the document's root elements list.
func AddRootNode(handle, nodeID string) error {
	doc, ok := docStore[handle]
	if !ok {
		return fmt.Errorf("unknown document handle: %s", handle)
	}

	doc.NodeList.RootElements = append(doc.NodeList.RootElements, nodeID)
	return nil
}

// AddEdge adds a relationship edge to the document.  edgeType should be one of
// the Edge_Type protobuf enum names such as "dependsOn", "contains", etc.
// toNodeIDs is a comma-separated list of target node IDs.
func AddEdge(handle, fromNodeID, edgeType, toNodeIDs string) error {
	doc, ok := docStore[handle]
	if !ok {
		return fmt.Errorf("unknown document handle: %s", handle)
	}

	et, ok := sbom.Edge_Type_value[edgeType]
	if !ok {
		return fmt.Errorf("unknown edge type: %s", edgeType)
	}

	to := strings.Split(toNodeIDs, ",")
	for i := range to {
		to[i] = strings.TrimSpace(to[i])
	}

	doc.NodeList.Edges = append(doc.NodeList.Edges, &sbom.Edge{
		Type: sbom.Edge_Type(et),
		From: fromNodeID,
		To:   to,
	})
	return nil
}

// DocumentToJSON serialises the in-memory document to a JSON string using the
// protobom writer with the given output format.
func DocumentToJSON(handle, format string) (string, error) {
	doc, ok := docStore[handle]
	if !ok {
		return "", fmt.Errorf("unknown document handle: %s", handle)
	}

	w := writer.New(writer.WithFormat(formats.Format(format)))
	var buf strings.Builder
	if err := w.WriteStream(doc, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// CloseDocument removes a document from the in-memory store.
func CloseDocument(handle string) {
	delete(docStore, handle)
}

// ListFormats returns a comma-separated list of the supported output format
// strings.
func ListFormats() string {
	fmts := []string{
		string(formats.SPDX23JSON),
		string(formats.CDX14JSON),
		string(formats.CDX15JSON),
		string(formats.CDX16JSON),
	}
	return strings.Join(fmts, ",")
}

// ---------- internal helpers ----------

func nodeInfoFromNode(n *sbom.Node) NodeInfo {
	ntype := "PACKAGE"
	if n.Type == sbom.Node_FILE {
		ntype = "FILE"
	}
	info := NodeInfo{
		ID:               n.Id,
		Type:             ntype,
		Name:             n.Name,
		Version:          n.Version,
		FileName:         n.FileName,
		Copyright:        n.Copyright,
		LicenseConcluded: n.LicenseConcluded,
		Comment:          n.Comment,
		Description:      n.Description,
	}

	if purl := n.Purl(); purl != "" {
		info.Purl = string(purl)
	}
	return info
}

// SaveDocumentToFile is an alias kept for discoverability.
func SaveDocumentToFile(handle, path, format string) error {
	return WriteFile(handle, path, format)
}

// GetNodeInfoJSON returns the NodeInfo as a JSON string for easy consumption
// in Python when the struct mapping is not needed.
func GetNodeInfoJSON(handle, nodeID string) (string, error) {
	info, err := GetNodeInfo(handle, nodeID)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DumpAllNodesJSON returns a JSON array of all NodeInfo structs in the
// document, useful for quick inspection from Python.
func DumpAllNodesJSON(handle string) (string, error) {
	doc, ok := docStore[handle]
	if !ok {
		return "", fmt.Errorf("unknown document handle: %s", handle)
	}

	infos := make([]NodeInfo, 0, len(doc.NodeList.Nodes))
	for _, n := range doc.NodeList.Nodes {
		infos = append(infos, nodeInfoFromNode(n))
	}

	data, err := json.MarshalIndent(infos, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteDocumentToStdout is a convenience function that writes the document to
// stdout in the requested format.
func WriteDocumentToStdout(handle, format string) error {
	doc, ok := docStore[handle]
	if !ok {
		return fmt.Errorf("unknown document handle: %s", handle)
	}

	w := writer.New(writer.WithFormat(formats.Format(format)))
	return w.WriteStream(doc, os.Stdout)
}
