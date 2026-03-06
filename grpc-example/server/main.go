// Package main implements a gRPC server that wraps the protobom Go library.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/protobom/pyprotobom/grpc-example/proto"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// ---------- document store ----------

type docStore struct {
	mu   sync.RWMutex
	docs map[string]*sbom.Document
}

func newDocStore() *docStore {
	return &docStore{docs: map[string]*sbom.Document{}}
}

func (s *docStore) Put(id string, doc *sbom.Document) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[id] = doc
}

func (s *docStore) Get(id string) (*sbom.Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.docs[id]
	return d, ok
}

func (s *docStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, id)
}

// ---------- gRPC server ----------

type protobomServer struct {
	pb.UnimplementedProtobomServiceServer
	store *docStore
}

func newServer() *protobomServer {
	return &protobomServer{store: newDocStore()}
}

// ---- ParseFile ----

func (s *protobomServer) ParseFile(_ context.Context, req *pb.ParseFileRequest) (*pb.ParseFileResponse, error) {
	r := reader.New()
	doc, err := r.ParseFile(req.Path)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", req.Path, err)
	}

	handle := doc.Metadata.GetId()
	if handle == "" {
		handle = req.Path
	}
	s.store.Put(handle, doc)

	return &pb.ParseFileResponse{Handle: handle}, nil
}

// ---- GetDocumentInfo ----

func (s *protobomServer) GetDocumentInfo(_ context.Context, req *pb.DocumentRequest) (*pb.DocumentInfoResponse, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	resp := &pb.DocumentInfoResponse{
		Id:      doc.Metadata.GetId(),
		Name:    doc.Metadata.GetName(),
		Version: doc.Metadata.GetVersion(),
	}
	if doc.Metadata.SourceData != nil {
		resp.SourceFormat = doc.Metadata.SourceData.Format
	}
	return resp, nil
}

// ---- GetNodes ----

func (s *protobomServer) GetNodes(_ context.Context, req *pb.DocumentRequest) (*pb.GetNodesResponse, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	resp := &pb.GetNodesResponse{
		RootIds: doc.NodeList.RootElements,
	}
	for _, n := range doc.NodeList.Nodes {
		resp.Nodes = append(resp.Nodes, nodeToProto(n))
	}
	return resp, nil
}

// ---- GetNodeInfo ----

func (s *protobomServer) GetNodeInfo(_ context.Context, req *pb.GetNodeInfoRequest) (*pb.NodeInfoResponse, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	for _, n := range doc.NodeList.Nodes {
		if n.Id == req.NodeId {
			return &pb.NodeInfoResponse{Node: nodeToProto(n)}, nil
		}
	}
	return nil, fmt.Errorf("node %s not found", req.NodeId)
}

// ---- GetEdges ----

func (s *protobomServer) GetEdges(_ context.Context, req *pb.DocumentRequest) (*pb.GetEdgesResponse, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	resp := &pb.GetEdgesResponse{}
	for _, e := range doc.NodeList.Edges {
		resp.Edges = append(resp.Edges, &pb.EdgeInfo{
			Type:     e.Type.String(),
			FromNode: e.From,
			ToNodes:  e.To,
		})
	}
	return resp, nil
}

// ---- Convert (in-memory, no file I/O) ----

func (s *protobomServer) Convert(_ context.Context, req *pb.ConvertRequest) (*pb.ConvertResponse, error) {
	// Read input.
	r := reader.New()
	rs := bytes.NewReader(req.SbomData)
	doc, err := r.ParseStream(rs)
	if err != nil {
		return nil, fmt.Errorf("parsing input SBOM: %w", err)
	}

	detectedFmt := ""
	if doc.Metadata.SourceData != nil {
		detectedFmt = doc.Metadata.SourceData.Format
	}

	// Write to output format.
	w := writer.New(writer.WithFormat(formats.Format(req.OutputFormat)))
	var buf bytes.Buffer
	if err := w.WriteStream(doc, &buf); err != nil {
		return nil, fmt.Errorf("writing %s: %w", req.OutputFormat, err)
	}

	return &pb.ConvertResponse{
		SbomData:       buf.Bytes(),
		DetectedFormat: detectedFmt,
	}, nil
}

// ---- CreateDocument ----

func (s *protobomServer) CreateDocument(_ context.Context, req *pb.CreateDocumentRequest) (*pb.CreateDocumentResponse, error) {
	doc := sbom.NewDocument()
	doc.Metadata.Id = req.Id
	doc.Metadata.Name = req.Name
	doc.Metadata.Version = req.Version

	s.store.Put(req.Id, doc)
	return &pb.CreateDocumentResponse{Handle: req.Id}, nil
}

// ---- AddNode ----

func (s *protobomServer) AddNode(_ context.Context, req *pb.AddNodeRequest) (*pb.Empty, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	n := sbom.NewNode()
	n.Id = req.Id
	n.Name = req.Name
	n.Version = req.Version
	n.Type = sbom.Node_PACKAGE
	if req.Purl != "" {
		n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = req.Purl
	}

	doc.NodeList.Nodes = append(doc.NodeList.Nodes, n)
	if req.IsRoot {
		doc.NodeList.RootElements = append(doc.NodeList.RootElements, req.Id)
	}

	return &pb.Empty{}, nil
}

// ---- AddEdge ----

func (s *protobomServer) AddEdge(_ context.Context, req *pb.AddEdgeRequest) (*pb.Empty, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	et, ok := sbom.Edge_Type_value[req.EdgeType]
	if !ok {
		return nil, fmt.Errorf("unknown edge type: %s", req.EdgeType)
	}

	doc.NodeList.Edges = append(doc.NodeList.Edges, &sbom.Edge{
		Type: sbom.Edge_Type(et),
		From: req.FromNodeId,
		To:   req.ToNodeIds,
	})
	return &pb.Empty{}, nil
}

// ---- Render ----

func (s *protobomServer) Render(_ context.Context, req *pb.RenderRequest) (*pb.RenderResponse, error) {
	doc, ok := s.store.Get(req.Handle)
	if !ok {
		return nil, fmt.Errorf("unknown document: %s", req.Handle)
	}

	w := writer.New(writer.WithFormat(formats.Format(req.Format)))
	var buf bytes.Buffer
	if err := w.WriteStream(doc, &buf); err != nil {
		return nil, fmt.Errorf("rendering: %w", err)
	}

	return &pb.RenderResponse{SbomData: buf.Bytes()}, nil
}

// ---- CloseDocument ----

func (s *protobomServer) CloseDocument(_ context.Context, req *pb.DocumentRequest) (*pb.Empty, error) {
	s.store.Delete(req.Handle)
	return &pb.Empty{}, nil
}

// ---- ListFormats ----

func (s *protobomServer) ListFormats(_ context.Context, _ *pb.Empty) (*pb.ListFormatsResponse, error) {
	return &pb.ListFormatsResponse{
		Formats: []string{
			string(formats.SPDX23JSON),
			string(formats.CDX14JSON),
			string(formats.CDX15JSON),
			string(formats.CDX16JSON),
		},
	}, nil
}

// ---- helpers ----

func nodeToProto(n *sbom.Node) *pb.NodeInfo {
	ntype := "PACKAGE"
	if n.Type == sbom.Node_FILE {
		ntype = "FILE"
	}
	info := &pb.NodeInfo{
		Id:               n.Id,
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

// Ensure the reader's ParseStream receives an io.ReadSeeker.
var _ io.ReadSeeker = (*bytes.Reader)(nil)
var _ = strings.TrimSpace // keep strings import used by edge type handling

// ---- main ----

func main() {
	port := flag.Int("port", 50051, "gRPC listen port")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterProtobomServiceServer(grpcServer, newServer())

	// Enable server reflection so clients like grpcurl can introspect.
	reflection.Register(grpcServer)

	log.Printf("protobom gRPC server listening on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
