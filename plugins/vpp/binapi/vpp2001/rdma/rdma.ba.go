// Code generated by GoVPP's binapi-generator. DO NOT EDIT.
// source: /usr/share/vpp/api/plugins/rdma.api.json

/*
Package rdma is a generated VPP binary API for 'rdma' module.

It consists of:
	  7 enums
	  1 alias
	  4 messages
	  2 services
*/
package rdma

import (
	"bytes"
	"context"
	"io"
	"strconv"

	api "git.fd.io/govpp.git/api"
	struc "github.com/lunixbochs/struc"

	interface_types "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2001/interface_types"
)

const (
	// ModuleName is the name of this module.
	ModuleName = "rdma"
	// VersionCrc is the CRC of this module.
	VersionCrc = 0x5ce233e0
)

type IfStatusFlags = interface_types.IfStatusFlags

type IfType = interface_types.IfType

type LinkDuplex = interface_types.LinkDuplex

type MtuProto = interface_types.MtuProto

// RdmaMode represents VPP binary API enum 'rdma_mode'.
type RdmaMode uint32

const (
	RDMA_API_MODE_AUTO RdmaMode = 0
	RDMA_API_MODE_IBV  RdmaMode = 1
	RDMA_API_MODE_DV   RdmaMode = 2
)

var RdmaMode_name = map[uint32]string{
	0: "RDMA_API_MODE_AUTO",
	1: "RDMA_API_MODE_IBV",
	2: "RDMA_API_MODE_DV",
}

var RdmaMode_value = map[string]uint32{
	"RDMA_API_MODE_AUTO": 0,
	"RDMA_API_MODE_IBV":  1,
	"RDMA_API_MODE_DV":   2,
}

func (x RdmaMode) String() string {
	s, ok := RdmaMode_name[uint32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}

type RxMode = interface_types.RxMode

type SubIfFlags = interface_types.SubIfFlags

type InterfaceIndex = interface_types.InterfaceIndex

// RdmaCreate represents VPP binary API message 'rdma_create'.
type RdmaCreate struct {
	HostIf  string `struc:"[64]byte"`
	Name    string `struc:"[64]byte"`
	RxqNum  uint16
	RxqSize uint16
	TxqSize uint16
	Mode    RdmaMode
}

func (m *RdmaCreate) Reset()                        { *m = RdmaCreate{} }
func (*RdmaCreate) GetMessageName() string          { return "rdma_create" }
func (*RdmaCreate) GetCrcString() string            { return "076fe418" }
func (*RdmaCreate) GetMessageType() api.MessageType { return api.RequestMessage }

// RdmaCreateReply represents VPP binary API message 'rdma_create_reply'.
type RdmaCreateReply struct {
	Retval    int32
	SwIfIndex InterfaceIndex
}

func (m *RdmaCreateReply) Reset()                        { *m = RdmaCreateReply{} }
func (*RdmaCreateReply) GetMessageName() string          { return "rdma_create_reply" }
func (*RdmaCreateReply) GetCrcString() string            { return "5383d31f" }
func (*RdmaCreateReply) GetMessageType() api.MessageType { return api.ReplyMessage }

// RdmaDelete represents VPP binary API message 'rdma_delete'.
type RdmaDelete struct {
	SwIfIndex InterfaceIndex
}

func (m *RdmaDelete) Reset()                        { *m = RdmaDelete{} }
func (*RdmaDelete) GetMessageName() string          { return "rdma_delete" }
func (*RdmaDelete) GetCrcString() string            { return "f9e6675e" }
func (*RdmaDelete) GetMessageType() api.MessageType { return api.RequestMessage }

// RdmaDeleteReply represents VPP binary API message 'rdma_delete_reply'.
type RdmaDeleteReply struct {
	Retval int32
}

func (m *RdmaDeleteReply) Reset()                        { *m = RdmaDeleteReply{} }
func (*RdmaDeleteReply) GetMessageName() string          { return "rdma_delete_reply" }
func (*RdmaDeleteReply) GetCrcString() string            { return "e8d4e804" }
func (*RdmaDeleteReply) GetMessageType() api.MessageType { return api.ReplyMessage }

func init() {
	api.RegisterMessage((*RdmaCreate)(nil), "rdma.RdmaCreate")
	api.RegisterMessage((*RdmaCreateReply)(nil), "rdma.RdmaCreateReply")
	api.RegisterMessage((*RdmaDelete)(nil), "rdma.RdmaDelete")
	api.RegisterMessage((*RdmaDeleteReply)(nil), "rdma.RdmaDeleteReply")
}

// Messages returns list of all messages in this module.
func AllMessages() []api.Message {
	return []api.Message{
		(*RdmaCreate)(nil),
		(*RdmaCreateReply)(nil),
		(*RdmaDelete)(nil),
		(*RdmaDeleteReply)(nil),
	}
}

// RPCService represents RPC service API for rdma module.
type RPCService interface {
	RdmaCreate(ctx context.Context, in *RdmaCreate) (*RdmaCreateReply, error)
	RdmaDelete(ctx context.Context, in *RdmaDelete) (*RdmaDeleteReply, error)
}

type serviceClient struct {
	ch api.Channel
}

func NewServiceClient(ch api.Channel) RPCService {
	return &serviceClient{ch}
}

func (c *serviceClient) RdmaCreate(ctx context.Context, in *RdmaCreate) (*RdmaCreateReply, error) {
	out := new(RdmaCreateReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serviceClient) RdmaDelete(ctx context.Context, in *RdmaDelete) (*RdmaDeleteReply, error) {
	out := new(RdmaDeleteReply)
	err := c.ch.SendRequest(in).ReceiveReply(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// This is a compile-time assertion to ensure that this generated file
// is compatible with the GoVPP api package it is being compiled against.
// A compilation error at this line likely means your copy of the
// GoVPP api package needs to be updated.
const _ = api.GoVppAPIPackageIsVersion1 // please upgrade the GoVPP api package

// Reference imports to suppress errors if they are not otherwise used.
var _ = api.RegisterMessage
var _ = bytes.NewBuffer
var _ = context.Background
var _ = io.Copy
var _ = strconv.Itoa
var _ = struc.Pack