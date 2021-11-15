// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: ligato/vpp/bfd/bfd.proto

package vpp_bfd

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type SingleHopBFD_Key_AuthenticationType int32

const (
	SingleHopBFD_Key_KEYED_SHA1            SingleHopBFD_Key_AuthenticationType = 0
	SingleHopBFD_Key_METICULOUS_KEYED_SHA1 SingleHopBFD_Key_AuthenticationType = 1
)

// Enum value maps for SingleHopBFD_Key_AuthenticationType.
var (
	SingleHopBFD_Key_AuthenticationType_name = map[int32]string{
		0: "KEYED_SHA1",
		1: "METICULOUS_KEYED_SHA1",
	}
	SingleHopBFD_Key_AuthenticationType_value = map[string]int32{
		"KEYED_SHA1":            0,
		"METICULOUS_KEYED_SHA1": 1,
	}
)

func (x SingleHopBFD_Key_AuthenticationType) Enum() *SingleHopBFD_Key_AuthenticationType {
	p := new(SingleHopBFD_Key_AuthenticationType)
	*p = x
	return p
}

func (x SingleHopBFD_Key_AuthenticationType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SingleHopBFD_Key_AuthenticationType) Descriptor() protoreflect.EnumDescriptor {
	return file_ligato_vpp_bfd_bfd_proto_enumTypes[0].Descriptor()
}

func (SingleHopBFD_Key_AuthenticationType) Type() protoreflect.EnumType {
	return &file_ligato_vpp_bfd_bfd_proto_enumTypes[0]
}

func (x SingleHopBFD_Key_AuthenticationType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SingleHopBFD_Key_AuthenticationType.Descriptor instead.
func (SingleHopBFD_Key_AuthenticationType) EnumDescriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0, 1, 0}
}

type SessionDetails_BfdState int32

const (
	SessionDetails_BFD_STATE_API_ADMIN_DOWN SessionDetails_BfdState = 0
	SessionDetails_BFD_STATE_API_DOWN       SessionDetails_BfdState = 1
	SessionDetails_BFD_STATE_API_INIT       SessionDetails_BfdState = 2
	SessionDetails_BFD_STATE_API_UP         SessionDetails_BfdState = 3
)

// Enum value maps for SessionDetails_BfdState.
var (
	SessionDetails_BfdState_name = map[int32]string{
		0: "BFD_STATE_API_ADMIN_DOWN",
		1: "BFD_STATE_API_DOWN",
		2: "BFD_STATE_API_INIT",
		3: "BFD_STATE_API_UP",
	}
	SessionDetails_BfdState_value = map[string]int32{
		"BFD_STATE_API_ADMIN_DOWN": 0,
		"BFD_STATE_API_DOWN":       1,
		"BFD_STATE_API_INIT":       2,
		"BFD_STATE_API_UP":         3,
	}
)

func (x SessionDetails_BfdState) Enum() *SessionDetails_BfdState {
	p := new(SessionDetails_BfdState)
	*p = x
	return p
}

func (x SessionDetails_BfdState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SessionDetails_BfdState) Descriptor() protoreflect.EnumDescriptor {
	return file_ligato_vpp_bfd_bfd_proto_enumTypes[1].Descriptor()
}

func (SessionDetails_BfdState) Type() protoreflect.EnumType {
	return &file_ligato_vpp_bfd_bfd_proto_enumTypes[1]
}

func (x SessionDetails_BfdState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SessionDetails_BfdState.Descriptor instead.
func (SessionDetails_BfdState) EnumDescriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{1, 0}
}

type SingleHopBFD struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Session      *SingleHopBFD_Session      `protobuf:"bytes,1,opt,name=session,proto3" json:"session,omitempty"`                               //  BFD session
	Key          *SingleHopBFD_Key          `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`                                       // authentication key
	EchoFunction *SingleHopBFD_EchoFunction `protobuf:"bytes,3,opt,name=echo_function,json=echoFunction,proto3" json:"echo_function,omitempty"` // BFD echo function (optional, disabled if empty)
}

func (x *SingleHopBFD) Reset() {
	*x = SingleHopBFD{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SingleHopBFD) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SingleHopBFD) ProtoMessage() {}

func (x *SingleHopBFD) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SingleHopBFD.ProtoReflect.Descriptor instead.
func (*SingleHopBFD) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0}
}

func (x *SingleHopBFD) GetSession() *SingleHopBFD_Session {
	if x != nil {
		return x.Session
	}
	return nil
}

func (x *SingleHopBFD) GetKey() *SingleHopBFD_Key {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *SingleHopBFD) GetEchoFunction() *SingleHopBFD_EchoFunction {
	if x != nil {
		return x.EchoFunction
	}
	return nil
}

type SessionDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Interface          string                  `protobuf:"bytes,1,opt,name=interface,proto3" json:"interface,omitempty"`
	DestinationAddress string                  `protobuf:"bytes,2,opt,name=destination_address,json=destinationAddress,proto3" json:"destination_address,omitempty"`
	SourceAddress      string                  `protobuf:"bytes,3,opt,name=source_address,json=sourceAddress,proto3" json:"source_address,omitempty"`
	State              SessionDetails_BfdState `protobuf:"varint,4,opt,name=state,proto3,enum=ligato.vpp.bfd.SessionDetails_BfdState" json:"state,omitempty"`
}

func (x *SessionDetails) Reset() {
	*x = SessionDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionDetails) ProtoMessage() {}

func (x *SessionDetails) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionDetails.ProtoReflect.Descriptor instead.
func (*SessionDetails) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{1}
}

func (x *SessionDetails) GetInterface() string {
	if x != nil {
		return x.Interface
	}
	return ""
}

func (x *SessionDetails) GetDestinationAddress() string {
	if x != nil {
		return x.DestinationAddress
	}
	return ""
}

func (x *SessionDetails) GetSourceAddress() string {
	if x != nil {
		return x.SourceAddress
	}
	return ""
}

func (x *SessionDetails) GetState() SessionDetails_BfdState {
	if x != nil {
		return x.State
	}
	return SessionDetails_BFD_STATE_API_ADMIN_DOWN
}

type SingleHopBFD_Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Interface             string                               `protobuf:"bytes,3,opt,name=interface,proto3" json:"interface,omitempty"`                                                           // interface to which this session is tied to
	DestinationAddress    string                               `protobuf:"bytes,4,opt,name=destination_address,json=destinationAddress,proto3" json:"destination_address,omitempty"`               // peer IP address
	SourceAddress         string                               `protobuf:"bytes,5,opt,name=source_address,json=sourceAddress,proto3" json:"source_address,omitempty"`                              // local IP address
	Enabled               bool                                 `protobuf:"varint,7,opt,name=enabled,proto3" json:"enabled,omitempty"`                                                              // controls whether this BFD session is administratively enabled or disabled
	DesiredMinTxInterval  uint32                               `protobuf:"varint,8,opt,name=desired_min_tx_interval,json=desiredMinTxInterval,proto3" json:"desired_min_tx_interval,omitempty"`    // desired min transmit interval (microseconds)
	RequiredMinRxInterval uint32                               `protobuf:"varint,9,opt,name=required_min_rx_interval,json=requiredMinRxInterval,proto3" json:"required_min_rx_interval,omitempty"` // required min receive interval (microseconds)
	DetectMultiplier      uint32                               `protobuf:"varint,10,opt,name=detect_multiplier,json=detectMultiplier,proto3" json:"detect_multiplier,omitempty"`                   // detect multiplier (# of packets missed before connection goes down) - must be non-zero
	Authentication        *SingleHopBFD_Session_Authentication `protobuf:"bytes,11,opt,name=authentication,proto3" json:"authentication,omitempty"`                                                // authentication of the session (if empty, authentication is disabled)
}

func (x *SingleHopBFD_Session) Reset() {
	*x = SingleHopBFD_Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SingleHopBFD_Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SingleHopBFD_Session) ProtoMessage() {}

func (x *SingleHopBFD_Session) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SingleHopBFD_Session.ProtoReflect.Descriptor instead.
func (*SingleHopBFD_Session) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0, 0}
}

func (x *SingleHopBFD_Session) GetInterface() string {
	if x != nil {
		return x.Interface
	}
	return ""
}

func (x *SingleHopBFD_Session) GetDestinationAddress() string {
	if x != nil {
		return x.DestinationAddress
	}
	return ""
}

func (x *SingleHopBFD_Session) GetSourceAddress() string {
	if x != nil {
		return x.SourceAddress
	}
	return ""
}

func (x *SingleHopBFD_Session) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *SingleHopBFD_Session) GetDesiredMinTxInterval() uint32 {
	if x != nil {
		return x.DesiredMinTxInterval
	}
	return 0
}

func (x *SingleHopBFD_Session) GetRequiredMinRxInterval() uint32 {
	if x != nil {
		return x.RequiredMinRxInterval
	}
	return 0
}

func (x *SingleHopBFD_Session) GetDetectMultiplier() uint32 {
	if x != nil {
		return x.DetectMultiplier
	}
	return 0
}

func (x *SingleHopBFD_Session) GetAuthentication() *SingleHopBFD_Session_Authentication {
	if x != nil {
		return x.Authentication
	}
	return nil
}

type SingleHopBFD_Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name               string                              `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`                                                                                                                // Unique name to identify this BFD auth key
	AuthKeyIndex       uint32                              `protobuf:"varint,2,opt,name=auth_key_index,json=authKeyIndex,proto3" json:"auth_key_index,omitempty"`                                                                         // BFD auth key index
	Id                 uint32                              `protobuf:"varint,3,opt,name=id,proto3" json:"id,omitempty"`                                                                                                                   // local key ID, used to uniquely identify this key
	AuthenticationType SingleHopBFD_Key_AuthenticationType `protobuf:"varint,4,opt,name=authentication_type,json=authenticationType,proto3,enum=ligato.vpp.bfd.SingleHopBFD_Key_AuthenticationType" json:"authentication_type,omitempty"` // authentication type
	Secret             string                              `protobuf:"bytes,5,opt,name=secret,proto3" json:"secret,omitempty"`                                                                                                            // shared secret (hex data)
}

func (x *SingleHopBFD_Key) Reset() {
	*x = SingleHopBFD_Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SingleHopBFD_Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SingleHopBFD_Key) ProtoMessage() {}

func (x *SingleHopBFD_Key) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SingleHopBFD_Key.ProtoReflect.Descriptor instead.
func (*SingleHopBFD_Key) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0, 1}
}

func (x *SingleHopBFD_Key) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SingleHopBFD_Key) GetAuthKeyIndex() uint32 {
	if x != nil {
		return x.AuthKeyIndex
	}
	return 0
}

func (x *SingleHopBFD_Key) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *SingleHopBFD_Key) GetAuthenticationType() SingleHopBFD_Key_AuthenticationType {
	if x != nil {
		return x.AuthenticationType
	}
	return SingleHopBFD_Key_KEYED_SHA1
}

func (x *SingleHopBFD_Key) GetSecret() string {
	if x != nil {
		return x.Secret
	}
	return ""
}

type SingleHopBFD_EchoFunction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name                string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	EchoSourceInterface string `protobuf:"bytes,2,opt,name=echo_source_interface,json=echoSourceInterface,proto3" json:"echo_source_interface,omitempty"` // name of the loopback interface that the echo source address will be derived from
}

func (x *SingleHopBFD_EchoFunction) Reset() {
	*x = SingleHopBFD_EchoFunction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SingleHopBFD_EchoFunction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SingleHopBFD_EchoFunction) ProtoMessage() {}

func (x *SingleHopBFD_EchoFunction) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SingleHopBFD_EchoFunction.ProtoReflect.Descriptor instead.
func (*SingleHopBFD_EchoFunction) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0, 2}
}

func (x *SingleHopBFD_EchoFunction) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SingleHopBFD_EchoFunction) GetEchoSourceInterface() string {
	if x != nil {
		return x.EchoSourceInterface
	}
	return ""
}

type SingleHopBFD_Session_Authentication struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId           uint32 `protobuf:"varint,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`                                 // local key ID for this session (ID of the key used for authentication
	AdvertisedKeyId uint32 `protobuf:"varint,2,opt,name=advertised_key_id,json=advertisedKeyId,proto3" json:"advertised_key_id,omitempty"` // BFD key ID, as carried in BFD control frames (does not refer to a local key ID)
}

func (x *SingleHopBFD_Session_Authentication) Reset() {
	*x = SingleHopBFD_Session_Authentication{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SingleHopBFD_Session_Authentication) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SingleHopBFD_Session_Authentication) ProtoMessage() {}

func (x *SingleHopBFD_Session_Authentication) ProtoReflect() protoreflect.Message {
	mi := &file_ligato_vpp_bfd_bfd_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SingleHopBFD_Session_Authentication.ProtoReflect.Descriptor instead.
func (*SingleHopBFD_Session_Authentication) Descriptor() ([]byte, []int) {
	return file_ligato_vpp_bfd_bfd_proto_rawDescGZIP(), []int{0, 0, 0}
}

func (x *SingleHopBFD_Session_Authentication) GetKeyId() uint32 {
	if x != nil {
		return x.KeyId
	}
	return 0
}

func (x *SingleHopBFD_Session_Authentication) GetAdvertisedKeyId() uint32 {
	if x != nil {
		return x.AdvertisedKeyId
	}
	return 0
}

var File_ligato_vpp_bfd_bfd_proto protoreflect.FileDescriptor

var file_ligato_vpp_bfd_bfd_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2f, 0x62, 0x66, 0x64,
	0x2f, 0x62, 0x66, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x6c, 0x69, 0x67, 0x61,
	0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x22, 0xa6, 0x08, 0x0a, 0x0c, 0x53,
	0x69, 0x6e, 0x67, 0x6c, 0x65, 0x48, 0x6f, 0x70, 0x42, 0x46, 0x44, 0x12, 0x3e, 0x0a, 0x07, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x6c,
	0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x53, 0x69,
	0x6e, 0x67, 0x6c, 0x65, 0x48, 0x6f, 0x70, 0x42, 0x46, 0x44, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x52, 0x07, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x32, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6c, 0x69, 0x67, 0x61, 0x74,
	0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65,
	0x48, 0x6f, 0x70, 0x42, 0x46, 0x44, 0x2e, 0x4b, 0x65, 0x79, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x4e, 0x0a, 0x0d, 0x65, 0x63, 0x68, 0x6f, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e,
	0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x48, 0x6f,
	0x70, 0x42, 0x46, 0x44, 0x2e, 0x45, 0x63, 0x68, 0x6f, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x0c, 0x65, 0x63, 0x68, 0x6f, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x1a,
	0xe8, 0x03, 0x0a, 0x07, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x2f, 0x0a, 0x13, 0x64, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x35, 0x0a, 0x17, 0x64,
	0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x5f, 0x6d, 0x69, 0x6e, 0x5f, 0x74, 0x78, 0x5f, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x14, 0x64, 0x65,
	0x73, 0x69, 0x72, 0x65, 0x64, 0x4d, 0x69, 0x6e, 0x54, 0x78, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x12, 0x37, 0x0a, 0x18, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x5f, 0x6d,
	0x69, 0x6e, 0x5f, 0x72, 0x78, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x15, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x4d, 0x69,
	0x6e, 0x52, 0x78, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x12, 0x2b, 0x0a, 0x11, 0x64,
	0x65, 0x74, 0x65, 0x63, 0x74, 0x5f, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c, 0x69, 0x65, 0x72,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x4d, 0x75,
	0x6c, 0x74, 0x69, 0x70, 0x6c, 0x69, 0x65, 0x72, 0x12, 0x5b, 0x0a, 0x0e, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x33, 0x2e, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66,
	0x64, 0x2e, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x48, 0x6f, 0x70, 0x42, 0x46, 0x44, 0x2e, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x53, 0x0a, 0x0e, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x2a,
	0x0a, 0x11, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x61, 0x64, 0x76, 0x65, 0x72,
	0x74, 0x69, 0x73, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x1a, 0x8e, 0x02, 0x0a, 0x03, 0x4b,
	0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x24, 0x0a, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c,
	0x61, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x64, 0x0a, 0x13,
	0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x33, 0x2e, 0x6c, 0x69, 0x67, 0x61,
	0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x53, 0x69, 0x6e, 0x67, 0x6c,
	0x65, 0x48, 0x6f, 0x70, 0x42, 0x46, 0x44, 0x2e, 0x4b, 0x65, 0x79, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x12,
	0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x22, 0x3f, 0x0a, 0x12, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x0e, 0x0a, 0x0a, 0x4b, 0x45, 0x59, 0x45, 0x44, 0x5f, 0x53, 0x48, 0x41, 0x31, 0x10, 0x00,
	0x12, 0x19, 0x0a, 0x15, 0x4d, 0x45, 0x54, 0x49, 0x43, 0x55, 0x4c, 0x4f, 0x55, 0x53, 0x5f, 0x4b,
	0x45, 0x59, 0x45, 0x44, 0x5f, 0x53, 0x48, 0x41, 0x31, 0x10, 0x01, 0x1a, 0x56, 0x0a, 0x0c, 0x45,
	0x63, 0x68, 0x6f, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x32, 0x0a, 0x15, 0x65, 0x63, 0x68, 0x6f, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13,
	0x65, 0x63, 0x68, 0x6f, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66,
	0x61, 0x63, 0x65, 0x22, 0xb5, 0x02, 0x0a, 0x0e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x44,
	0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66,
	0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x66, 0x61, 0x63, 0x65, 0x12, 0x2f, 0x0a, 0x13, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x12, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x3d, 0x0a, 0x05,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x27, 0x2e, 0x6c, 0x69,
	0x67, 0x61, 0x74, 0x6f, 0x2e, 0x76, 0x70, 0x70, 0x2e, 0x62, 0x66, 0x64, 0x2e, 0x53, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x2e, 0x42, 0x66, 0x64, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x22, 0x6e, 0x0a, 0x08, 0x42,
	0x66, 0x64, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1c, 0x0a, 0x18, 0x42, 0x46, 0x44, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x5f, 0x41, 0x44, 0x4d, 0x49, 0x4e, 0x5f, 0x44,
	0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x42, 0x46, 0x44, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x5f, 0x44, 0x4f, 0x57, 0x4e, 0x10, 0x01, 0x12, 0x16, 0x0a,
	0x12, 0x42, 0x46, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x5f, 0x49,
	0x4e, 0x49, 0x54, 0x10, 0x02, 0x12, 0x14, 0x0a, 0x10, 0x42, 0x46, 0x44, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x5f, 0x55, 0x50, 0x10, 0x03, 0x42, 0x38, 0x5a, 0x36, 0x67,
	0x6f, 0x2e, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x6f, 0x2e, 0x69, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2d,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6c,
	0x69, 0x67, 0x61, 0x74, 0x6f, 0x2f, 0x76, 0x70, 0x70, 0x2f, 0x62, 0x66, 0x64, 0x3b, 0x76, 0x70,
	0x70, 0x5f, 0x62, 0x66, 0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ligato_vpp_bfd_bfd_proto_rawDescOnce sync.Once
	file_ligato_vpp_bfd_bfd_proto_rawDescData = file_ligato_vpp_bfd_bfd_proto_rawDesc
)

func file_ligato_vpp_bfd_bfd_proto_rawDescGZIP() []byte {
	file_ligato_vpp_bfd_bfd_proto_rawDescOnce.Do(func() {
		file_ligato_vpp_bfd_bfd_proto_rawDescData = protoimpl.X.CompressGZIP(file_ligato_vpp_bfd_bfd_proto_rawDescData)
	})
	return file_ligato_vpp_bfd_bfd_proto_rawDescData
}

var file_ligato_vpp_bfd_bfd_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_ligato_vpp_bfd_bfd_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_ligato_vpp_bfd_bfd_proto_goTypes = []interface{}{
	(SingleHopBFD_Key_AuthenticationType)(0),    // 0: ligato.vpp.bfd.SingleHopBFD.Key.AuthenticationType
	(SessionDetails_BfdState)(0),                // 1: ligato.vpp.bfd.SessionDetails.BfdState
	(*SingleHopBFD)(nil),                        // 2: ligato.vpp.bfd.SingleHopBFD
	(*SessionDetails)(nil),                      // 3: ligato.vpp.bfd.SessionDetails
	(*SingleHopBFD_Session)(nil),                // 4: ligato.vpp.bfd.SingleHopBFD.Session
	(*SingleHopBFD_Key)(nil),                    // 5: ligato.vpp.bfd.SingleHopBFD.Key
	(*SingleHopBFD_EchoFunction)(nil),           // 6: ligato.vpp.bfd.SingleHopBFD.EchoFunction
	(*SingleHopBFD_Session_Authentication)(nil), // 7: ligato.vpp.bfd.SingleHopBFD.Session.Authentication
}
var file_ligato_vpp_bfd_bfd_proto_depIdxs = []int32{
	4, // 0: ligato.vpp.bfd.SingleHopBFD.session:type_name -> ligato.vpp.bfd.SingleHopBFD.Session
	5, // 1: ligato.vpp.bfd.SingleHopBFD.key:type_name -> ligato.vpp.bfd.SingleHopBFD.Key
	6, // 2: ligato.vpp.bfd.SingleHopBFD.echo_function:type_name -> ligato.vpp.bfd.SingleHopBFD.EchoFunction
	1, // 3: ligato.vpp.bfd.SessionDetails.state:type_name -> ligato.vpp.bfd.SessionDetails.BfdState
	7, // 4: ligato.vpp.bfd.SingleHopBFD.Session.authentication:type_name -> ligato.vpp.bfd.SingleHopBFD.Session.Authentication
	0, // 5: ligato.vpp.bfd.SingleHopBFD.Key.authentication_type:type_name -> ligato.vpp.bfd.SingleHopBFD.Key.AuthenticationType
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_ligato_vpp_bfd_bfd_proto_init() }
func file_ligato_vpp_bfd_bfd_proto_init() {
	if File_ligato_vpp_bfd_bfd_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ligato_vpp_bfd_bfd_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SingleHopBFD); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ligato_vpp_bfd_bfd_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionDetails); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ligato_vpp_bfd_bfd_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SingleHopBFD_Session); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ligato_vpp_bfd_bfd_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SingleHopBFD_Key); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ligato_vpp_bfd_bfd_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SingleHopBFD_EchoFunction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ligato_vpp_bfd_bfd_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SingleHopBFD_Session_Authentication); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ligato_vpp_bfd_bfd_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ligato_vpp_bfd_bfd_proto_goTypes,
		DependencyIndexes: file_ligato_vpp_bfd_bfd_proto_depIdxs,
		EnumInfos:         file_ligato_vpp_bfd_bfd_proto_enumTypes,
		MessageInfos:      file_ligato_vpp_bfd_bfd_proto_msgTypes,
	}.Build()
	File_ligato_vpp_bfd_bfd_proto = out.File
	file_ligato_vpp_bfd_bfd_proto_rawDesc = nil
	file_ligato_vpp_bfd_bfd_proto_goTypes = nil
	file_ligato_vpp_bfd_bfd_proto_depIdxs = nil
}
