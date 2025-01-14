// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package alignchecker

import (
	"reflect"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the datapath match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		"ipv4_ct_tuple":        {reflect.TypeOf(ctmap.CtKey4{}), reflect.TypeOf(ctmap.CtKey4Global{})},
		"ipv6_ct_tuple":        {reflect.TypeOf(ctmap.CtKey6{}), reflect.TypeOf(ctmap.CtKey6Global{})},
		"ct_entry":             {reflect.TypeOf(ctmap.CtEntry{})},
		"ipcache_key":          {reflect.TypeOf(ipcachemap.Key{})},
		"remote_endpoint_info": {reflect.TypeOf(ipcachemap.RemoteEndpointInfo{})},
		"lb4_key":              {reflect.TypeOf(lbmap.Service4Key{})},
		"lb4_service":          {reflect.TypeOf(lbmap.Service4Value{})},
		"lb4_backend":          {reflect.TypeOf(lbmap.Backend4Value{})},
		"lb6_key":              {reflect.TypeOf(lbmap.Service6Key{})},
		"lb6_service":          {reflect.TypeOf(lbmap.Service6Value{})},
		"lb6_backend":          {reflect.TypeOf(lbmap.Backend6Value{})},
		"endpoint_info":        {reflect.TypeOf(lxcmap.EndpointInfo{})},
		"metrics_key":          {reflect.TypeOf(metricsmap.Key{})},
		"metrics_value":        {reflect.TypeOf(metricsmap.Value{})},
		"policy_key":           {reflect.TypeOf(policymap.PolicyKey{})},
		"policy_entry":         {reflect.TypeOf(policymap.PolicyEntry{})},
		"sock_key":             {reflect.TypeOf(sockmap.SockmapKey{})},
		"ipv4_revnat_tuple":    {reflect.TypeOf(lbmap.SockRevNat4Key{})},
		"ipv4_revnat_entry":    {reflect.TypeOf(lbmap.SockRevNat4Value{})},
		"ipv6_revnat_tuple":    {reflect.TypeOf(lbmap.SockRevNat6Key{})},
		"ipv6_revnat_entry":    {reflect.TypeOf(lbmap.SockRevNat6Value{})},
		"v6addr":               {reflect.TypeOf(neighborsmap.Key6{})},
		"macaddr":              {reflect.TypeOf(neighborsmap.Value{})},
		"ipv4_frag_id":         {reflect.TypeOf(fragmap.FragmentKey{})},
		"ipv4_frag_l4ports":    {reflect.TypeOf(fragmap.FragmentValue{})},
		"capture4_wcard":       {reflect.TypeOf(recorder.CaptureWcard4{})},
		"capture6_wcard":       {reflect.TypeOf(recorder.CaptureWcard6{})},
		"capture_rule":         {reflect.TypeOf(recorder.CaptureRule4{})},
		// TODO: alignchecker does not support nested structs yet.
		// "capture_rule":      {reflect.TypeOf(recorder.CaptureRule6{})},
		// "ipv4_nat_entry":    {reflect.TypeOf(nat.NatEntry4{})},
		// "ipv6_nat_entry":    {reflect.TypeOf(nat.NatEntry6{})},
		"endpoint_key": {
			reflect.TypeOf(bpf.EndpointKey{}),
			reflect.TypeOf(eppolicymap.EndpointKey{}),
			reflect.TypeOf(tunnel.TunnelEndpoint{}),
		},
		"lb4_affinity_key":  {reflect.TypeOf(lbmap.Affinity4Key{})},
		"lb6_affinity_key":  {reflect.TypeOf(lbmap.Affinity6Key{})},
		"lb_affinity_match": {reflect.TypeOf(lbmap.AffinityMatchKey{})},
		"lb_affinity_val":   {reflect.TypeOf(lbmap.AffinityValue{})},
		"lb4_src_range_key": {reflect.TypeOf(lbmap.SourceRangeKey4{})},
		"lb6_src_range_key": {reflect.TypeOf(lbmap.SourceRangeKey6{})},
		"edt_id":            {reflect.TypeOf(bwmap.EdtId{})},
		"edt_info":          {reflect.TypeOf(bwmap.EdtInfo{})},
	}
	if err := check.CheckStructAlignments(path, toCheck, true); err != nil {
		return err
	}
	toCheckSizes := map[string][]reflect.Type{
		"__u16": {
			reflect.TypeOf(lbmap.Backend4Key{}),
			reflect.TypeOf(lbmap.Backend6Key{}),
			reflect.TypeOf(lbmap.RevNat4Key{}),
			reflect.TypeOf(lbmap.RevNat6Key{}),
		},
		"__u32": {
			reflect.TypeOf(lbmap.Backend4KeyV2{}),
			reflect.TypeOf(lbmap.Backend6KeyV2{}),
			reflect.TypeOf(signalmap.Key{}),
			reflect.TypeOf(signalmap.Value{}),
			reflect.TypeOf(eventsmap.Key{}),
			reflect.TypeOf(eventsmap.Value{}),
			reflect.TypeOf(policymap.CallKey{}),
			reflect.TypeOf(policymap.CallValue{}),
		},
		"int": {
			reflect.TypeOf(sockmap.SockmapValue{}),
			reflect.TypeOf(eppolicymap.EPPolicyValue{}),
		},
		"__be32": {reflect.TypeOf(neighborsmap.Key4{})},
	}
	return check.CheckStructAlignments(path, toCheckSizes, false)
}
