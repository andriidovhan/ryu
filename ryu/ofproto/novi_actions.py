# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from ryu import utils
from ryu.lib import type_desc
from ryu.ofproto import ofproto_common


def generate(ofp_name, ofpp_name):
    import sys

    ofp = sys.modules[ofp_name]
    ofpp = sys.modules[ofpp_name]

    class NoviAction(ofpp.OFPActionExperimenter):
        _fmt_str = '>BBH'
        _subtypes = {}
        _experimenter = ofproto_common.NOVI_EXPERIMENTER_ID
        customer = 0xff
        reserved = 0x00

        def __init__(self):
            super(NoviAction, self).__init__(self._experimenter)
            self.subtype = self._subtype

        @classmethod
        def parse(cls, buf):
            fmt_str = NoviAction._fmt_str
            (customer, reserved, novi_action_type) = struct.unpack_from(fmt_str, buf, 0)
            subtype_cls = cls._subtypes.get(novi_action_type)
            rest = buf[struct.calcsize(fmt_str):]
            if subtype_cls is None:
                return NoviActionUnknown(novi_action_type, rest)
            return subtype_cls.parser(rest)

        def serialize(self, buf, offset):
            prefix_size = struct.calcsize(NoviAction._fmt_str)
            prefix_buf = bytearray(prefix_size)
            struct.pack_into(NoviAction._fmt_str, prefix_buf, 0, self.customer, self.reserved, self._subtype)

            prefix_buf += self.serialize_body()

            super(NoviAction, self).serialize(buf, offset)

            buf += prefix_buf

        @classmethod
        def register(cls, subtype_cls):
            assert subtype_cls._subtype is not cls._subtypes
            cls._subtypes[subtype_cls._subtype] = subtype_cls

    class NoviActionUnknown(NoviAction):
        def __init__(self, novi_action_type, data=None,
                     type_=None, len_=None, experimenter=None):
            self.novi_action_type = novi_action_type
            super(NoviActionUnknown, self).__init__()
            self.data = data

        @classmethod
        def parser(cls, buf):
            return cls(data=buf)

        def serialize_body(self):
            # fixup
            return bytearray() if self.data is None else self.data

    class NoviActionPopVxlan(NoviAction):
        _fmt_str = '>b3x'
        NOVI_ACTION_POP_TUNNEL = 0x0003
        NOVI_TUNNEL_TYPE_VXLAN = 0x00

        _subtype = NOVI_ACTION_POP_TUNNEL

        def __init__(self):
            super(NoviActionPopVxlan, self).__init__()
            self.len = 16


        def action_to_str(self):
            return "NOVI_POP_VXLAN"

        @classmethod
        def parser(cls, buf):
            tunnel_type = struct.unpack(cls._fmt_str, buf)
            assert len(tunnel_type) == 1
            assert tunnel_type[0] == cls.NOVI_TUNNEL_TYPE_VXLAN
            return cls()

        def serialize_body(self):
            sz = struct.calcsize(self._fmt_str)
            buf = bytearray(sz)
            try:
                struct.pack_into(self._fmt_str, buf, 0, self.NOVI_TUNNEL_TYPE_VXLAN)
            except Exception as e:
                print(e)
            return buf

    class NoviActionPushVxlanShort(NoviAction):
        _fmt_str = '>BB2x'
        NOVI_ACTION_PUSH_TUNNEL = 0x0002
        _subtype = NOVI_ACTION_PUSH_TUNNEL
        NOVI_TUNNEL_TYPE_VXLAN = 0x00

        def __init__(self):
            super(NoviActionPushVxlanShort, self).__init__()
            self.len = 16

        def action_to_str(self):
                return "NOVI_PUSH_VXLAN"

        @classmethod
        def parser(cls, buf):
            size = struct.calcsize(cls._fmt_str)
            tunnel_type, flag = struct.unpack(
                cls._fmt_str, buf[:size])
            assert tunnel_type == cls.NOVI_TUNNEL_TYPE_VXLAN
            if flag:
                return NoviActionPushVxlan.parser(buf)
            else:
                return cls()

        def serialize_body(self):
            sz = struct.calcsize(self._fmt_str)
            buf = bytearray(sz)
            try:
                struct.pack_into(self._fmt_str, buf, 0, self.NOVI_TUNNEL_TYPE_VXLAN, 0)
            except Exception as e:
                print(e)
            return buf

    class NoviActionPushVxlan(NoviActionPushVxlanShort):
        _fmt_str = '>BB6s6s4s4sHI'
        NOVI_ACTION_PUSH_TUNNEL = 0x0002
        _subtype = NOVI_ACTION_PUSH_TUNNEL
        NOVI_TUNNEL_TYPE_VXLAN = 0x00
        TUNNEL_DATA_PRESENT = 0x01

        def __init__(self, eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni):
            super(NoviActionPushVxlan, self).__init__()
            self.eth_src = eth_src
            self.eth_dst = eth_dst
            self.ipv4_src = ipv4_src
            self.ipv4_dst = ipv4_dst
            self.udp_src = udp_src
            self.vni = vni
            self.len = 40

        @classmethod
        def parser(cls, buf):
            tunnel_type, flag, eth_src_buff, eth_dst_buff, ipv4_src_buff, ipv4_dst_buff, udp_src, vni = struct.unpack(
                cls._fmt_str, buf)
            eth_src = type_desc.MacAddr.to_user(eth_src_buff)
            eth_dst = type_desc.MacAddr.to_user(eth_dst_buff)
            ipv4_src = type_desc.IPv4Addr.to_user(ipv4_src_buff)
            ipv4_dst = type_desc.IPv4Addr.to_user(ipv4_dst_buff)
            return cls(eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni)

        def action_to_str(self):
            return "NOVI_PUSH_VXLAN: {'eth_src': %s, 'eth_dst': %s, " \
                   "'ipv4_src': %s, 'ipv4_dst': %s, 'udp_src': %d, 'vni': %d}" % (self.eth_src, self.eth_dst,
                                                                                  self.ipv4_src, self.ipv4_dst,
                                                                                  self.udp_src, self.vni)

        def serialize_body(self):
            sz = struct.calcsize(self._fmt_str)
            buf = bytearray(sz)
            try:
                struct.pack_into(self._fmt_str, buf, 0, self.NOVI_TUNNEL_TYPE_VXLAN,
                                 self.TUNNEL_DATA_PRESENT, type_desc.MacAddr.from_user(self.eth_src),
                                 type_desc.MacAddr.from_user(self.eth_dst),
                                 type_desc.IPv4Addr.from_user(self.ipv4_src),
                                 type_desc.IPv4Addr.from_user(self.ipv4_dst), self.udp_src, self.vni)
            except Exception as e:
                print(e)
            return buf

    class NoviActionCopyField(NoviAction):
        _fmt_str_20 = '>HHH2x12s'
        _fmt_str_24 = '>HHH2x16s'
        _fmt_str_28 = '>HHH2x20s'
        NOVI_ACTION_COPY_FIELD = 0x0005
        _subtype = NOVI_ACTION_COPY_FIELD

        def __init__(self, n_bits, src_offset, dst_offset, src, dst):
            super(NoviActionCopyField, self).__init__()
            self.n_bits = n_bits
            self.src_offset = src_offset
            self.dst_offset = dst_offset
            self.src = src
            self.dst = dst

            self.len = 0 # 32/36/40 depends on the type of src and dst

        @classmethod
        def parser(cls, buf):
            try:
                if len(buf) == 20:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_20, buf)
                elif len(buf) == 24:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_24, buf)
                elif len(buf) == 28:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_28, buf)
                else:
                    raise Exception("Unknown buffer")
                (n, src_size) = ofp.oxm_parse_header(oxms, 0)
                src = ofp.oxm_to_user_header(n)
                oxms = oxms[src_size:]
                (n, dst_size) = ofp.oxm_parse_header(oxms, 0)
                dst = ofp.oxm_to_user_header(n)

                return cls(n_bits, src_offset, dst_offset, src, dst)
            except Exception as e:
                print(e)

        def action_to_str(self):
            return "NOVI_COPY_FIELD: {'n_bits': %d, 'src_offset': %d, " \
                   "'dst_offset': %d, 'src': %s, 'dst': %s}" % (self.n_bits, self.src_offset, self.dst_offset,
                                                                self.src, self.dst)

        def serialize_body(self):
            src_header = bytearray()
            dst_header = bytearray()
            n = ofp.oxm_from_user_header(self.src)
            ofp.oxm_serialize_header(n, src_header, 0)
            n = ofp.oxm_from_user_header(self.dst)
            ofp.oxm_serialize_header(n, dst_header, 0)
            src_header.extend(dst_header)
            if len(src_header) != 12:
                src_header.extend(bytearray(4))
            sz = struct.calcsize(self._fmt_str_28)
            buf = bytearray(sz)
            try:
                struct.pack_into(self._fmt_str_28, buf, 0, self.n_bits, self.src_offset, self.dst_offset, src_header)

            except Exception as e:
                print(e)
            self.len = 12 + len(buf)
            return buf

    class NoviActionSwapField(NoviAction):
        _fmt_str_20 = '>HHH2x12s'
        _fmt_str_24 = '>HHH2x16s'
        _fmt_str_28 = '>HHH2x20s'
        NOVI_ACTION_SWAP_FIELD = 0x0009
        _subtype = NOVI_ACTION_SWAP_FIELD

        def __init__(self, n_bits, src_offset, dst_offset, src, dst):
            super(NoviActionSwapField, self).__init__()
            self.n_bits = n_bits
            self.src_offset = src_offset
            self.dst_offset = dst_offset
            self.src = src
            self.dst = dst

            self.len = 0 # 32/36/40 depends on the type of src and dst

        @classmethod
        def parser(cls, buf):
            try:
                if len(buf) == 20:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_20, buf)
                elif len(buf) == 24:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_24, buf)
                elif len(buf) == 28:
                    n_bits, src_offset, dst_offset, oxms = struct.unpack(cls._fmt_str_28, buf)
                else:
                    raise Exception("Unknown buffer")
                (n, src_size) = ofp.oxm_parse_header(oxms, 0)
                src = ofp.oxm_to_user_header(n)
                oxms = oxms[src_size:]
                (n, dst_size) = ofp.oxm_parse_header(oxms, 0)
                dst = ofp.oxm_to_user_header(n)

                return cls(n_bits, src_offset, dst_offset, src, dst)
            except Exception as e:
                print(e)

        def action_to_str(self):
            return "NOVI_SWAP_FIELD: {'n_bits': %d, 'src_offset': %d, " \
                   "'dst_offset': %d, 'src': %s, 'dst': %s}" % (self.n_bits, self.src_offset, self.dst_offset,
                                                                self.src, self.dst)

        def serialize_body(self):
            src_header = bytearray()
            dst_header = bytearray()
            n = ofp.oxm_from_user_header(self.src)
            ofp.oxm_serialize_header(n, src_header, 0)
            n = ofp.oxm_from_user_header(self.dst)
            ofp.oxm_serialize_header(n, dst_header, 0)
            src_header.extend(dst_header)
            if len(src_header) != 12:
                src_header.extend(bytearray(4))
            sz = struct.calcsize(self._fmt_str_28)
            buf = bytearray(sz)
            try:
                struct.pack_into(self._fmt_str_28, buf, 0, self.n_bits, self.src_offset, self.dst_offset, src_header)

            except Exception as e:
                print(e)
            self.len = 12 + len(buf)
            return buf

    class NoviActionHashFieldSym(NoviAction):
        _fmt_str = '>B'
        NOVI_ACTION_HASH_FIELDS_SYM = 0x0007
        _subtype = NOVI_ACTION_HASH_FIELDS_SYM

        def __init__(self, field_num, fields):
            super(NoviActionHashFieldSym, self).__init__()
            self.field_num = field_num
            self.fields = fields
            self.len = 0 # 32/36/40 depends on the type of src and dst

        @classmethod
        def parser(cls, buf):
            oxms = len(buf) - 1
            fmt = cls._fmt_str + str(oxms) + 's'

            try:
                field_num, oxm_buf = struct.unpack(fmt, buf)
                fields = []
                for i in range(field_num):
                    (n, offset) = ofp.oxm_parse_header(oxm_buf, 0)
                    fields.append(ofp.oxm_to_user_header(n))
                    oxm_buf = oxm_buf[offset:]
                return cls(field_num, fields)
            except Exception as e:
                print(e)

        def action_to_str(self):
            fields = ''
            if self.fields:
                fields = ','.join(["'%s'" % x for x in self.fields])
            return "NOVI_HASH_FIELD_SYM: {'field_num': %d, 'fields': [%s]}" % (self.field_num, fields)

        def serialize_body(self):
            oxm_buffer = bytearray()
            for field in self.fields:
                field_buf = bytearray()
                n = ofp.oxm_from_user_header(field)
                ofp.oxm_serialize_header(n, field_buf, 0)
                oxm_buffer.extend(field_buf)
            prefix_len = 13  # type, len, experimenter, customer, reserved, novi_action_type, fields_num,
            oxm_len = len(oxm_buffer)
            pad_len = utils.round_up(prefix_len + oxm_len, 8) - prefix_len - oxm_len
            self.len = prefix_len + oxm_len + pad_len

            buf = bytearray(1 + oxm_len + pad_len)  # 1 for fields_num
            fmt = self._fmt_str + str(oxm_len) + 's' + str(pad_len) + 'x'
            try:
                struct.pack_into(fmt, buf, 0, self.field_num, oxm_buffer)
            except Exception as e:
                print(e)
            return buf

    def add_attr(k, v):
        v.__module__ = ofpp.__name__  # Necessary for stringify stuff
        setattr(ofpp, k, v)

    add_attr('NoviAction', NoviAction)
    add_attr('NoviUnknown', NoviActionUnknown)

    classes = [
        ('NoviActionPushVxlanShort', True),
        ('NoviActionPopVxlan', True),
        ('NoviActionPushVxlan', False),
        ('NoviActionCopyField', True),
        ('NoviActionSwapField', True),
        ('NoviActionHashFieldSym', True)
    ]
    vars = locals()
    for name, register in classes:
        cls = vars[name]
        add_attr(name, cls)
        if register:
            NoviAction.register(cls)
