# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011, 2012 Isaku Yamahata <yamahata at valinux co jp>
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

# Nicira extensions
# Many of these definitions are common among OpenFlow versions.

from ryu.lib import type_desc
from ryu.ofproto import oxm_fields


oxm_types = [
    oxm_fields.NoviExperimenter('novi_hash_result', 4, type_desc.Int1),
    oxm_fields.NoviExperimenter('novi_rx_timestamp', 6, type_desc.Int1),
    oxm_fields.NoviExperimenter('novi_tx_timestamp', 7, type_desc.Int1),
    oxm_fields.NoviExperimenter('novi_packet_offset', 8, type_desc.Int1)
]
