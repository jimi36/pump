/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pump/proto/quic/config.h"
#include "pump/proto/quic/defaults.h"

namespace pump {
namespace proto {
namespace quic {

    void init_config(config *cfg) {
        cfg->versions.push_back(version_tls);

        cfg->connection_id_length = DEF_CONNECTION_ID_LEN;
 
        cfg->handshake_idle_timeout = DEF_HANDSHAKE_IDLE_TIMEOUT;

        cfg->max_idle_timeout = DEF_IDLE_TIMEOUT;
 
        cfg->initial_stream_receive_window = DEF_STREAM_RECEIVE_WINDOW_SIZE;
        cfg->max_stream_receive_window = DEF_MAX_STREAM_RECEIVE_WINDOW_SIZE;

        cfg->initial_connection_receive_window = DEF_CONNECTION_RECEIVE_WINDOW_SIZE;
        cfg->max_connection_receive_window = DEF_MAX_CONNECTION_RECEIVE_WINDOW_SIZE;

        cfg->max_incoming_streams = DEF_MAX_INCOMING_STREAM_COUNT;
        cfg->max_incoming_uni_streams = DEF_MAX_INCOMING_NUI_STREAM_COUNT;

        cfg->keepalive = false;

        cfg->disable_path_mtu_discovery = false;

        cfg->disable_version_negotiation_packets = false;

        cfg->enable_datagrams = false;
    }

    void populate_config(config *cfg) {
        if (cfg->versions.empty()) {
            cfg->versions.push_back(version_tls);
        }
        if (cfg->connection_id_length <= 0) {
            cfg->connection_id_length = DEF_CONNECTION_ID_LEN;
        }
        if (cfg->handshake_idle_timeout <= 0) {
            cfg->handshake_idle_timeout = DEF_HANDSHAKE_IDLE_TIMEOUT;
        }
        if (cfg->max_idle_timeout <= 0) {
            cfg->max_idle_timeout = DEF_IDLE_TIMEOUT;
        }
        if (cfg->initial_stream_receive_window <= 0) {
            cfg->initial_stream_receive_window = DEF_STREAM_RECEIVE_WINDOW_SIZE;
        }
        if (cfg->max_stream_receive_window <= 0) {
            cfg->max_stream_receive_window = DEF_MAX_STREAM_RECEIVE_WINDOW_SIZE;
        }
        if (cfg->initial_connection_receive_window <= 0) {
            cfg->initial_connection_receive_window = DEF_CONNECTION_RECEIVE_WINDOW_SIZE;
        }
        if (cfg->max_connection_receive_window <= 0) {
            cfg->max_connection_receive_window = DEF_MAX_CONNECTION_RECEIVE_WINDOW_SIZE;
        }
        if (cfg->max_incoming_streams < 0) {
            cfg->max_incoming_streams = DEF_MAX_INCOMING_STREAM_COUNT;
        }
        if (cfg->max_incoming_uni_streams < 0) {
            cfg->max_incoming_uni_streams = DEF_MAX_INCOMING_NUI_STREAM_COUNT;
        }
    }

}
}
}