/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef upsi_PROTOCOL_CLIENT_H_
#define upsi_PROTOCOL_CLIENT_H_

#include "upsi/message_sink.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"

namespace upsi {

// Abstract class representing a server for a cryptographic protocol.
class ProtocolClient {
 public:
  virtual ~ProtocolClient() = default;

  /*
  // All subclasses should send the starting client message(s) to the message
  // sink.
  virtual Status StartProtocol(
      MessageSink<ClientMessage>* client_message_sink) = 0;
  */

  // All subclasses should check that the server response is the right type,
  // and, if so, execute the next round of the client, which may involve sending
  // one or more messages to the client message sink.
  virtual Status Handle(const ServerMessage& server_message,
                        MessageSink<ClientMessage>* client_message_sink) = 0;

  // All subclasses should return true if the protocol is complete, and
  // false otherwise.
  virtual bool protocol_finished() = 0;

 protected:
  ProtocolClient() = default;
};

}  // namespace upsi

#endif  // upsi_PROTOCOL_CLIENT_H_
